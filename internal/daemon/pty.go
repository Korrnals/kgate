// pty.go — PTY-читалка для локальных ndmc-вызовов демона.
//
// Зачем: ndmc (KeeneticOS CLI) рендерит для терминала — БЕЗ tty он клипует
// вывод (полевой факт 2026-11-12, CHANGELOG 1.8.2: хвост `show running-config`
// терялся при росте конфига, парсеры слепли). deploy ходит по ssh с
// RequestPty (internal/deploy/ssh.go ptyRun); демон вызывает /bin/ndmc
// ЛОКАЛЬНО через sh+CombinedOutput — пайпы, тот же клип. kgate-002 закрывает
// демона: каждый ndmc-вызов идёт под локальной PTY-сессией.
package daemon

import (
	"bytes"
	"fmt"
	"os/exec"
	"syscall"
	"time"

	"github.com/creack/pty"

	"kgate/internal/policy"
)

const (
	// ndmcPtyRows/ndmcPtyCols — профиль PTY-окна: тот же, что в deploy
	// (RequestPty "dumb" 200x500). Широкая колонка держит исходные длины
	// строк ndm-рендера (без заворачивания на 80 колонок).
	ndmcPtyRows = 200
	ndmcPtyCols = 500

	// ndmcTimeout — потолок одного ndmc-вызова. Прежний путь
	// (sh + CombinedOutput) зависал навсегда на зависшем ndmc; потолок честно
	// роняет вызов в ERR-поверхность (панель/CLI получают 500, супервизор
	// продолжает тикать).
	ndmcTimeout = 30 * time.Second

	// ndmcReapGrace — страховка после PTY-hangup: SIGHUP обычно добивает
	// зависшего ndmc мгновенно; если процесс игнорирует hangup, по грейсу —
	// SIGKILL (реквизиция обязательна: зомби копится в pid-таблице роутера).
	ndmcReapGrace = 3 * time.Second

	// ptyDrainGrace — окно дочитывания мастера после выхода ndmc: хвост рендера
	// может прибыть после exit. Ограничено на случай, если что-то стороннее
	// держит slave открытым (master тогда не даёт EIO никогда).
	ptyDrainGrace = 2 * time.Second

	// ndmcPtyPoll — пауза между EAGAIN-порожними чтениями мастера (мастер в
	// O_NONBLOCK; спим вместо блокировки — детерминированный выход по Close).
	ndmcPtyPoll = 5 * time.Millisecond
)

// ndmCmd строит команду ndmc так, как её строит демон (та же env) — общий
// корень для ndmc() и NdmRun.
func ndmCmd(verb string) *exec.Cmd {
	cmd := exec.Command("/bin/ndmc", "-c", verb)
	cmd.Env = daemonEnv()
	return cmd
}

// NdmRun — экспортированный passthrough для диагностики (`kgate ndm "<verb>"`):
// тот же путь, которым демон читает ndm, с той же PTY-читалкой. Read-only
// по соглашению вызова — верба входит как есть (фильтр $/backtick в ndmc).
func NdmRun(verb string) (string, error) {
	return ptyRun(ndmCmd(verb), ndmcTimeout)
}

// ptyRun запускает готовую команду под свежей PTY-сессией и возвращает
// ПОЛНЫЙ, вычищенный от ANSI/CR вывод (PTY-рендер ndmc несёт \x1b[K и \r —
// policy.StripANSI снимает их до возврата, парсеры не слепнут). Вызывающий
// отвечает за конструирование *exec.Cmd (env, argv) — ptyRun владеет PTY,
// дренированием и ожиданием.
//
// Ошибка (не стартовал / не нулевой exit / таймаут) возвращается парой
// (вывод-как-есть, err) — вызывающий формирует sh()-совместимую поверхность
// "ERR(<err>): <out>", на которой работают ndmExecFailed (префикс "ERR(") и
// ndmcFailed ("err(" в lower).
//
// SIGHUP-контейнмент (полевой инцидент 2026-11-12, deploy): PTY опасен, когда
// под ним стартует ДОЛГОЖИВУЩИЙ процесс, а сессия закрывается — controlling
// terminal hangup посылает SIGHUP процессной группе. Здесь ребёнок —
// короткоживущий ndmc (show/конфиг-верб), ptyRun ждёт его выхода ДО закрытия
// мастера; ни один вызов ndm() не стартует процессов (аудит call-site'ов:
// show*, ip route, interface Proxy0 up|down, system configuration save).
// sing-box поднимает procManager обычными пайпами — PTY его не касается.
// Ветка таймаута закрывает мастера первой — ядро шлёт SIGHUP зависшему ndmc:
// для короткоживущего зависшего ребёнка это желаемая реквизиция.
func ptyRun(cmd *exec.Cmd, timeout time.Duration) (string, error) {
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: ndmcPtyRows, Cols: ndmcPtyCols})
	if err != nil {
		return "", err
	}

	// Мастер — в O_NONBLOCK и читаем сырым syscall.Read. Причина: /dev/ptmx
	// не попадает в runtime-poller (зонд 2026-11-14: SetReadDeadline
	// принимается молча и НЕ исполняется; os.File.Close не прерывает
	// параллельный блокирующий Read) — блокирующее чтение навсегда держало
	// бы горутину на зависшем ndmc. Неблокирующий fd читается мгновенно:
	// EAGAIN (данных нет) → пауза-ретрай; EIO (slave закрыт, ребёнок вышел),
	// EOF, EBADF (наш Close) → конец потока. Выход детерминирован.
	fd := int(ptmx.Fd())
	if ferr := syscall.SetNonblock(fd, true); ferr != nil {
		_ = ptmx.Close()
		return "", fmt.Errorf("pty nonblock: %w", ferr)
	}

	// читатель: buf пишется только здесь; основной поток читает его после
	// <-drained (happens-before по close канала).
	var buf bytes.Buffer
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		chunk := make([]byte, 32*1024)
		for {
			n, rerr := syscall.Read(fd, chunk)
			if n > 0 {
				buf.Write(chunk[:n])
			}
			if rerr == syscall.EAGAIN || rerr == syscall.EINTR {
				time.Sleep(ndmcPtyPoll)
				continue
			}
			if rerr != nil || n == 0 {
				return
			}
		}
	}()

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	var waitErr error
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case waitErr = <-exited:
		// ребёнок вышел — дочитываем хвост мастера; если EIO не пришёл
		// (сторонний держатель slave) — грейс, затем Close мастеру (читатель
		// увидит EBADF и закончит).
		select {
		case <-drained:
		case <-time.After(ptyDrainGrace):
			_ = ptmx.Close()
			<-drained
		}
	case <-timer.C:
		// завис: Close мастера первым (ядро шлёт SIGHUP процессной группе
		// controlling terminal'а; читатель увидит EBADF), затем реквизиция
		// процесса.
		_ = ptmx.Close()
		<-drained
		select {
		case werr := <-exited:
			waitErr = fmt.Errorf("ndmc не завершился за %v (реквизирован по PTY hangup: %v)", timeout, werr)
		case <-time.After(ndmcReapGrace):
			_ = cmd.Process.Kill()
			<-exited
			waitErr = fmt.Errorf("ndmc не завершился за %v (убит SIGKILL после грейса)", timeout)
		}
	}
	_ = ptmx.Close()

	out := policy.StripANSI(buf.String())
	if waitErr != nil {
		return out, waitErr
	}
	return out, nil
}
