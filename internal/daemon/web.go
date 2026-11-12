package daemon

// Встроенные ресурсы панели (go:embed, vanilla, без CDN — роутер
// офлайн-дружелюбен). {{RETURN_URL}} в panel.html подставляется при старте
// из cfg.Panel.ReturnURL (href кнопки «← Приложения»).

import _ "embed"

//go:embed web/panel.html
var panelHTML string

//go:embed web/icon.svg
var panelIcon string

//go:embed web/manifest.webmanifest
var panelManifest string
