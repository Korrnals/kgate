package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Ensure generates the CA + server + client certificates unless they
// already exist. The server certificate is issued for the router IP
// and the "kgate" DNS name.
func Ensure(dir, routerIP string) (created bool, err error) {
	need := []string{"ca.crt", "ca.key", "server.crt", "server.key", "client.crt", "client.key"}
	missing := false
	for _, f := range need {
		if _, err := os.Stat(filepath.Join(dir, f)); os.IsNotExist(err) {
			missing = true
			break
		}
	}
	if !missing {
		return false, nil
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return false, err
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return false, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "kgate-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return false, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return false, err
	}
	if err := writePEM(filepath.Join(dir, "ca.crt"), "CERTIFICATE", caDER, 0644); err != nil {
		return false, err
	}
	if err := writeKey(filepath.Join(dir, "ca.key"), caKey); err != nil {
		return false, err
	}

	ip := net.ParseIP(routerIP)
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "kgate-server"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IPAddresses:  []net.IP{ip, net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"kgate", "localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return false, err
	}
	if err := writePEM(filepath.Join(dir, "server.crt"), "CERTIFICATE", serverDER, 0644); err != nil {
		return false, err
	}
	if err := writeKey(filepath.Join(dir, "server.key"), serverKey); err != nil {
		return false, err
	}

	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "kgate-client"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return false, err
	}
	if err := writePEM(filepath.Join(dir, "client.crt"), "CERTIFICATE", clientDER, 0644); err != nil {
		return false, err
	}
	if err := writeKey(filepath.Join(dir, "client.key"), clientKey); err != nil {
		return false, err
	}
	return true, nil
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
}

func writeKey(path string, k *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600)
}
