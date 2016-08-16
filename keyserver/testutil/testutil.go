package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path"
	"testing"
	"time"
)

const (
	TestDir          = "coniksServerTest"
	PublicConnection = "127.0.0.1:3000"
	LocalConnection  = "127.0.0.1:3001"
)

func CreateTLSCert(dir string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(1 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Coniks.org"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: true,
	}
	template.Subject.CommonName = "localhost"
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(path.Join(dir, "server.pem"))
	if err != nil {
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, err := os.OpenFile(path.Join(dir, "server.key"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	pemBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	pem.Encode(keyOut, pemBlock)
	keyOut.Close()
	return nil
}

func CreateTLSCertForTest(t *testing.T) (string, func()) {
	dir, err := ioutil.TempDir("", TestDir)
	if err != nil {
		t.Fatal(err)
	}
	err = CreateTLSCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, func() {
		os.RemoveAll(dir)
	}
}

func NewClient(t *testing.T, address string, msg []byte) ([]byte, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", address, conf)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(msg))
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}
