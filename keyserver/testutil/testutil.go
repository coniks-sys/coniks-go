/*
Package testutil provides utility functions for
writing server tests and generating a test server configuration.

testutil provides functions to create a self-signed TLS
certificate which can be used for a test server. It also provides
functions to create a basic test client which can send requests
to a test server via a TLS socket connection or a Unix socket connection.
*/
package testutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"net/url"
	"os"
	"path"
	"testing"
	"time"

	"github.com/coniks-sys/coniks-go/protocol"
)

const (
	// TestDir is the default directory for server tests
	TestDir          = "coniksServerTest"
	// PublicConnection is the default address for TCP connections
	PublicConnection = "tcp://127.0.0.1:3000"
	// LocalConnection is the default address for Unix socket connections
	LocalConnection  = "unix:///tmp/conikstest.sock"
)

type ExpectingDirProofResponse struct {
	Error             protocol.ErrorCode
	DirectoryResponse struct {
		AP  json.RawMessage
		STR json.RawMessage
		TB  json.RawMessage
	}
}

type ExpectingDirProofsResponse struct {
	Error             protocol.ErrorCode
	DirectoryResponse struct {
		AP  []json.RawMessage
		STR []json.RawMessage
	}
}

type ExpectingSTR struct {
	Epoch uint64
}

// CreateTLSCert generates a new self-signed TLS certificate
// and stores it in the path given by dir.
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

// CreateTLSCertForTest generates a temporary self-signed TLS certificate
// that only lasts for the duration of the test t.
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

// NewTCPClient creates a basic test client that sends a given
// request msg to the server listening at the given address
// via a TCP connection.
func NewTCPClient(msg []byte, address string) ([]byte, error) {
	conf := &tls.Config{InsecureSkipVerify: true}
	u, _ := url.Parse(address)
	conn, err := net.Dial(u.Scheme, u.Host)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, conf)

	_, err = tlsConn.Write([]byte(msg))
	if err != nil {
		return nil, err
	}

	if c, ok := conn.(interface {
		CloseWrite() error
	}); ok {
		c.CloseWrite()
	}

	var buf bytes.Buffer
	if _, err := io.CopyN(&buf, tlsConn, 8192); err != nil && err != io.EOF {
		return nil, err
	}

	return buf.Bytes(), nil
}

// NewTCPClientDefault creates a basic test client that sends a given
// request msg to a server listening at the default PublicConnection
// address.
func NewTCPClientDefault(msg []byte) ([]byte, error) {
	return NewTCPClient(msg, PublicConnection)
}

// NewUnixClient creates a basic test client that sends a given
// request msg to the server listening at the given address
// via a Unix socket connection.
func NewUnixClient(msg []byte, address string) ([]byte, error) {
	u, _ := url.Parse(address)
	unixaddr := &net.UnixAddr{Name: u.Path, Net: u.Scheme}
	conn, err := net.DialUnix(u.Scheme, nil, unixaddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_, err = conn.Write([]byte(msg))
	if err != nil {
		return nil, err
	}

	conn.CloseWrite()
	var buf bytes.Buffer
	if _, err := io.CopyN(&buf, conn, 8192); err != nil && err != io.EOF {
		return nil, err
	}

	return buf.Bytes(), nil
}

// NewUnixClientDefault creates a basic test client that sends a given
// request msg to a server listening at the default LocalConnection
// address.
func NewUnixClientDefault(msg []byte) ([]byte, error) {
	return NewUnixClient(msg, LocalConnection)
}
