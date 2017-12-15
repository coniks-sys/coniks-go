package application

import (
	"path"
	"testing"

	"github.com/coniks-sys/coniks-go/application/testutil"
)

func TestResolveAndListen(t *testing.T) {
	dir, teardown := testutil.CreateTLSCertForTest(t)
	defer teardown()

	// test TCP network
	addr := &ServerAddress{
		Address:     testutil.PublicConnection,
		TLSCertPath: path.Join(dir, "server.pem"),
		TLSKeyPath:  path.Join(dir, "server.key"),
	}
	ln, _ := addr.resolveAndListen()
	defer ln.Close()

	// test Unix network
	addr = &ServerAddress{
		Address: testutil.LocalConnection,
	}
	ln, _ = addr.resolveAndListen()
	defer ln.Close()

	// test unknown network scheme
	addr = &ServerAddress{
		Address: testutil.PublicConnection,
	}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Expected resolveAndListen to panic.")
		}
	}()
	addr.resolveAndListen()
}
