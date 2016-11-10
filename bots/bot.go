// A CONIKS registration bot interface that can be used to implement
// an account verification proxy for any first-party identity provider.
// Currently, this interface is used to implement a Twitter account
// verification proxy.

package bots

import (
	"bytes"
	"io"
	"net"
)

const (
	messagePrefix = "?CONIKS?"
)

// A Bot is a CONIKS registration proxy that verifies
// the authenticity of a user account with an
// identity provider (i.e. communication service
// that hands out service-specific user identifiers).
type Bot interface {
	HandleRegistration(string, []byte) string
	Run()
	Stop()
}

// SendRequestToCONIKS forwards a given msg to the CONIKS
// server listening at the named Unix socket addr.
// SendRequestToCONIKS, therefore, assumes that the registration
// bot runs on the same host OS as the CONIKS server.
func SendRequestToCONIKS(addr string, msg []byte) ([]byte, error) {
	scheme := "unix"
	unixaddr := &net.UnixAddr{Name: addr, Net: scheme}

	conn, err := net.DialUnix(scheme, nil, unixaddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_, err = conn.Write(msg)
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
