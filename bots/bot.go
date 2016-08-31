package bots

import (
	"bytes"
	"io"
	"net"
)

const (
	messagePrefix = "?CONIKS?"
)

type BotHandleFunc func(string, []byte)

type Bot interface {
	HandleRegistration(string, []byte) string
	Run()
	Stop()
}

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
