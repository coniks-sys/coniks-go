package coniksserver

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"time"

	"github.com/coniks-sys/coniks-go/application"
	"github.com/coniks-sys/coniks-go/protocol"
)

func (server *ConiksServer) handleRequests(ln net.Listener, tlsConfig *tls.Config,
	handler func(req *protocol.Request) *protocol.Response) {
	defer ln.Close()
	go func() {
		<-server.stop
		if l, ok := ln.(interface {
			SetDeadline(time.Time) error
		}); ok {
			l.SetDeadline(time.Now())
		}
	}()

	for {
		select {
		case <-server.stop:
			server.waitCloseConn.Wait()
			return
		default:
		}
		conn, err := ln.Accept()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				continue
			}
			server.logger.Error(err.Error())
			continue
		}
		if _, ok := ln.(*net.TCPListener); ok {
			conn = tls.Server(conn, tlsConfig)
		}
		server.waitCloseConn.Add(1)
		go func() {
			server.acceptClient(conn, handler)
			server.waitCloseConn.Done()
		}()
	}
}

func (server *ConiksServer) acceptClient(conn net.Conn, handler func(req *protocol.Request) *protocol.Response) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	var buf bytes.Buffer
	var response *protocol.Response
	if _, err := io.CopyN(&buf, conn, 8192); err != nil && err != io.EOF {
		server.logger.Error(err.Error(),
			"address", conn.RemoteAddr().String())
		return
	}

	// unmarshalling
	req, err := application.UnmarshalRequest(buf.Bytes())
	if err != nil {
		response = malformedClientMsg(err)
	} else {
		response = handler(req)
		if response.Error != protocol.ReqSuccess {
			server.logger.Warn(response.Error.Error(),
				"address", conn.RemoteAddr().String())
		}
	}

	// marshalling
	res, e := application.MarshalResponse(response)
	if e != nil {
		panic(e)
	}
	_, err = conn.Write([]byte(res))
	if err != nil {
		server.logger.Error(err.Error(),
			"address", conn.RemoteAddr().String())
		return
	}
}

func malformedClientMsg(err error) *protocol.Response {
	// check if we're just propagating a message
	if err == nil {
		err = protocol.ErrMalformedMessage
	}
	return protocol.NewErrorResponse(protocol.ErrMalformedMessage)
}

// handleOps validates the request message and then pass it to
// appropriate operation handler according to the request type.
func (server *ConiksServer) handleOps(req *protocol.Request) *protocol.Response {
	switch req.Type {
	case protocol.RegistrationType:
		if msg, ok := req.Request.(*protocol.RegistrationRequest); ok {
			return server.dir.Register(msg)
		}
	case protocol.KeyLookupType:
		if msg, ok := req.Request.(*protocol.KeyLookupRequest); ok {
			return server.dir.KeyLookup(msg)
		}
	case protocol.KeyLookupInEpochType:
		if msg, ok := req.Request.(*protocol.KeyLookupInEpochRequest); ok {
			return server.dir.KeyLookupInEpoch(msg)
		}
	case protocol.MonitoringType:
		if msg, ok := req.Request.(*protocol.MonitoringRequest); ok {
			return server.dir.Monitor(msg)
		}
	}
	return protocol.NewErrorResponse(protocol.ErrMalformedMessage)
}

func (server *ConiksServer) makeHandler(acceptableTypes map[int]bool) func(req *protocol.Request) *protocol.Response {
	return func(req *protocol.Request) *protocol.Response {
		if !acceptableTypes[req.Type] {
			server.logger.Error("Unacceptable message type",
				"request type", req.Type)
			return malformedClientMsg(protocol.ErrMalformedMessage)
		}

		switch req.Type {
		case protocol.KeyLookupType, protocol.KeyLookupInEpochType, protocol.MonitoringType:
			server.RLock()
		default:
			server.Lock()
		}
		response := server.handleOps(req)
		switch req.Type {
		case protocol.KeyLookupType, protocol.KeyLookupInEpochType, protocol.MonitoringType:
			server.RUnlock()
		default:
			server.Unlock()
		}

		return response
	}
}
