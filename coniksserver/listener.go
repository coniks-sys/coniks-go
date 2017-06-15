package coniksserver

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"time"

	"github.com/coniks-sys/coniks-go/protocol"
)

func (server *ConiksServer) handleRequests(ln net.Listener, tlsConfig *tls.Config,
	handler func(msg []byte) ([]byte, error)) {
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

func (server *ConiksServer) acceptClient(conn net.Conn, handler func(msg []byte) ([]byte, error)) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	var buf bytes.Buffer
	if _, err := io.CopyN(&buf, conn, 8192); err != nil && err != io.EOF {
		server.logger.Error(err.Error(),
			"address", conn.RemoteAddr().String())
		return
	}

	res, err := handler(buf.Bytes())
	// TODO: The `err` returned here is purely for logging purposes.  It
	// would be better for `handler` not to return any error, and instead
	// log if the error code in the `res` is not `ReqSuccess`.
	if err != protocol.ReqSuccess {
		server.logger.Warn(err.Error(),
			"address", conn.RemoteAddr().String())
	}

	_, err = conn.Write([]byte(res))
	if err != nil {
		server.logger.Error(err.Error(),
			"address", conn.RemoteAddr().String())
		return
	}
}

func malformedClientMsg(err error) ([]byte, error) {
	// check if we're just propagating a message
	if err == nil {
		err = protocol.ErrMalformedClientMessage
	}
	response := protocol.NewErrorResponse(protocol.ErrMalformedClientMessage)
	res, e := MarshalResponse(response)
	if e != nil {
		panic(e)
	}
	return res, err
}

// handleOps validates the request message and then pass it to
// appropriate operation handler according to the request type.
func (server *ConiksServer) handleOps(req *protocol.Request) (*protocol.Response, protocol.ErrorCode) {
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
	return protocol.NewErrorResponse(protocol.ErrMalformedClientMessage),
		protocol.ErrMalformedClientMessage
}

func (server *ConiksServer) makeHandler(acceptableTypes map[int]bool) func(msg []byte) ([]byte, error) {
	return func(msg []byte) ([]byte, error) {
		// get request message
		req, err := UnmarshalRequest(msg)
		if err != nil {
			return malformedClientMsg(err)
		}
		if !acceptableTypes[req.Type] {
			server.logger.Error("Unacceptable message type",
				"request type", req.Type)
			return malformedClientMsg(protocol.ErrMalformedClientMessage)
		}

		switch req.Type {
		case protocol.KeyLookupType, protocol.KeyLookupInEpochType, protocol.MonitoringType:
			server.RLock()
		default:
			server.Lock()
		}
		response, e := server.handleOps(req)
		switch req.Type {
		case protocol.KeyLookupType, protocol.KeyLookupInEpochType, protocol.MonitoringType:
			server.RUnlock()
		default:
			server.Unlock()
		}

		res, err := MarshalResponse(response)
		if err != nil {
			panic(err)
		}
		return res, e
	}
}
