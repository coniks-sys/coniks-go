package keyserver

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"time"

	. "github.com/coniks-sys/coniks-go/protocol"
)

func (server *ConiksServer) listenForRequests(ln net.Listener, handler func(msg []byte) ([]byte, error)) {
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
			log.Printf("accept client: %s", err)
			continue
		}
		if _, ok := ln.(*net.TCPListener); ok {
			conn = tls.Server(conn, server.tlsConfig)
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
		log.Printf("client read %v: %v", conn.RemoteAddr(), err)
		return
	}

	res, err := handler(buf.Bytes())
	// TODO: The `err` returned here is purely for logging purposes.  It
	// would be better for `handler` not to return any error, and instead
	// log if the error code in the `res` is not `Success`.
	if err != nil {
		log.Printf("client handle %v: %v", conn.RemoteAddr(), err)
	}

	_, err = conn.Write([]byte(res))
	if err != nil {
		log.Printf("client write %v: %v", conn.RemoteAddr(), err)
		return
	}
}

func malformedClientMsg(err error) ([]byte, error) {
	// check if we're just propagating a message
	if err == nil {
		err = ErrorMalformedClientMessage
	}
	response := NewErrorResponse(ErrorMalformedClientMessage)
	res, e := MarshalResponse(response)
	if e != nil {
		panic(e)
	}
	return res, err
}

// andleOps validates the request message and then pass it to
// appropriate operation handler according to the request type.
func handleOps(d *ConiksDirectory, req *Request) (*Response, ErrorCode) {
	switch req.Type {
	case RegistrationType:
		if msg, ok := req.Request.(*RegistrationRequest); ok {
			return d.Register(msg)
		}
	case KeyLookupType:
		if msg, ok := req.Request.(*KeyLookupRequest); ok {
			return d.KeyLookup(msg)
		}
	case KeyLookupInEpochType:
		if msg, ok := req.Request.(*KeyLookupInEpochRequest); ok {
			return d.KeyLookupInEpoch(msg)
		}
	case MonitoringType:
		if msg, ok := req.Request.(*MonitoringRequest); ok {
			return d.Monitor(msg)
		}
	}
	return NewErrorResponse(ErrorMalformedClientMessage),
		ErrorMalformedClientMessage
}

func (server *ConiksServer) makeHandler(acceptableTypes map[int]bool) func(msg []byte) ([]byte, error) {
	return func(msg []byte) ([]byte, error) {
		// get request message
		req, err := UnmarshalRequest(msg)
		if err != nil {
			return malformedClientMsg(err)
		}
		if !acceptableTypes[req.Type] {
			log.Printf("unacceptable message type: %q", req.Type)
			return malformedClientMsg(ErrorMalformedClientMessage)
		}

		switch req.Type {
		case KeyLookupType, KeyLookupInEpochType, MonitoringType:
			server.RLock()
		default:
			server.Lock()
		}
		response, e := handleOps(server.dir, req)
		switch req.Type {
		case KeyLookupType, KeyLookupInEpochType, MonitoringType:
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
