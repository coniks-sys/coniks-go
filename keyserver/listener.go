package keyserver

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"time"

	p "github.com/coniks-sys/coniks-go/protocol"
)

func (server *ConiksServer) listenForRequests(ln net.Listener) {
	defer server.waitStop.Done()
	defer ln.Close()
	go func() {
		<-server.stop
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-server.stop:
				return
			default:
				log.Printf("accept client: %s", err)
				continue
			}
		}
		server.waitStop.Add(1)
		go server.handleClient(conn)
	}
}

func (server *ConiksServer) handleClient(conn net.Conn) {
	defer conn.Close()
	defer server.waitStop.Done()
	closed := make(chan struct{})
	defer close(closed)
	go func() {
		select {
		case <-server.stop:
			conn.Close()
		case <-closed:
		}
	}()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// handle request
	buf := make([]byte, 4<<10)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			select {
			case <-server.stop:
				return
			default:
				if err != io.EOF {
					log.Printf("client read %v: %v", conn.RemoteAddr(), err)
				}
				return
			}
		}

		res, err := server.handleClientMessage(buf[:n])
		if err != nil {
			log.Printf("client handle %v: %v", conn.RemoteAddr(), err)
		}

		resBytes, err := json.Marshal(res)
		if err != nil {
			panic(p.Error(p.ErrorInternalServer))
		}
		n, err = conn.Write([]byte(resBytes))
		if err != nil {
			select {
			case <-server.stop:
				return
			default:
				log.Printf("client write %v: %v", conn.RemoteAddr(), err)
				return
			}
		}
	}
}

func (server *ConiksServer) handleClientMessage(msg []byte) (p.Response, error) {
	var content json.RawMessage
	req := p.Request{
		Request: &content,
	}
	if err := json.Unmarshal(msg, &req); err != nil {
		return p.NewErrorResponse(p.ErrorMalformedClientMessage),
			err
	}

	switch req.Type {
	case p.RegistrationType:
		var reg p.RegistrationRequest
		if err := json.Unmarshal(content, &reg); err != nil {
			return p.NewErrorResponse(p.ErrorMalformedClientMessage),
				err
		}
		return server.handleRegistrationMessage(&reg)

	default:
		log.Printf("unknown message type: %q", req.Type)
		return p.NewErrorResponse(p.ErrorMalformedClientMessage),
			p.Error(p.ErrorMalformedClientMessage)
	}
}
