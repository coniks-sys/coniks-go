package keyserver

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"time"

	. "github.com/coniks-sys/coniks-go/protocol"
)

func (server *ConiksServer) listenForRequests(ln net.Listener, handler func(msg []byte) ([]byte, error)) {
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
		go server.acceptClient(conn, handler)
	}
}

func (server *ConiksServer) acceptClient(conn net.Conn, handler func(msg []byte) ([]byte, error)) {
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
	buf := make([]byte, 4096)
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

		res, err := handler(buf[:n])
		if err != nil {
			log.Printf("client handle %v: %v", conn.RemoteAddr(), err)
		}

		n, err = conn.Write([]byte(res))
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

func malformedClientMsg() []byte {
	res, err := MarshalErrorResponse(ErrorMalformedClientMessage)
	if err != nil {
		panic(err)
	}
	return res
}

// handleClientMessage returns a byte slice of marshaled response
// and an error for server logging
func (server *ConiksServer) handleClientMessage(msg []byte) ([]byte, error) {
	// get request message
	req, _, err := UnmarshalRequest(msg)
	if err != nil {
		return malformedClientMsg(), err
	}

	// handle request
	switch req.Type {
	default:
		log.Printf("unknown message type: %q", req.Type)
		return malformedClientMsg(), ErrorMalformedClientMessage.Error()
	}
}

func (server *ConiksServer) handleBotMessage(msg []byte) ([]byte, error) {
	var response Response
	var err error

	// get request message
	req, content, err := UnmarshalRequest(msg)
	if err != nil {
		return malformedClientMsg(), err
	}

	// handle request
	switch req.Type {
	case RegistrationType:
		var reg RegistrationRequest
		if err = json.Unmarshal(content, &reg); err != nil {
			return malformedClientMsg(), err
		}
		response, err = server.handleRegistrationMessage(&reg)
		if err == nil {
			res, e := MarshalRegistrationResponse(response.(*RegistrationResponse))
			if e != nil {
				panic(e)
			}
			return res, nil
		}
		res, e := MarshalErrorResponse(response.(*ErrorResponse).Error)
		if e != nil {
			panic(e)
		}
		return res, nil

	default:
		log.Printf("unknown message type: %q", req.Type)
		return malformedClientMsg(), ErrorMalformedClientMessage.Error()
	}
}
