package keyserver

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"time"

	p "github.com/coniks-sys/coniks-go/protocol"
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

func (server *ConiksServer) handleClientMessage(msg []byte) ([]byte, error) {
	var response p.Response
	var err error

	// get request message
	var content json.RawMessage
	req := p.Request{
		Request: &content,
	}
	if e := json.Unmarshal(msg, &req); e != nil {
		response = p.NewErrorResponse(p.ErrorMalformedClientMessage)
		err = e
		goto marshalling
	}

	// handle request
	switch req.Type {
	default:
		log.Printf("unknown message type: %q", req.Type)
		response = p.NewErrorResponse(p.ErrorMalformedClientMessage)
		err = p.Error(p.ErrorMalformedClientMessage)
	}

marshalling:
	res, e := json.Marshal(response)
	if e != nil {
		panic(p.Error(p.ErrorInternalServer))
	}
	return res, err
}

func (server *ConiksServer) handleBotMessage(msg []byte) ([]byte, error) {
	var response p.Response
	var err error

	// get request message
	var content json.RawMessage
	req := p.Request{
		Request: &content,
	}
	if e := json.Unmarshal(msg, &req); e != nil {
		response = p.NewErrorResponse(p.ErrorMalformedClientMessage)
		err = e
		goto marshalling
	}

	// handle request
	switch req.Type {
	case p.RegistrationType:
		var reg p.RegistrationRequest
		if e := json.Unmarshal(content, &reg); e != nil {
			response = p.NewErrorResponse(p.ErrorMalformedClientMessage)
			err = e
		} else {
			response, err = server.handleRegistrationMessage(&reg)
			if err == nil {
				tbEncoded, err := p.MarshalTemporaryBinding(response.(*RegistrationResponse).TB)
				if err != nil {
					panic(err)
				}
				apEncoded, err := p.MarshalAuthenticationPath(response.(*RegistrationResponse).AP)
				if err != nil {
					panic(err)
				}
				strEncoded, err := p.MarshalSTR(response.(*RegistrationResponse).STR)
				if err != nil {
					panic(err)
				}
				res, e := json.Marshal(&struct {
					Type int
					STR  json.RawMessage `json:"str"`
					AP   json.RawMessage `json:"ap"`
					TB   json.RawMessage `json:"tb"`
				}{
					Type: response.(*RegistrationResponse).Type,
					STR:  strEncoded,
					AP:   apEncoded,
					TB:   tbEncoded,
				})
				if e != nil {
					panic(e)
				}
				return res, nil
			}
		}

	default:
		log.Printf("unknown message type: %q", req.Type)
		response = p.NewErrorResponse(p.ErrorMalformedClientMessage)
		err = p.Error(p.ErrorMalformedClientMessage)
	}

marshalling:
	res, e := json.Marshal(response)
	if e != nil {
		panic(p.Error(p.ErrorInternalServer))
	}
	return res, err
}
