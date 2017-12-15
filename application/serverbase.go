package application

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/coniks-sys/coniks-go/protocol"
)

// A Server is a generic interface used to implement CONIKS key servers
// and auditors.
// CONIKS server's must implement a request handler, an epoch update
// procedure, and hot-reloading the configuration.
type Server interface {
	EpochUpdate()
	ConfigHotReload()
	HandleRequests(*protocol.Request) *protocol.Response
}

// A ServerBaseConfig contains configuration values
// which are read at initialization time from
// a TOML format configuration file.
type ServerBaseConfig struct {
	Logger         *LoggerConfig `toml:"logger"`
	ConfigFilePath string
}

// A ServerBase represents the base features needed to implement
// a CONIKS key server or auditor.
// It wraps a ConiksDirectory or AuditLog with a network layer which
// handles requests/responses and their encoding/decoding.
// A ServerBase also supports concurrent handling of requests.
type ServerBase struct {
	Verb           string
	acceptableReqs map[*ServerAddress]map[int]bool

	logger *Logger
	sync.RWMutex

	stop          chan struct{}
	waitStop      sync.WaitGroup
	waitCloseConn sync.WaitGroup

	configFilePath string
	reloadChan     chan os.Signal
}

// A ServerAddress describes a server's connection.
// It supports two types of connections: a TCP connection ("tcp")
// and a Unix socket connection ("unix").
//
// Additionally, TCP connections must use TLS for added security,
// and each is required to specify a TLS certificate and corresponding
// private key.
type ServerAddress struct {
	// Address is formatted as a url: scheme://address.
	Address string `toml:"address"`
	// TLSCertPath is a path to the server's TLS Certificate,
	// which has to be set if the connection is TCP.
	TLSCertPath string `toml:"cert,omitempty"`
	// TLSKeyPath is a path to the server's TLS private key,
	// which has to be set if the connection is TCP.
	TLSKeyPath string `toml:"key,omitempty"`
}

// NewServerBase creates a new generic CONIKS-ready server base.
func NewServerBase(conf *ServerBaseConfig, listenVerb string,
	perms map[*ServerAddress]map[int]bool) *ServerBase {
	// create server instance
	sb := new(ServerBase)
	sb.Verb = listenVerb
	sb.acceptableReqs = perms
	sb.logger = NewLogger(conf.Logger)
	sb.stop = make(chan struct{})
	sb.configFilePath = conf.ConfigFilePath
	sb.reloadChan = make(chan os.Signal, 1)
	signal.Notify(sb.reloadChan, syscall.SIGUSR2)
	return sb
}

// ListenAndHandle implements the main functionality of a CONIKS-ready
// server. It listens athe the given server address with corresponding
// permissions, and takes the specified pre- and post-Listening actions.
// It also supports hot-reloading the configuration by listening for
// SIGUSR2 signal.
func (sb *ServerBase) ListenAndHandle(addr *ServerAddress,
	reqHandler func(req *protocol.Request) *protocol.Response) {
	ln, tlsConfig := addr.resolveAndListen()
	sb.waitStop.Add(1)
	go func() {
		sb.logger.Info(sb.Verb, "address", addr.Address)
		sb.acceptRequests(addr, ln, tlsConfig, reqHandler)
		sb.waitStop.Done()
	}()
}

func (addr *ServerAddress) resolveAndListen() (ln net.Listener,
	tlsConfig *tls.Config) {
	u, err := url.Parse(addr.Address)
	if err != nil {
		panic(err)
	}
	switch u.Scheme {
	case "tcp":
		// force to use TLS
		cer, err := tls.LoadX509KeyPair(addr.TLSCertPath, addr.TLSKeyPath)
		if err != nil {
			panic(err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cer}}
		tcpaddr, err := net.ResolveTCPAddr(u.Scheme, u.Host)
		if err != nil {
			panic(err)
		}
		ln, err = net.ListenTCP(u.Scheme, tcpaddr)
		if err != nil {
			panic(err)
		}
		return
	case "unix":
		unixaddr, err := net.ResolveUnixAddr(u.Scheme, u.Path)
		if err != nil {
			panic(err)
		}
		ln, err = net.ListenUnix(u.Scheme, unixaddr)
		if err != nil {
			panic(err)
		}
		return
	default:
		panic("Unknown network type")
	}
}

func (sb *ServerBase) acceptRequests(addr *ServerAddress, ln net.Listener,
	tlsConfig *tls.Config,
	handler func(req *protocol.Request) *protocol.Response) {
	defer ln.Close()
	go func() {
		<-sb.stop
		if l, ok := ln.(interface {
			SetDeadline(time.Time) error
		}); ok {
			l.SetDeadline(time.Now())
		}
	}()

	for {
		select {
		case <-sb.stop:
			sb.waitCloseConn.Wait()
			return
		default:
		}
		conn, err := ln.Accept()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				continue
			}
			sb.logger.Error(err.Error())
			continue
		}
		if _, ok := ln.(*net.TCPListener); ok {
			conn = tls.Server(conn, tlsConfig)
		}
		sb.waitCloseConn.Add(1)
		go func() {
			sb.acceptClient(addr, conn, handler)
			sb.waitCloseConn.Done()
		}()
	}
}

// checkRequestType verifies that the server is allowed to handle
// the given Request message type at the given address.
// If reqType is not acceptable, checkRequestType() returns a
// protocol.ErrMalformedMessage, otherwise it returns.
func (sb *ServerBase) checkRequestType(addr *ServerAddress,
	reqType int) error {
	if !sb.acceptableReqs[addr][reqType] {
		sb.logger.Error("Unacceptable message type",
			"request type", reqType)
		return protocol.ErrMalformedMessage
	}
	return nil
}

func (sb *ServerBase) acceptClient(addr *ServerAddress, conn net.Conn,
	handler func(req *protocol.Request) *protocol.Response) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	var buf bytes.Buffer
	var response *protocol.Response
	if _, err := io.CopyN(&buf, conn, 8192); err != nil && err != io.EOF {
		sb.logger.Error(err.Error(),
			"address", conn.RemoteAddr().String())
		return
	}

	// unmarshalling
	req, err := UnmarshalRequest(buf.Bytes())
	if err != nil {
		response = malformedClientMsg(err)
	} else {
		if err := sb.checkRequestType(addr, req.Type); err != nil {
			response = malformedClientMsg(err)
		} else {
			switch req.Type {
			case protocol.KeyLookupType, protocol.KeyLookupInEpochType, protocol.MonitoringType:
				sb.RLock()
			default:
				sb.Lock()
			}

			response = handler(req)

			switch req.Type {
			case protocol.KeyLookupType, protocol.KeyLookupInEpochType, protocol.MonitoringType:
				sb.RUnlock()
			default:
				sb.Unlock()
			}

			if response.Error != protocol.ReqSuccess {
				sb.logger.Warn(response.Error.Error(),
					"address", conn.RemoteAddr().String())
			}
		}
	}

	// marshalling
	res, e := MarshalResponse(response)
	if e != nil {
		panic(e)
	}
	_, err = conn.Write([]byte(res))
	if err != nil {
		sb.logger.Error(err.Error(),
			"address", conn.RemoteAddr().String())
		return
	}
}

// TODO: Remove/refactor these getters. We would be happier if we didn't
// have to expose the WaitGroup to the server/auditor at all, and maybe
// we can export some of these other fields.

// WaitStopAdd increments the server base's waitgroup counter.
func (sb *ServerBase) WaitStopAdd() {
	sb.waitStop.Add(1)
}

// WaitStopDone is a wrapper around waitgroup's Done(), which
// decrements the WaitGroup counter by one.
func (sb *ServerBase) WaitStopDone() {
	sb.waitStop.Done()
}

// Stop returns the server base's stop channel.
func (sb *ServerBase) Stop() chan struct{} {
	return sb.stop
}

// ReloadChan returns the server base's configuration reload channel.
func (sb *ServerBase) ReloadChan() chan os.Signal {
	return sb.reloadChan
}

// Logger returns the server base's logger instance.
func (sb *ServerBase) Logger() *Logger {
	return sb.logger
}

// ConfigFilePath returns the server base's config file path.
func (sb *ServerBase) ConfigFilePath() string {
	return sb.configFilePath
}

// Shutdown closes all of the server's connections and shuts down the server.
func (sb *ServerBase) Shutdown() error {
	close(sb.stop)
	sb.waitStop.Wait()
	return nil
}
