package keyserver

import (
	"encoding/base64"

	p "github.com/coniks-sys/coniks-go/protocol"
)

func (server *ConiksServer) handleRegistrationMessage(reg *p.RegistrationRequest) (p.Response, error) {
	if len(reg.Username) == 0 || len(reg.Key) == 0 {
		return p.NewErrorResponse(p.ErrorMalformedClientMessage),
			p.Error(p.ErrorMalformedClientMessage)
	}

	// decode key string
	key, err := base64.StdEncoding.DecodeString(reg.Key)
	if err != nil {
		return p.NewErrorResponse(p.ErrorMalformedClientMessage),
			p.Error(p.ErrorMalformedClientMessage)
	}

	server.Lock()
	// check the temporary bindings array first
	// currently the server allows only one registration/key change per epoch
	if server.tbs[reg.Username] != nil {
		server.Unlock()
		return p.NewErrorResponse(p.ErrorNameExisted),
			p.Error(p.ErrorNameExisted)
	}

	ap, tb, errCode := server.directory.Register(reg.Username, key)
	if errCode != p.Success {
		server.Unlock()
		return p.NewErrorResponse(errCode), p.Error(errCode)
	}
	server.tbs[reg.Username] = tb
	server.Unlock()

	// TODO: do we want to store the user policies into DB?

	tbEncoded, err := p.MarshalTemporaryBinding(tb)
	if err != nil {
		return p.NewErrorResponse(p.ErrorInternalServer), err
	}
	apEncoded, err := p.MarshalAuthenticationPath(ap)
	if err != nil {
		return p.NewErrorResponse(p.ErrorInternalServer), err
	}
	strEncoded, err := p.MarshalSTR(server.directory.LatestSTR())
	if err != nil {
		return p.NewErrorResponse(p.ErrorInternalServer), err
	}

	return &p.RegistrationResponse{
		STR: string(strEncoded),
		AP:  string(apEncoded),
		TB:  string(tbEncoded),
	}, nil
}
