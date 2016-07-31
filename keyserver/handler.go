package keyserver

import (
	"encoding/base64"

	"github.com/coniks-sys/coniks-go/merkletree"
	p "github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/utils"
)

// RegistrationResponse is used to replace the protocol RegistrationResponse
// with addition TB field
type RegistrationResponse struct {
	Type int
	STR  *merkletree.SignedTreeRoot
	AP   *merkletree.AuthenticationPath
	TB   *merkletree.TemporaryBinding
}

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
		return p.NewErrorResponse(errCode),
			p.Error(errCode)
	}
	server.tbs[reg.Username] = tb
	server.Unlock()

	// store the user policies into DB
	err = server.StoreUserPoliciesToKV(&p.ConiksUserPolicies{
		AllowUnsignedKeychange: reg.AllowUnsignedKeychange,
		AllowPublicLookup:      reg.AllowPublicLookup,
	})
	if err != nil {
		return p.NewErrorResponse(p.ErrorInternalServer),
			err
	}

	return &RegistrationResponse{
		Type: p.RegistrationType,
		STR:  server.directory.LatestSTR(),
		AP:   ap,
		TB:   tb,
	}, nil
}

func (server *ConiksServer) StoreUserPoliciesToKV(up *p.ConiksUserPolicies) error {
	buf := make([]byte, 0, 1)
	buf = append(util.ToBytes([]bool{up.AllowUnsignedKeychange, up.AllowPublicLookup}))
	if err := server.db.Put([]byte(up.Username), buf); err != nil {
		return err
	}
	return nil
}
