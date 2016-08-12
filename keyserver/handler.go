package keyserver

import (
	. "github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/utils"
)

func (server *ConiksServer) handleRegistrationMessage(reg *RegistrationRequest) (Response, error) {
	if len(reg.Username) == 0 || len(reg.Key) == 0 {
		return NewErrorResponse(ErrorMalformedClientMessage),
			ErrorMalformedClientMessage.Error()
	}

	server.Lock()

	ap, tb, errCode := server.directory.Register(reg.Username, []byte(reg.Key))
	if errCode != Success {
		server.Unlock()
		return NewErrorResponse(errCode),
			errCode.Error()
	}
	server.Unlock()

	// store the user policies into DB
	err := server.StoreUserPoliciesToKV(&ConiksUserPolicies{
		AllowUnsignedKeychange: reg.AllowUnsignedKeychange,
		AllowPublicLookup:      reg.AllowPublicLookup,
	})
	if err != nil {
		return NewErrorResponse(ErrorInternalServer),
			err
	}

	return &RegistrationResponse{
		Type: RegistrationType,
		STR:  server.directory.LatestSTR(),
		AP:   ap,
		TB:   tb,
	}, nil
}

func (server *ConiksServer) StoreUserPoliciesToKV(up *ConiksUserPolicies) error {
	buf := make([]byte, 0, 1)
	buf = append(util.ToBytes([]bool{up.AllowUnsignedKeychange, up.AllowPublicLookup}))
	if err := server.db.Put([]byte(up.Username), buf); err != nil {
		return err
	}
	return nil
}
