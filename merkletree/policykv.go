package merkletree

import (
	"encoding/binary"

	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/storage/kv"
	"github.com/coniks-sys/coniks-go/utils"
)

func (p *DefaultPolicies) serializeKvKey(epoch uint64) []byte {
	buf := make([]byte, 0, 1+8)
	buf = append(buf, PoliciesIdentifier)
	buf = append(buf, util.ULongToBytes(epoch)...)
	return buf
}

// StoreToKV stores DefaultPolicies instance into an array with following scheme:
// [p.LibVersion+len, p.HashID+len, vrfPrivateKey]
func (p *DefaultPolicies) StoreToKV(epoch uint64, wb kv.Batch) {
	var buf []byte
	buf = append(buf, util.IntToBytes(len([]byte(p.LibVersion)))...)
	buf = append(buf, []byte(p.LibVersion)...)
	buf = append(buf, util.IntToBytes(len([]byte(p.HashID)))...)
	buf = append(buf, []byte(p.HashID)...)
	buf = append(buf, p.vrfPrivateKey[:]...)
	wb.Put(p.serializeKvKey(epoch), buf)
}

func (p *DefaultPolicies) LoadFromKV(db kv.DB, epoch uint64) error {
	buf, err := db.Get(p.serializeKvKey(epoch))
	if err != nil {
		return err
	}
	l := int(binary.LittleEndian.Uint32(buf[:4]))
	buf = buf[4:]
	p.LibVersion = string(buf[:l])
	buf = buf[l:]
	l = int(binary.LittleEndian.Uint32(buf[:4]))
	buf = buf[4:]
	p.HashID = string(buf[:l])
	buf = buf[l:]
	vrfKey := new([vrf.SecretKeySize]byte)
	copy(vrfKey[:], buf[:vrf.SecretKeySize])
	p.vrfPrivateKey = vrfKey
	buf = buf[vrf.SecretKeySize:]
	if len(buf) != 0 {
		panic(kv.ErrorBadBufferLength)
	}
	return nil
}
