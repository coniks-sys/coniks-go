package merkletree

type Policies interface {
	Serialize() []byte
}

type DefaultPolicies struct {
}

var _ Policies = (*DefaultPolicies)(nil)

func (p *DefaultPolicies) Serialize() []byte {
	var bs []byte
	bs = append(bs, []byte(Version)...)          // lib Version
	bs = append(bs, []byte(HashID)...)           // cryptographic algorithms in use
	bs = append(bs, LongToBytes(NextEpoch())...) // expected time of next epoch
	return bs
}
