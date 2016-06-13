package merkletree

// SignedTreeRoot represents a signed tree root, which is generated
// at the beginning of every epoch.
// Signed tree roots contain the current root node,
// the current and previous epochs, the hash of the
// previous STR, and its signature.
// STR should be final
type SignedTreeRoot struct {
	treeRoot    *interiorNode
	epoch       int64
	prevEpoch   int64
	prevStrHash []byte
	sig         []byte
	policies    []byte
	prev        *SignedTreeRoot
}

func (m *MerkleTree) generateSTR(ep int64, prevEp int64, prevHash []byte) *SignedTreeRoot {
	bytesPreSig := getSTRBytesForSig(m, ep, prevEp, prevHash)
	sig := Sign(m.privKey, bytesPreSig)

	return &SignedTreeRoot{
		treeRoot:    m.root,
		epoch:       ep,
		prevEpoch:   prevEp,
		prevStrHash: prevHash,
		sig:         sig,
		policies:    m.policies.Serialize(),
		prev:        nil,
	}
}

func (m *MerkleTree) generateNextSTR(ep int64) *SignedTreeRoot {
	currentSTR := getCurrentSTR()
	prevEpoch := currentSTR.epoch
	prevStrHash := Digest(serializeSTR(*currentSTR))
	bytesPreSig := getSTRBytesForSig(m, ep, prevEpoch, prevStrHash)

	sig := Sign(m.privKey, bytesPreSig)
	return &SignedTreeRoot{
		treeRoot:    m.root,
		epoch:       ep,
		prevEpoch:   prevEpoch,
		prevStrHash: prevStrHash,
		sig:         sig,
		policies:    m.policies.Serialize(),
		prev:        currentSTR,
	}
}

func getSTRBytesForSig(m *MerkleTree, ep int64, prevEp int64, prevHash []byte) []byte {
	var strBytes []byte

	strBytes = append(strBytes, LongToBytes(ep)...)        // t - epoch number
	strBytes = append(strBytes, LongToBytes(prevEp)...)    // t_prev - previous epoch number
	strBytes = append(strBytes, m.root.serialize()...)     // root
	strBytes = append(strBytes, prevHash...)               // previous STR hash
	strBytes = append(strBytes, m.policies.Serialize()...) // P
	return strBytes
}

func serializeSTR(str SignedTreeRoot) []byte {
	var strBytes []byte

	strBytes = append(strBytes, str.treeRoot.serialize()...)   // root
	strBytes = append(strBytes, LongToBytes(str.epoch)...)     // epoch
	strBytes = append(strBytes, LongToBytes(str.prevEpoch)...) // previous epoch
	strBytes = append(strBytes, str.prevStrHash...)            // previous hash
	strBytes = append(strBytes, str.sig...)                    // signature

	return strBytes
}
