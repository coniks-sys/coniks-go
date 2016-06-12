[![Build Status](https://travis-ci.org/coniks-sys/libmerkleprefixtree-go.svg?branch=merkle-tree)](https://travis-ci.org/coniks-sys/libmerkleprefixtree-go)

# libmerkleprefixtree-go
A Merkle prefix tree implementation in Golang

This library currently uses the `SHAKE128` ShakeHash with output size of 32 bytes. 

The signature scheme is `Ed25519` signature algorithm.

### Usage
Initiate the tree & history
```
m := merkletree.InitMerkleTree(nonce, salt, publicKey, privateKey)
// insert existing data (e.g., from db)
m.Set(key, value)
...
// recompute tree hash
m.RecomputeHash()
// init STR history chain
m.InitHistory(startupEpoch, epochInterval)
```

Update tree in each epoch
```
// clone the tree
m = m.Clone()
// insert new data
m.Set(key, value)
...
// recompute tree hash
m.RecomputeHash()
// update STR history chain
m.UpdateHistory(nextEpoch)
```

Look-up

`LookUp(key)` and `LookUpInEpoch(key, epoch)` return a `MerkleNode` instance and an _authenticate path_ for proofs of inclusion/absence.
`MerkleNode.IsEmpty()` is used to check whether the returned value is an empty leaf node or an user leaf node.
A proof of absence also includes an empty leaf node in the returned auth path.

### TODO
Some methods/functions should be exported in the future when the library is being used in real applications.