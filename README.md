[![Build Status](https://travis-ci.org/coniks-sys/libmerkleprefixtree-go.svg?branch=merkle-tree)](https://travis-ci.org/coniks-sys/libmerkleprefixtree-go)

# libmerkleprefixtree-go
A Merkle prefix tree implementation in Golang

This library currently uses the `SHAKE128` ShakeHash with output size of 32 bytes. 

The signature scheme is `Ed25519` signature algorithm.

### Usage
Initiate the tree & history
```
// using DefaultPolicies as current policy of the tree
m := merkletree.InitMerkleTree(&DefaultPolicies{}, "nonce", "salt")
// insert existing data (e.g., from db)
m.Set(key, value)
...
// recompute tree hash
m.RecomputeHash()
// generate private key for STR signing
signKey := crypto.GenerateKey()
// init STR history chain
history := NewHistory(m, signKey, startupEpoch, epochInterval)
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
history.UpdateHistory(m, nextEpoch)
```

Look-up

`Get(key)` and `GetInEpoch(key, epoch)` return a `MerkleNode` instance and an _authenticate path_ for proofs of inclusion/absence.
A proof of absence also includes an empty leaf node in the returned auth path.

### TODO
Some methods/functions should be exported in the future when the library is being used in real applications.