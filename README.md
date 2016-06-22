[![Build Status](https://travis-ci.org/coniks-sys/libmerkleprefixtree-go.svg?branch=master)](https://travis-ci.org/coniks-sys/libmerkleprefixtree-go)

# libmerkleprefixtree-go
A Merkle prefix tree implementation in Golang

This library currently uses the `SHAKE128` ShakeHash with output size of 32 bytes.

The signature scheme is `Ed25519` signature algorithm.

### Usage
Initiate the tree
```
// using DefaultPolicies as current policy of the tree
m := merkletree.InitMerkleTree(&DefaultPolicies{}, "nonce", "salt")
// insert existing data (e.g., from db)
m.Set(key, value)
...

### TODO
Some methods/functions should be exported in the future when the library is being used in real applications.