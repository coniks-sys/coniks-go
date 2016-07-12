[![Build Status](https://travis-ci.org/coniks-sys/libmerkleprefixtree-go.svg?branch=master)](https://travis-ci.org/coniks-sys/libmerkleprefixtree-go)

# libmerkleprefixtree-go
A Merkle prefix tree implementation in Golang

This library currently uses the `SHAKE128` ShakeHash with output size of 32 bytes.

The signature scheme is `Ed25519` signature algorithm.

### Usage
Initiate the history hash chain (the persistent authenticated dictionary)
```
// generate private key for STR signing
signKey := crypto.GenerateKey()

// init STR history chain with maximum length is len
// using DefaultPolicies as current policy
pad := NewPAD(NewPolicies(epochDeadline), signKey, len)
```

Update tree in each epoch
```
// insert new data
pad.Set(key, value)
...
// update STR history chain
// pass nil if the policies doesn't change
pad.Update(nil)
```

Look-up

`LookUp(key)` and `LookUpInEpoch(key, epoch)` return a `MerkleNode` instance and an `AuthenticationPath` for proofs of inclusion/absence.
A proof of absence also includes an empty leaf node in the returned auth path.

### TODO
Some methods/functions should be exported in the future when the library is being used in real applications.