# Merkle Tree
This package contains the CONIKS Merkle prefix tree implementation

We use the `SHAKE128` ShakeHash with output size of 32 bytes, and the signature scheme is `Ed25519` signature algorithm. See our [crypto package](https://github.com/coniks-sys/coniks-go/tree/master/crypto) for details and the implementation used.

### Usage
Initiate the history hash chain (the persistent authenticated dictionary)
```
// generate private key for STR signing
signKey := crypto.GenerateKey()

// init STR history chain with maximum length is len
pad := NewPAD(NewPolicies(epochDeadline, vrfPrivKey), signKey, len)
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

`LookUp(key)` and `LookUpInEpoch(key, epoch)` return an `AuthenticationPath` for proofs of inclusion/absence.
A proof of absence also includes an empty leaf node in the returned auth path.

### TODO
Some methods/functions should be exported in the future when the library is being used in real applications.