/*
Package client provides a library for all client-side CONIKS operations.

Introduction

One crucial component of the CONIKS key management system are the clients
verifying the cryptographic proofs returned by the CONIKS server as part of
the registration, lookup and monitoring protocols. client implements the
operations performed by CONIKS clients during these protocols. This document
outlines each of these protocols from a client perspective.

Registration

- The user registers her username with the CONIKS client.

- The client generates a new public-private key pair for this username,
and stores the keys on the device.

- The client sends a registration request
        reg_req = (username, key)
to the server (may be validated by a registration bot; see
https://github.com/coniks-sys/coniks-go/bots)

- If the registration request is accepted*, the server returns a registration proof.
More specifically, the server returns a proof of absence:
        reg_pf = (auth_path, str)
If the server supports the temporary binding protocol extension, reg_pf will
also include a temporary binding (see https://github.com/coniks-sys/coniks-go/merkletree/tb.go)

- The client recomputes the root hash of the directory using the given auth_path,
and verifies that the str includes the recomputed root in its signature.

- If registration proof is invalid, the client notifies the user. Reporting mechanism TBD.

* The registration request may be denied for one of the following reasons: (1) The
client attempts to register a name that already exists in the CONIKS key directory
(ErrorNameExisted); the server returns a privacy-preserving proof of inclusion
in its response. (2) The server encounters an internal error when attempting to
register the name (ErrorDirectory).

*/
package client
