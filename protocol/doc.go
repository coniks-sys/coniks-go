/*
Package protocol is a library for building compatible CONIKS clients and
servers.

protocol implements the server- and client-side components of the CONIKS key
management and verification protocols. More specifically, protocol provides
an API for maintaining an auditable, privacy-preserving key directory on a
server, as well as an API for checking the consistency of the directory
at the client.

Consistency Checks

This module implements all consistency checks performed by a CONIKS client
on directory proofs received from a CONIKS server. These operations
include the verification of username-to-key bindings (authentication paths),
and non-equivocation checks (signed tree roots).

Directory

This module implements a CONIKS key directory that a CONIKS key server
maintains. A directory is a publicly auditable, tamper-evident,
privacy-preserving data structure that contains mappings from usernames
to public keys. It currently supports registration of new mappings,
latest-version key lookups, historical key lookups, and monitoring of
mappings.

Error

This module defines the constants representing the types
of errors that a CONIKS server may return to a client,
and the results of a consistency check or a cryptographic verification
that a CONIKS client performs.

Message

This module defines the message format of the CONIKS client requests
and corresponding CONIKS server responses for each CONIKS protocol.
It also provides constructors for the response messages for each
protocol.

Policy

This module defines the directory's current CONIKS security/privacy
policies, which include the public part of the VRF key used to generate
private indices, the cryptographic algorithms in use, as well as the
protocol version number.

Temporary Binding

This module implements a temporary binding, which serves both as a proof of
registration with a directory and as a signed promise by a CONIKS server
to include the corresponding name-to-key binding in the next directory
snapshot.
As such, TBs allow clients to begin using a newly registered name-to-key
binding for encryption/signing immediately without having to wait for the
binding's inclusion in the next snapshot. However, clients must still check
in the next epoch that the binding has been included in the snapshot to
ensure that the server has not equivocated about it.
*/
package protocol
