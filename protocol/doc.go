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
and non-equivocation checks (signed tree root).

Directory

This module implements a CONIKS key directory that a CONIKS key server
maintains. A directory is a publicly auditable, tamper-evident,
privacy-preserving data structure that contains mappings from usernames
to public keys. It currently supports registration of new mappings,
latest-version key lookups, historical key lookups, and monitoring of mappings.

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
*/
package protocol
