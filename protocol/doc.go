/*
Package protocol is a library for building compatible CONIKS clients and
servers.

protocol implements the server- and client-side components of the CONIKS key
management and verification protocols. More specifically, protocol provides
an API for maintaining an auditable, privacy-preserving key directory on a
server, as well as an API for checking the consistency of the directory
at the client.

Directory

This module implements a CONIKS key directory that a CONIKS key server
maintains. A directory is a publicly auditable, tamper-evident,
privacy-preserving data structure that contains mappings from usernames
to public keys. It currently supports registration of new mappings,
current key lookups, historical key lookups, and monitoring of mappings.
*/
package protocol
