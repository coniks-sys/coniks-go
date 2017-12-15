/*
Package application is a library for building compatible CONIKS clients and
servers.

application implements the server- and client-side application-layer
components of the CONIKS key management and verification system.
More specifically, application provides
an API for building CONIKS registration proxies (bots), client applications,
and key servers.

Encoding

This module implements the message encoding and decoding for client-server
communications. Currently this module only supports JSON encoding.
Protobufs will be supported in the future.

Logger

This module implements a generic logging system that can be used by any
CONIKS application/executable.

ServerBase

This module provides an API for implementing any CONIKS server-side
functionality (either key server or auditor-client interface).
*/
package application
