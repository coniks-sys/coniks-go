# CONIKS Go

[![Build Status](https://travis-ci.org/coniks-sys/coniks-go.svg?branch=master)](https://travis-ci.org/coniks-sys/coniks-go)
[![Coverage Status](https://coveralls.io/repos/github/coniks-sys/coniks-go/badge.svg?branch=master&dummy=1)](https://coveralls.io/github/coniks-sys/coniks-go)

http://coniks.org

## Overview

CONIKS is a key management system that provides transparency and privacy
for end-user public keys.
CONIKS protects end-to-end encrypted communications against malicious or
compromised communication providers and surveillance by storing users'
encryption keys in tamper-evident and publicly auditable
key directories on the server side.
This allows messaging clients to verify the identity of
users automatically, and prevents malicious/compromised servers from
hijacking secure communications without getting caught.

This repository provides a [Golang](https://golang.org) implementation of the
CONIKS system. The implementation consists of a library, described in the
following section, a standalone CONIKS-server and -client, and a registration
proxy using this library.

## Golang Library

The packages in this library implement the various components of the CONIKS
system and may be imported individually.

- `application`: CONIKS application-layer library.
- `cli`: CONIKS command-line tools (registration bots, key server, and test client).
- `crypto`: Cryptographic algorithms and operations
- `merkletree`: Merkle prefix tree and related data structures
- `utils`: Utility functions
- `protocol`: CONIKS protocols implementation/library
- `storage`: Hooks for persistent storage backend (currently unused)

## Installation

You need to have [Golang](https://golang.org/doc/install) version 1.9 or higher installed.
If Golang is set up correctly, you can simply run:
```
go get github.com/coniks-sys/coniks-go/...
```

For usage instructions, see the documentation in their respective packages: [CONIKS-server](cli/coniksserver), a
simple command-line [client](cli/coniksclient), and the [registration-proxy](cli/coniksbot).

## Disclaimer

Please keep in mind that this CONIKS library is under active development.
The repository may contain experimental features that aren't fully tested.
We recommend using a [tagged release](https://github.com/coniks-sys/coniks-go/releases).

## API Documentation

https://godoc.org/github.com/coniks-sys/coniks-go

## Core Team

- **Marcela Melara** &lt;msmelara@gmail.com&gt; `C0EB3C38F30F80AB6A12C9B78E556CF999AAFE63`
