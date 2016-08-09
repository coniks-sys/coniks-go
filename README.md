# CONIKS Go Library

[![Build Status](https://travis-ci.org/coniks-sys/coniks-go.svg?branch=master)](https://travis-ci.org/coniks-sys/coniks-go)
[![Coverage Status](https://coveralls.io/repos/github/coniks-sys/coniks-go/badge.svg?branch=master&dummy=1)](https://coveralls.io/github/coniks-sys/coniks-go)

http://coniks.org

##Introduction
CONIKS is a key management system that provides transparency and privacy 
for end-user public keys.
CONIKS protects end-to-end encrypted communications against malicious or 
compromised communication providers and surveillance by storing users' 
encryption keys in tamper-evident and publicly auditable 
key directories on the server side. 
This allows messaging clients to verify the identity of 
users automatically, and prevents malicious/compromised servers from 
hijacking secure communications without getting caught.

## Golang Library
The packages in this library implement the various components of the CONIKS system and may be imported individually.

- ``client``: Client-side protocol cgo hooks
- ``crypto``: Cryptographic algorithms and operations
- ``merkletree``: Merkle prefix tree and related data structures
- ``storage``: DB hooks for storage backend (currently the library supports key-value db only)
- ``utils``: Utility functions 
- ``storage``: DB hooks for storage backend (currently the library supports key-value db only)

## Disclaimer
Please keep in mind that this CONIKS library is under active development. The repository may contain experimental features that aren't fully tested. We recommend using a [tagged release](https://github.com/coniks-sys/coniks-go/releases).

##Documentation
Coming soon!

## Current Core Developers
Releases of coniks-go will be signed with one of the following GPG keys:

- **Arlo Breault** &lt;arlo@torproject.org&gt; `4797E7E1069D84AC4040797A5E3A93B4D4DDCD8B`
- **Ismail Khoffi** &lt;Ismail.Khoffi@gmail.com&gt; `2BC709FBD0E50EB2D7272AD8760DA7917109FB7B`
- **Marcela Melara** &lt;msmelara@gmail.com&gt; `C0EB3C38F30F80AB6A12C9B78E556CF999AAFE`
- **Vu Quoc Huy** &lt;huyvq.c633@gmail.com&gt; `533191CEEC406DFF360D19DEC6202750C2FA740E`
