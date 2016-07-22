# CONIKS Go Library

[![Build Status](https://travis-ci.org/coniks-sys/coniks-go.svg?branch=master)](https://travis-ci.org/coniks-sys/coniks-go)

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

- ``crypto``: Cryptographic algorithms and operations
- ``merkletree``: Merkle prefix tree and related data structures
- ``storage``: DB hooks for storage backend (currently the library supports key-value db only)
- ``utils``: Utility functions 

## Disclaimer
Please keep in mind that this CONIKS library is under active development. The repository may contain experimental features that aren't fully tested. We recommend using a [tagged release](https://github.com/coniks-sys/coniks-go/releases).

##Documentation
Coming soon!
