/*
Package merkletree implements a Merkle prefix tree and related data structures.
The Merkle prefix tree is one of the most important components of the CONIKS protocol.
We implemented this data structure separately as a library
to help other developers use it in their implementation easily.

Persistent Authenticated Dictionary

This module implements a persistent authenticated dictionary (PAD) where the client
can query a name-to-key binding at a specific epoch and get authenticated answer.
The PAD is represented by a hash chain committing to the entire history. This hash chain
is used to prove to the client that the PAD is maintaining a linear hash chain
and there is no equivocations.

Merkle Tree

This module implements the Merkle prefix tree data structure. It provides methods to
insert, update and lookup. The tree is append-only which means there is no ways to delete
any node from the tree or change a user leaf node to an empty node.
All the tree hash operations use the hash algorithm provided by our crypto package
(see https://godoc.org/github.com/coniks-sys/coniks-go/crypto).
*/
package merkletree
