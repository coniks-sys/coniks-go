/*
Package merkletree implements a Merkle prefix tree and related data structures.
The Merkle prefix tree is one of the most important components of the CONIKS protocol.
We implemented this data structure separately as a library
to help other developers use it in their implementation easily.

Persistent Authenticated Dictionary

This module implements a persistent authenticated dictionary (PAD) data structure,
which supports dictionary operations with two additional features:
(1) lookups return a cryptographic proof of correctness along with the result,
and (2) it supports taking and storing snapshots of the current contents of
the dictionary to allow lookups in historical versions of the dictionary.
In CONIKS, the general PAD design is extended to return proofs for inserts.
This design does not support deletions, and that individual snapshots are linked
via a hash chain to commit the entire history. This PAD implementation also supports
randomizing the order of directory entries by changing the VRF private key.
This protects the user's privacy against other malicious parties who
wish to obtain information about users by querying the key directory.

Merkle Prefix Tree

This module implements the Merkle prefix tree, which is the data structure
underlying our PAD implementation. It is a binary tree, and that there are
two types of leaf nodes: empty leaf node and user leaf node. Each node contains
its prefix index and its level value. It provides methods to insert, update
(to update an existing key-value pair) and lookup.
The tree has the property of not being able to remove user leafs.
This Merkle prefix tree implementation also preserves the privacy feature:
the prefix used to search in the tree is a cryptographic transformation (VRF)
of the search key, and values are concealed using cryptographic commitments.
The VRF, commitment scheme and hash operations are provided by our crypto package
(see https://godoc.org/github.com/coniks-sys/coniks-go/crypto).
*/
package merkletree
