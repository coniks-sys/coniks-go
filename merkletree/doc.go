/*
Package merkletree implements a Merkle prefix tree and related data structures.
The Merkle prefix tree is one of the most important components of the CONIKS protocol.
We implemented this data structure separately as a library
to help other developers use it in their implementation easily.

Persistent Authenticated Dictionary

This module implements a persistent authenticated dictionary (PAD) data structure.

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
