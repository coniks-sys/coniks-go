package main

import "testing"

func TestVerifyVrf(t *testing.T) { testVerifyVrf(t) }

func TestVerifySignature(t *testing.T) { testVerifySignature(t) }

func TestVerifyHashChain(t *testing.T) { testVerifyHashChain(t) }

func TestVerifyAuthPath(t *testing.T) { testVerifyAuthPath(t) }

func TestVerifyProofOfAbsenceSamePrefix(t *testing.T) { testVerifyProofOfAbsenceSamePrefix(t) }
