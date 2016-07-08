// Copyright 2014 The Dename Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"golang.org/x/crypto/ed25519"
)

const (
	SECRET_KEY string = "ed25519.secret"
	PUBLIC_KEY string = "ed25519.pub"
	VRF_SECRET string = "vrf.secret"
	VRF_PUBLIC string = "vrf.pub"
)

func main() {
	var vrf = flag.Bool("vrf", false, "Generate VRF key pair")
	var sign = flag.Bool("signing", false, "Generate Signing key pair")
	flag.Parse()

	switch true {
	case *vrf:
		mkVrfKey()
	case *sign:
		mkSigningKey()
	}
}

func mkSigningKey() {
	if _, err := os.Stat(SECRET_KEY); err == nil {
		fmt.Fprintf(os.Stderr, "%s already exists\n", SECRET_KEY)
		os.Exit(1)
	}
	if _, err := os.Stat(PUBLIC_KEY); err == nil {
		fmt.Fprintf(os.Stderr, "%s already exists\n", PUBLIC_KEY)
		os.Exit(1)
	}

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	if err := ioutil.WriteFile(SECRET_KEY, sk[:], 0600); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	if err = ioutil.WriteFile(PUBLIC_KEY, pk[:], 0644); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}

func mkVrfKey() {
	if _, err := os.Stat(VRF_SECRET); err == nil {
		fmt.Fprintf(os.Stderr, "%s already exists\n", VRF_SECRET)
		os.Exit(1)
	}
	if _, err := os.Stat(VRF_PUBLIC); err == nil {
		fmt.Fprintf(os.Stderr, "%s already exists\n", VRF_PUBLIC)
		os.Exit(1)
	}

	pk, sk, err := vrf.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	if err := ioutil.WriteFile(VRF_SECRET, sk[:], 0600); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	if err = ioutil.WriteFile(VRF_PUBLIC, pk[:], 0644); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
