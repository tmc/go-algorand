// Copyright (C) 2019-2023 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

//go:generate go generate ./internal/cgovrf

package crypto

import (
	"crypto/rand"
	"io"
	"sync"

	"github.com/tmc/go-algorand/crypto/vrf/internal/cgovrf"
)

// TODO: Go arrays are copied by value, so any call to e.g. VrfPrivkey.Prove() makes a copy of the secret key that lingers in memory.
// To avoid this, should we instead allocate memory for secret keys here (maybe even in the C heap) and pass around pointers?
// e.g., allocate a privkey with sodium_malloc and have VrfPrivkey be of type unsafe.Pointer?
type (
	// A VrfPrivkey is a private key used for producing VRF proofs.
	// Specifically, we use a 64-byte ed25519 private key (the latter 32-bytes are the precomputed public key)
	VrfPrivkey [64]byte
	// A VrfPubkey is a public key that can be used to verify VRF proofs.
	VrfPubkey [32]byte
	// A VrfProof for a message can be generated with a secret key and verified against a public key, like a signature.
	// Proofs are malleable, however, for a given message and public key, the VRF output that can be computed from a proof is unique.
	VrfProof [80]byte
	// VrfOutput is a 64-byte pseudorandom value that can be computed from a VrfProof.
	// The VRF scheme guarantees that such output will be unique
	VrfOutput [64]byte
)

// deprecated names + wrappers -- TODO remove

// VRFVerifier is a deprecated name for VrfPubkey
type VRFVerifier = VrfPubkey

// VRFProof is a deprecated name for VrfProof
type VRFProof = VrfProof

// VRFSecrets is a wrapper for a VRF keypair. Use *VrfPrivkey instead
type VRFSecrets struct {
	_struct struct{} `codec:""`

	PK VrfPubkey
	SK VrfPrivkey
}

var (
	useGoImplementation bool
	implMutex           sync.RWMutex
)

// SetUseGoImplementation controls whether to use the pure Go implementation (true) or the C/libsodium implementation (false)
func SetUseGoImplementation(useGo bool) {
	implMutex.Lock()
	defer implMutex.Unlock()
	useGoImplementation = useGo
}

// VrfKeygenFromSeed deterministically generates a VRF keypair from 32 bytes of (secret) entropy.
func VrfKeygenFromSeed(seed [32]byte) (pub VrfPubkey, priv VrfPrivkey) {
	implMutex.RLock()
	defer implMutex.RUnlock()

	if useGoImplementation {
		return VrfKeygenFromSeedGo(seed)
	}

	cPub, cPriv := cgovrf.VrfKeygenFromSeed(seed)
	copy(pub[:], cPub[:])
	copy(priv[:], cPriv[:])
	return
}

// VrfKeygen generates a random VRF keypair.
func VrfKeygen() (pub VrfPubkey, priv VrfPrivkey) {
	implMutex.RLock()
	defer implMutex.RUnlock()

	if useGoImplementation {
		// VrfKeygenGo isn't implemented yet, but it can be done by generating a random seed
		// and calling VrfKeygenFromSeedGo
		var seed [32]byte
		_, err := io.ReadFull(rand.Reader, seed[:])
		if err != nil {
			panic("crypto/rand failed to generate random bytes")
		}
		return VrfKeygenFromSeedGo(seed)
	}

	cPub, cPriv := cgovrf.VrfKeygen()
	copy(pub[:], cPub[:])
	copy(priv[:], cPriv[:])
	return
}

// Pubkey returns the public key that corresponds to the given private key.
func (sk VrfPrivkey) Pubkey() (pk VrfPubkey) {
	implMutex.RLock()
	defer implMutex.RUnlock()

	if useGoImplementation {
		// Extract the public key part from the private key (it's stored in the second half)
		copy(pk[:], sk[32:])
		return
	}

	var cSk cgovrf.VrfPrivkey
	copy(cSk[:], sk[:])
	cPk := cSk.Pubkey()
	copy(pk[:], cPk[:])
	return
}

func (sk VrfPrivkey) proveBytes(msg []byte) (proof VrfProof, ok bool) {
	implMutex.RLock()
	defer implMutex.RUnlock()

	if useGoImplementation {
		return sk.proveBytesGo(msg)
	}

	var cSk cgovrf.VrfPrivkey
	copy(cSk[:], sk[:])
	cProof, cOk := cSk.ProveBytes(msg)
	copy(proof[:], cProof[:])
	return proof, cOk
}

// Prove constructs a VRF Proof for a given Hashable.
// ok will be false if the private key is malformed.
func (sk VrfPrivkey) Prove(message Hashable) (proof VrfProof, ok bool) {
	return sk.proveBytes(HashRep(message))
}

// Hash converts a VRF proof to a VRF output without verifying the proof.
// TODO: Consider removing so that we don't accidentally hash an unverified proof
func (proof VrfProof) Hash() (hash VrfOutput, ok bool) {
	implMutex.RLock()
	defer implMutex.RUnlock()

	var cProof cgovrf.VrfProof
	copy(cProof[:], proof[:])
	cHash, cOk := cProof.Hash()
	copy(hash[:], cHash[:])
	return hash, cOk
}

func (pk VrfPubkey) verifyBytes(proof VrfProof, msg []byte) (bool, VrfOutput) {
	implMutex.RLock()
	defer implMutex.RUnlock()

	if useGoImplementation {
		return pk.verifyBytesGo(proof, msg)
	}

	var cPk cgovrf.VrfPubkey
	var cProof cgovrf.VrfProof
	copy(cPk[:], pk[:])
	copy(cProof[:], proof[:])

	cOk, cOut := cPk.VerifyBytes(cProof, msg)
	var out VrfOutput
	copy(out[:], cOut[:])
	return cOk, out
}

// validateGoVerify is a temporary helper that allows testing both C and Go VRF implementations (this will be removed before this branch is merged).
var validateGoVerify func(pk VrfPubkey, p VrfProof, message Hashable, ok bool, out VrfOutput)

// Verify checks a VRF proof of a given Hashable. If the proof is valid the pseudorandom VrfOutput will be returned.
// For a given public key and message, there are potentially multiple valid proofs.
// However, given a public key and message, all valid proofs will yield the same output.
// Moreover, the output is indistinguishable from random to anyone without the proof or the secret key.
func (pk VrfPubkey) Verify(p VrfProof, message Hashable) (bool, VrfOutput) {
	msgBytes := HashRep(message)
	ok, out := pk.verifyBytes(p, msgBytes)
	// Temporary addition to enable build tag based setting of an implementation to compare C and Go implementations.
	if validateGoVerify != nil {
		validateGoVerify(pk, p, message, ok, out)
	}
	return ok, out
}