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

package cgovrf

// VrfPrivkey is a private key used for producing VRF proofs.
// Specifically, we use a 64-byte ed25519 private key (the latter 32-bytes are the precomputed public key)
type VrfPrivkey [64]byte

// VrfPubkey is a public key that can be used to verify VRF proofs.
type VrfPubkey [32]byte

// VrfProof for a message can be generated with a secret key and verified against a public key, like a signature.
// Proofs are malleable, however, for a given message and public key, the VRF output that can be computed from a proof is unique.
type VrfProof [80]byte

// VrfOutput is a 64-byte pseudorandom value that can be computed from a VrfProof.
// The VRF scheme guarantees that such output will be unique
type VrfOutput [64]byte