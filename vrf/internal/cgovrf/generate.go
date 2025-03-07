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

// Package cgovrf provides Verifiable Random Function (VRF) implementation using libsodium via CGO.
// 
// Building libsodium:
// To build libsodium, run one of:
//   - `go generate github.com/tmc/go-algorand/crypto/vrf/internal/cgovrf`
//   - `cd internal/cgovrf && make`
//
// Cleaning build artifacts:
//   - `cd internal/cgovrf && make clean`
package cgovrf

//go:generate make -f Makefile build-libsodium