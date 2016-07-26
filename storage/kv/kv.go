// Copyright 2014-2015 The Coname Authors.
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

// Package kv contains a generic interface for key-value databases with support
// for batch writes. All operations are safe for concurrent use, atomic and
// synchronously persistent.
package kv

import "errors"

// DB is an abstract ordered key-value store. All operations are assumed to be
// synchronous, atomic and linearizable. This includes the following guarantee:
// After Put(k, v) has returned, and as long as no other Put(k, ?) has been
// called happened, Get(k) MUST return always v, regardless of whether the
// process or the entire system has been reset in the meantime or very little
// time has passed. To amortize the overhead of synchronous writes, DB offers
// batch operations: Write(...) performs a series of Put-s atomically (and
// possibly almost as fast as a single Put).
type DB interface {
	Get(key []byte) ([]byte, error)
	Put(key, value []byte) error
	Delete(key []byte) error
	NewBatch() Batch
	Write(Batch) error
	NewIterator(*Range) Iterator
	Close() error

	ErrNotFound() error
}

// A Batch contains a sequence of Put-s waiting to be Write-n to a DB.
type Batch interface {
	Reset()
	Put(key, value []byte)
	Delete(key []byte)
}

// Iterator is an abstract pointer to a DB entry. It must be valid to call
// Error() after release. The boolean return values indicate whether the
// requested entry exists.
type Iterator interface {
	Key() []byte
	Value() []byte
	First() bool
	Next() bool
	Last() bool
	Release()
	Error() error
}

var (
	ErrorBadBufferLength = errors.New("[kv] Bad KV buffer's length")
)
