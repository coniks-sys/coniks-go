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

// Package leveldbkv implements the kv interface using leveldb
package leveldbkv

import (
	"fmt"

	"github.com/coniks-sys/coniks-go/kv"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
)

type leveldbkv leveldb.DB

func OpenDB(path string) kv.DB {
	// open db & keep it open
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		panic(err)
	}
	return Wrap(db)
}

// Wrap uses a leveldb.DB as a kv.DB the obvious way (and with Sync:true).
func Wrap(db *leveldb.DB) kv.DB {
	return (*leveldbkv)(db)
}

func (db *leveldbkv) Get(key []byte) ([]byte, error) {
	return (*leveldb.DB)(db).Get(key, nil)
}

func (db *leveldbkv) Put(key, value []byte) error {
	return (*leveldb.DB)(db).Put(key, value, &opt.WriteOptions{Sync: true})
}

func (db *leveldbkv) Delete(key []byte) error {
	return (*leveldb.DB)(db).Delete(key, &opt.WriteOptions{Sync: true})
}

func (db *leveldbkv) NewBatch() kv.Batch {
	return new(leveldb.Batch)
}

func (db *leveldbkv) Write(b kv.Batch) error {
	wb, ok := b.(*leveldb.Batch)
	if !ok {
		return fmt.Errorf("leveldbkv.Write: expected *leveldb.Batch, got %T", b)
	}
	return (*leveldb.DB)(db).Write(wb, &opt.WriteOptions{Sync: true})
}

func (db *leveldbkv) NewIterator(rg *kv.Range) kv.Iterator {
	if rg == nil {
		return (*leveldb.DB)(db).NewIterator(nil, nil)
	}
	return (*leveldb.DB)(db).NewIterator(&util.Range{Start: rg.Start, Limit: rg.Limit}, nil)
}

func (db *leveldbkv) Close() error {
	return (*leveldb.DB)(db).Close()
}

func (db *leveldbkv) ErrNotFound() error {
	return leveldb.ErrNotFound
}
