// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package trie

import (
	"fmt"
	"sync"

	ogTypes "github.com/annchain/OG/og_interface"
	"github.com/annchain/ogdb"
	lru "github.com/hashicorp/golang-lru"
)

// MaxTrieCacheGen is trie cache generation limit after which to evict trie nodes from memory.
var MaxTrieCacheGen = uint16(120)

const (
	// Number of past tries to keep. This value is chosen such that
	// reasonable chain reorg depths will hit an existing trie.
	maxPastTries = 12

	// Number of codehash->size associations to keep.
	codeSizeCacheSize = 100000
)

// Database wraps access to tries and contract code.
type Database interface {
	// OpenTrie opens the main account trie.
	OpenTrie(root ogTypes.Hash) (TrieI, error)

	// OpenStorageTrie opens the storage trie of an account.
	OpenStorageTrie(addrHash, root ogTypes.Hash) (TrieI, error)

	// CopyTrie returns an independent copy of the given trie.
	CopyTrie(TrieI) TrieI

	// ContractCode retrieves a particular contract's code.
	ContractCode(addrHash, codeHash ogTypes.Hash) ([]byte, error)

	// ContractCodeSize retrieves a particular contracts code's size.
	ContractCodeSize(addrHash, codeHash ogTypes.Hash) (int, error)

	// TrieDB retrieves the low level trie database used for data storage.
	TrieDB() *TrieDatabase
}

// Trie is a Ethereum Merkle Trie.
type TrieI interface {
	TryGet(key []byte) ([]byte, error)
	TryUpdate(key, value []byte) error
	TryDelete(key []byte) error
	// preCommit is a flag for pre confirming sequencer. Because pre confirm uses the
	// same trie db in real sequencer confirm and the db will be modified during db commit.
	// To avoid this, add a flag to let pre confirm process not modify trie db anymore.
	Commit(onleaf LeafCallback, preCommit bool) (ogTypes.Hash, error)
	Hash() ogTypes.Hash
	NodeIterator(startKey []byte) NodeIterator
	GetKey([]byte) []byte // TODO(fjl): remove this when SecureTrie is removed
	Prove(key []byte, fromLevel uint, proofDb ogdb.Putter) error
}

// NewDatabase creates a backing store for state. The returned database is safe for
// concurrent use and retains cached trie nodes in memory. The pool is an optional
// intermediate trie-node memory pool between the low level storage layer and the
// high level trie abstraction.
func NewDatabase(db ogdb.Database) Database {
	csc, _ := lru.New(codeSizeCacheSize)
	return &cachingDB{
		db:            NewTrieDatabase(db),
		codeSizeCache: csc,
	}
}

type cachingDB struct {
	db            *TrieDatabase
	mu            sync.Mutex
	pastTries     []*SecureTrie
	codeSizeCache *lru.Cache
}

// OpenTrie opens the main account trie.
func (db *cachingDB) OpenTrie(root ogTypes.Hash) (TrieI, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	for i := len(db.pastTries) - 1; i >= 0; i-- {
		if db.pastTries[i].Hash() == root {
			return cachedTrie{db.pastTries[i].Copy(), db}, nil
		}
	}
	tr, err := NewSecure(root, db.db, MaxTrieCacheGen)
	if err != nil {
		return nil, err
	}
	return cachedTrie{tr, db}, nil
}

func (db *cachingDB) pushTrie(t *SecureTrie) {
	db.mu.Lock()
	defer db.mu.Unlock()

	if len(db.pastTries) >= maxPastTries {
		copy(db.pastTries, db.pastTries[1:])
		db.pastTries[len(db.pastTries)-1] = t
	} else {
		db.pastTries = append(db.pastTries, t)
	}
}

// OpenStorageTrie opens the storage trie of an account.
func (db *cachingDB) OpenStorageTrie(addrHash, root ogTypes.Hash) (TrieI, error) {
	return NewSecure(root, db.db, 0)
}

// CopyTrie returns an independent copy of the given trie.
func (db *cachingDB) CopyTrie(t TrieI) TrieI {
	switch t := t.(type) {
	case cachedTrie:
		return cachedTrie{t.SecureTrie.Copy(), db}
	case *SecureTrie:
		return t.Copy()
	default:
		panic(fmt.Errorf("unknown trie type %T", t))
	}
}

// ContractCode retrieves a particular contract's code.
func (db *cachingDB) ContractCode(addrHash, codeHash ogTypes.Hash) ([]byte, error) {
	code, err := db.db.Node(codeHash)
	if err == nil {
		db.codeSizeCache.Add(codeHash, len(code))
	}
	return code, err
}

// ContractCodeSize retrieves a particular contracts code's size.
func (db *cachingDB) ContractCodeSize(addrHash, codeHash ogTypes.Hash) (int, error) {
	if cached, ok := db.codeSizeCache.Get(codeHash); ok {
		return cached.(int), nil
	}
	code, err := db.ContractCode(addrHash, codeHash)
	return len(code), err
}

// TrieDB retrieves any intermediate trie-node caching layer.
func (db *cachingDB) TrieDB() *TrieDatabase {
	return db.db
}

// cachedTrie inserts its trie into a cachingDB on commit.
type cachedTrie struct {
	*SecureTrie
	db *cachingDB
}

func (m cachedTrie) Commit(onleaf LeafCallback, preCommit bool) (ogTypes.Hash, error) {
	root, err := m.SecureTrie.Commit(onleaf, preCommit)
	if err == nil {
		m.db.pushTrie(m.SecureTrie)
	}
	return root, err
}

func (m cachedTrie) Prove(key []byte, fromLevel uint, proofDb ogdb.Putter) error {
	return m.SecureTrie.Prove(key, fromLevel, proofDb)
}
