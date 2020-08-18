// Copyright 2018 The go-ethereum Authors
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
	"sync"
	"time"

	ogTypes "github.com/annchain/OG/og_interface"
	"github.com/annchain/commongo/bytes"
	"github.com/annchain/commongo/utils"
	"github.com/annchain/ogdb"
	"github.com/annchain/ogdb/leveldb/metrics"
	log "github.com/sirupsen/logrus"
)

var (
	EmptyHash = ogTypes.EmptyHash

	memcacheFlushTimeTimer  = metrics.NewRegisteredResettingTimer("trie/memcache/flush/time", nil)
	memcacheFlushNodesMeter = metrics.NewRegisteredMeter("trie/memcache/flush/nodes", nil)
	memcacheFlushSizeMeter  = metrics.NewRegisteredMeter("trie/memcache/flush/size", nil)

	memcacheGCTimeTimer  = metrics.NewRegisteredResettingTimer("trie/memcache/gc/time", nil)
	memcacheGCNodesMeter = metrics.NewRegisteredMeter("trie/memcache/gc/nodes", nil)
	memcacheGCSizeMeter  = metrics.NewRegisteredMeter("trie/memcache/gc/size", nil)

	memcacheCommitTimeTimer  = metrics.NewRegisteredResettingTimer("trie/memcache/commit/time", nil)
	memcacheCommitNodesMeter = metrics.NewRegisteredMeter("trie/memcache/commit/nodes", nil)
	memcacheCommitSizeMeter  = metrics.NewRegisteredMeter("trie/memcache/commit/size", nil)
)

// secureKeyPrefix is the database key prefix used to store trie node preimages.
var secureKeyPrefix = []byte("secure-key-")

// secureKeyLength is the length of the above prefix + 32byte hash.
const secureKeyLength = 11 + 32

// DatabaseReader wraps the Get and IsTxExists method of a backing store for the trie.
type DatabaseReader interface {
	// Get retrieves the value associated with key form the database.
	Get(key []byte) (value []byte, err error)

	// IsTxExists retrieves whether a key is present in the database.
	Has(key []byte) (bool, error)
}

// Database is an intermediate write layer between the trie data structures and
// the disk database. The aim is to accumulate trie writes in-memory and only
// periodically flush a couple tries to disk, garbage collecting the remainder.
type TrieDatabase struct {
	diskdb ogdb.Database // Persistent storage for matured trie nodes

	nodes  map[ogTypes.HashKey]*cachedNode // Data and references relationships of a node
	oldest ogTypes.Hash                    // Oldest tracked node, flush-list head
	newest ogTypes.Hash                    // Newest tracked node, flush-list tail

	preimages map[ogTypes.HashKey][]byte // Preimages of nodes from the secure trie
	seckeybuf [secureKeyLength]byte      // Ephemeral buffer for calculating preimage keys

	gctime  time.Duration     // Time spent on garbage collection since last commit
	gcnodes uint64            // Nodes garbage collected since last commit
	gcsize  utils.StorageSize // Data storage garbage collected since last commit

	flushtime  time.Duration     // Time spent on data flushing since last commit
	flushnodes uint64            // Nodes flushed since last commit
	flushsize  utils.StorageSize // Data storage flushed since last commit

	nodesSize     utils.StorageSize // Storage size of the nodes cache (exc. flushlist)
	preimagesSize utils.StorageSize // Storage size of the preimages cache

	lock sync.RWMutex
}

// cachedNode is all the information we know about a single cached node in the
// memory database write layer.
type cachedNode struct {
	blob     []byte                  // Cached data block of the trie node
	parents  int                     // Number of live nodes referencing this one
	children map[ogTypes.HashKey]int // Children referenced by this nodes

	flushPrev ogTypes.Hash // Previous node in the flush-list
	flushNext ogTypes.Hash // Next node in the flush-list
}

// NewDatabase creates a new trie database to store ephemeral trie content before
// its written out to disk or garbage collected.
func NewTrieDatabase(diskdb ogdb.Database) *TrieDatabase {
	return &TrieDatabase{
		diskdb: diskdb,
		nodes: map[ogTypes.HashKey]*cachedNode{
			EmptyHash.HashKey(): {children: make(map[ogTypes.HashKey]int)},
		},
		preimages: make(map[ogTypes.HashKey][]byte),
	}
}

// DiskDB retrieves the persistent storage backing the trie database.
func (db *TrieDatabase) DiskDB() DatabaseReader {
	return db.diskdb
}

// Insert writes a new trie node to the memory database if it's yet unknown. The
// method will make a copy of the slice.
func (db *TrieDatabase) Insert(hash ogTypes.Hash, blob []byte) {
	db.lock.Lock()
	defer db.lock.Unlock()

	db.insert(hash, blob)
}

// insert is the private locked version of Insert.
func (db *TrieDatabase) insert(hash ogTypes.Hash, blob []byte) {
	// If the node's already cached, skip
	if _, ok := db.nodes[hash.HashKey()]; ok {
		return
	}
	db.nodes[hash.HashKey()] = &cachedNode{
		blob:      bytes.CopyBytes(blob),
		children:  make(map[ogTypes.HashKey]int),
		flushPrev: db.newest,
	}
	// Update the flush-list endpoints
	//log.Tracef("Panic debug, insert hash: %x, db.oldest: %x", hash.KeyBytes, db.oldest.KeyBytes)
	if db.oldest.HashKey() == EmptyHash.HashKey() {
		db.oldest, db.newest = hash, hash
	} else {
		//log.Tracef("Panic debug, insert hash: %x, get db.newest: %x", hash.KeyBytes, db.newest.KeyBytes)
		db.nodes[db.newest.HashKey()].flushNext, db.newest = hash, hash
	}
	db.nodesSize += utils.StorageSize(len(hash.Bytes()) + len(blob))
}

// insertPreimage writes a new trie node pre-image to the memory database if it's
// yet unknown. The method will make a copy of the slice.
//
// Note, this method assumes that the database's lock is held!
func (db *TrieDatabase) insertPreimage(hash ogTypes.Hash, preimage []byte) {
	if _, ok := db.preimages[hash.HashKey()]; ok {
		return
	}
	db.preimages[hash.HashKey()] = bytes.CopyBytes(preimage)
	db.preimagesSize += utils.StorageSize(len(hash.Bytes()) + len(preimage))
}

// Node retrieves a cached trie node from memory. If it cannot be found cached,
// the method queries the persistent database for the content.
func (db *TrieDatabase) Node(hash ogTypes.Hash) ([]byte, error) {
	// Retrieve the node from cache if available
	db.lock.RLock()
	node := db.nodes[hash.HashKey()]
	db.lock.RUnlock()

	if node != nil {
		return node.blob, nil
	}
	// Content unavailable in memory, attempt to retrieve from disk
	return db.diskdb.Get(hash.Bytes())
}

// preimage retrieves a cached trie node pre-image from memory. If it cannot be
// found cached, the method queries the persistent database for the content.
func (db *TrieDatabase) preimage(hash ogTypes.Hash) ([]byte, error) {
	// Retrieve the node from cache if available
	db.lock.RLock()
	preimage := db.preimages[hash.HashKey()]
	db.lock.RUnlock()

	if preimage != nil {
		return preimage, nil
	}
	// Content unavailable in memory, attempt to retrieve from disk
	return db.diskdb.Get(db.secureKey(hash.Bytes()))
}

// secureKey returns the database key for the preimage of key, as an ephemeral
// buffer. The caller must not hold onto the return value because it will become
// invalid on the next call.
func (db *TrieDatabase) secureKey(key []byte) []byte {
	buf := append(db.seckeybuf[:0], secureKeyPrefix...)
	buf = append(buf, key...)
	return buf
}

// Nodes retrieves the hashes of all the nodes cached within the memory database.
// This method is extremely expensive and should only be used to validate internal
// states in test code.
func (db *TrieDatabase) Nodes() []ogTypes.Hash {
	db.lock.RLock()
	defer db.lock.RUnlock()

	var hashes = make([]ogTypes.Hash, 0, len(db.nodes))
	for hashKey := range db.nodes {
		if hashKey != EmptyHash.HashKey() { // Special case for "root" references/nodes
			hashes = append(hashes, ogTypes.HashKeyToHash(hashKey))
		}
	}
	return hashes
}

// Reference adds a new reference from a parent node to a child node.
func (db *TrieDatabase) Reference(child ogTypes.Hash, parent ogTypes.Hash) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	db.reference(child, parent)
}

// reference is the private locked version of Reference.
func (db *TrieDatabase) reference(child ogTypes.Hash, parent ogTypes.Hash) {
	// If the node does not exist, it's a node pulled from disk, skip
	node, ok := db.nodes[child.HashKey()]
	if !ok {
		return
	}
	// If the reference already exists, only duplicate for roots
	if _, ok = db.nodes[parent.HashKey()].children[child.HashKey()]; ok && parent.HashKey() != EmptyHash.HashKey() {
		return
	}
	node.parents++
	db.nodes[parent.HashKey()].children[child.HashKey()]++
}

// Dereference removes an existing reference from a parent node to a child node.
func (db *TrieDatabase) Dereference(child ogTypes.Hash, parent ogTypes.Hash) {
	db.lock.Lock()
	defer db.lock.Unlock()

	nodes, storage, start := len(db.nodes), db.nodesSize, time.Now()
	db.dereference(child.HashKey(), parent.HashKey())

	db.gcnodes += uint64(nodes - len(db.nodes))
	db.gcsize += storage - db.nodesSize
	db.gctime += time.Since(start)

	memcacheGCTimeTimer.Update(time.Since(start))
	memcacheGCSizeMeter.Mark(int64(storage - db.nodesSize))
	memcacheGCNodesMeter.Mark(int64(nodes - len(db.nodes)))

	log.Debug("Dereferenced trie from memory database", "nodes", nodes-len(db.nodes), "size", storage-db.nodesSize, "time", time.Since(start),
		"gcnodes", db.gcnodes, "gcsize", db.gcsize, "gctime", db.gctime, "livenodes", len(db.nodes), "livesize", db.nodesSize)
}

// dereference is the private locked version of Dereference.
func (db *TrieDatabase) dereference(childKey ogTypes.HashKey, parentKey ogTypes.HashKey) {
	// Dereference the parent-child
	node := db.nodes[parentKey]

	node.children[childKey]--
	if node.children[childKey] == 0 {
		delete(node.children, childKey)
	}
	// If the child does not exist, it's a previously committed node.
	node, ok := db.nodes[childKey]
	if !ok {
		return
	}
	// If there are no more references to the child, delete it and cascade
	node.parents--
	if node.parents == 0 {
		// Remove the node from the flush-list
		if childKey == db.oldest.HashKey() {
			db.oldest = node.flushNext
		} else {
			db.nodes[node.flushPrev.HashKey()].flushNext = node.flushNext
			db.nodes[node.flushNext.HashKey()].flushPrev = node.flushPrev
		}
		// Dereference all children and delete the node
		for hashKey := range node.children {
			db.dereference(hashKey, childKey)
		}
		delete(db.nodes, childKey)
		db.nodesSize -= utils.StorageSize(len(childKey.Bytes()) + len(node.blob))
	}
}

// Cap iteratively flushes old but still referenced trie nodes until the total
// memory usage goes below the given threshold.
func (db *TrieDatabase) Cap(limit utils.StorageSize) error {
	// Create a database batch to flush persistent data out. It is important that
	// outside code doesn't see an inconsistent state (referenced data removed from
	// memory cache during commit but not yet in persistent storage). This is ensured
	// by only uncaching existing data when the database write finalizes.
	db.lock.RLock()

	nodes, storage, start := len(db.nodes), db.nodesSize, time.Now()
	batch := db.diskdb.NewBatch()

	// db.nodesSize only contains the useful data in the cache, but when reporting
	// the total memory consumption, the maintenance metadata is also needed to be
	// counted. For every useful node, we track 2 extra hashes as the flushlist.
	nodesHashKeySize := 0
	for hashKey := range db.nodes {
		nodesHashKeySize += len(hashKey.Bytes())
	}
	nodesHashKeySize *= 2
	size := db.nodesSize + utils.StorageSize(nodesHashKeySize)

	// If the preimage cache got large enough, push to disk. If it's still small
	// leave for later to deduplicate writes.
	flushPreimages := db.preimagesSize > 4*1024*1024
	if flushPreimages {
		for hashKey, preimage := range db.preimages {
			if err := batch.Put(db.secureKey(hashKey.Bytes()), preimage); err != nil {
				log.Error("Failed to commit preimage from trie database", "err", err)
				db.lock.RUnlock()
				return err
			}
			if batch.ValueSize() > ogdb.IdealBatchSize {
				if err := batch.Write(); err != nil {
					db.lock.RUnlock()
					return err
				}
				batch.Reset()
			}
		}
	}
	// Keep committing nodes from the flush-list until we're below allowance
	oldest := db.oldest
	for size > limit && oldest.HashKey() != EmptyHash.HashKey() {
		// Fetch the oldest referenced node and push into the batch
		node := db.nodes[oldest.HashKey()]
		if err := batch.Put(oldest.Bytes(), node.blob); err != nil {
			db.lock.RUnlock()
			return err
		}
		// If we exceeded the ideal batch size, commit and reset
		if batch.ValueSize() >= ogdb.IdealBatchSize {
			if err := batch.Write(); err != nil {
				log.Error("Failed to write flush list to disk", "err", err)
				db.lock.RUnlock()
				return err
			}
			batch.Reset()
		}
		// Iterate to the next flush item, or abort if the size cap was achieved. Size
		// is the total size, including both the useful cached data (hash -> blob), as
		// well as the flushlist metadata (2*hash). When flushing items from the cache,
		// we need to reduce both.
		size -= utils.StorageSize(3*len(oldest.Bytes()) + len(node.blob))
		oldest = node.flushNext
	}
	// Flush out any remainder data from the last batch
	if err := batch.Write(); err != nil {
		log.Error("Failed to write flush list to disk", "err", err)
		db.lock.RUnlock()
		return err
	}
	db.lock.RUnlock()

	// Write successful, clear out the flushed data
	db.lock.Lock()
	defer db.lock.Unlock()

	if flushPreimages {
		db.preimages = make(map[ogTypes.HashKey][]byte)
		db.preimagesSize = 0
	}
	for db.oldest != oldest {
		node := db.nodes[db.oldest.HashKey()]
		delete(db.nodes, db.oldest.HashKey())
		db.nodesSize -= utils.StorageSize(len(db.oldest.Bytes()) + len(node.blob))
		db.oldest = node.flushNext
	}
	if db.oldest.HashKey() != EmptyHash.HashKey() {
		db.nodes[db.oldest.HashKey()].flushPrev = &ogTypes.Hash32{}
	}
	db.flushnodes += uint64(nodes - len(db.nodes))
	db.flushsize += storage - db.nodesSize
	db.flushtime += time.Since(start)

	memcacheFlushTimeTimer.Update(time.Since(start))
	memcacheFlushSizeMeter.Mark(int64(storage - db.nodesSize))
	memcacheFlushNodesMeter.Mark(int64(nodes - len(db.nodes)))

	log.Debug("Persisted nodes from memory database", "nodes", nodes-len(db.nodes), "size", storage-db.nodesSize, "time", time.Since(start),
		"flushnodes", db.flushnodes, "flushsize", db.flushsize, "flushtime", db.flushtime, "livenodes", len(db.nodes), "livesize", db.nodesSize)

	return nil
}

// Commit iterates over all the children of a particular node, writes them out
// to disk, forcefully tearing down all references in both directions.
//
// As a side effect, all pre-images accumulated up to this point are also written.
func (db *TrieDatabase) Commit(node ogTypes.Hash, report bool) error {
	// Create a database batch to flush persistent data out. It is important that
	// outside code doesn't see an inconsistent state (referenced data removed from
	// memory cache during commit but not yet in persistent storage). This is ensured
	// by only uncaching existing data when the database write finalizes.
	db.lock.RLock()

	start := time.Now()
	batch := db.diskdb.NewBatch()

	// Move all of the accumulated preimages into a write batch
	for hashKey, preimage := range db.preimages {
		if err := batch.Put(db.secureKey(hashKey.Bytes()), preimage); err != nil {
			log.Error("Failed to commit preimage from trie database", "err", err)
			db.lock.RUnlock()
			return err
		}
		if batch.ValueSize() > ogdb.IdealBatchSize {
			if err := batch.Write(); err != nil {
				return err
			}
			batch.Reset()
		}
	}
	// Move the trie itself into the batch, flushing if enough data is accumulated
	nodes, storage := len(db.nodes), db.nodesSize
	if err := db.commit(node.HashKey(), batch); err != nil {
		log.Error("Failed to commit trie from trie database", "err", err)
		db.lock.RUnlock()
		return err
	}
	// Write batch ready, unlock for readers during persistence
	if err := batch.Write(); err != nil {
		log.Error("Failed to write trie to disk", "err", err)
		db.lock.RUnlock()
		return err
	}
	db.lock.RUnlock()

	// Write successful, clear out the flushed data
	db.lock.Lock()
	defer db.lock.Unlock()

	db.preimages = make(map[ogTypes.HashKey][]byte)
	db.preimagesSize = 0

	db.uncache(node.HashKey())

	memcacheCommitTimeTimer.Update(time.Since(start))
	memcacheCommitSizeMeter.Mark(int64(storage - db.nodesSize))
	memcacheCommitNodesMeter.Mark(int64(nodes - len(db.nodes)))

	logger := log.Info
	if !report {
		logger = log.Debug
	}
	logger("Persisted trie from memory database", "nodes", nodes-len(db.nodes)+int(db.flushnodes), "size", storage-db.nodesSize+db.flushsize, "time", time.Since(start)+db.flushtime,
		"gcnodes", db.gcnodes, "gcsize", db.gcsize, "gctime", db.gctime, "livenodes", len(db.nodes), "livesize", db.nodesSize)

	// Reset the garbage collection statistics
	db.gcnodes, db.gcsize, db.gctime = 0, 0, 0
	db.flushnodes, db.flushsize, db.flushtime = 0, 0, 0

	return nil
}

// commit is the private locked version of Commit.
func (db *TrieDatabase) commit(hashKey ogTypes.HashKey, batch ogdb.Batch) error {
	// If the node does not exist, it's a previously committed node
	node, ok := db.nodes[hashKey]
	if !ok {
		return nil
	}
	for childKey := range node.children {
		if err := db.commit(childKey, batch); err != nil {
			return err
		}
	}
	if err := batch.Put(hashKey.Bytes(), node.blob); err != nil {
		return err
	}
	// If we've reached an optimal batch size, commit and start over
	if batch.ValueSize() >= ogdb.IdealBatchSize {
		if err := batch.Write(); err != nil {
			return err
		}
		batch.Reset()
	}
	return nil
}

// uncache is the post-processing step of a commit operation where the already
// persisted trie is removed from the cache. The reason behind the two-phase
// commit is to ensure consistent data availability while moving from memory
// to disk.
func (db *TrieDatabase) uncache(hashKey ogTypes.HashKey) {

	//log.Tracef("Panic debug, uncache the node: %x, cur db.oldest: %x", hash.KeyBytes, db.oldest.KeyBytes)
	// If the node does not exist, we're done on this path
	node, ok := db.nodes[hashKey]
	if !ok {
		return
	}
	// Node still exists, remove it from the flush-list
	if hashKey == db.oldest.HashKey() {
		//log.Tracef("Panic debug, uncache the node: %x, set oldest to: %x", hash.KeyBytes, node.flushNext.KeyBytes)
		db.oldest = node.flushNext
	} else {
		//log.Tracef("Panic debug, uncache the node: %x, delete node between next: %x, prev: %x", hash.KeyBytes, node.flushNext.KeyBytes, node.flushPrev.KeyBytes)
		db.nodes[node.flushPrev.HashKey()].flushNext = node.flushNext
		db.nodes[node.flushNext.HashKey()].flushPrev = node.flushPrev
	}
	// Uncache the node's subtries and remove the node itself too
	for childKey := range node.children {
		db.uncache(childKey)
	}
	delete(db.nodes, hashKey)
	db.nodesSize -= utils.StorageSize(len(hashKey.Bytes()) + len(node.blob))
}

// Size returns the current storage size of the memory cache in front of the
// persistent database layer.
func (db *TrieDatabase) Size() (utils.StorageSize, utils.StorageSize) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	// db.nodesSize only contains the useful data in the cache, but when reporting
	// the total memory consumption, the maintenance metadata is also needed to be
	// counted. For every useful node, we track 2 extra hashes as the flushlist.
	flushListSize := 0
	for hashKey := range db.nodes {
		flushListSize += len(hashKey.Bytes())
	}
	flushListSize *= 2

	return db.nodesSize + utils.StorageSize(flushListSize), db.preimagesSize
}
