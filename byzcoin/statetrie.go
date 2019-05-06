package byzcoin

import (
	"bytes"
	"encoding/binary"
	"errors"

	"go.dedis.ch/cothority/v3/byzcoin/trie"
	"go.dedis.ch/cothority/v3/darc"
	"go.etcd.io/bbolt"
)

var errKeyNotSet = errors.New("key not set")

// ReadOnlyStateTrie is the read-only interface for StagingStateTrie and
// StateTrie.
type ReadOnlyStateTrie interface {
	GetValues(key []byte) (value []byte, version uint64, contractID string, darcID darc.ID, err error)
	GetProof(key []byte) (*trie.Proof, error)
	GetIndex() int
	GetNonce() ([]byte, error)
	ForEach(func(k, v []byte) error) error
}

// StagingStateTrie is a wrapper around trie.StagingTrie that allows for use in
// byzcoin.
type StagingStateTrie struct {
	trie.StagingTrie
}

// Clone makes a copy of the staged data of the structure, the source Trie is
// not copied.
func (t *StagingStateTrie) Clone() *StagingStateTrie {
	return &StagingStateTrie{
		StagingTrie: *t.StagingTrie.Clone(),
	}
}

// StoreAll puts all the state changes and the index in the staging area.
func (t *StagingStateTrie) StoreAll(scs StateChanges) error {
	pairs := make([]trie.KVPair, len(scs))
	for i := range pairs {
		pairs[i] = &scs[i]
	}
	if err := t.StagingTrie.Batch(pairs); err != nil {
		return err
	}
	return nil
}

// GetValues returns the associated value, contract ID and darcID. An error is
// returned if the key does not exist or another issue occurs.
func (t *StagingStateTrie) GetValues(key []byte) (value []byte, version uint64, contractID string, darcID darc.ID, err error) {
	var buf []byte
	buf, err = t.Get(key)
	if err != nil {
		return
	}
	if buf == nil {
		err = errKeyNotSet
		return
	}

	var vals StateChangeBody
	vals, err = decodeStateChangeBody(buf)
	if err != nil {
		return
	}

	value = vals.Value
	version = vals.Version
	contractID = string(vals.ContractID)
	darcID = vals.DarcID
	return
}

// Commit commits the staged data to the source trie.
func (t *StagingStateTrie) Commit() error {
	return t.StagingTrie.Commit()
}

// GetIndex returns the index of the current trie.
func (t *StagingStateTrie) GetIndex() int {
	panic("cannot get index in StagingStateTrie")
}

const trieIndexKey = "trieIndexKey"

// stateTrie is a wrapper around trie.Trie that support the storage of an
// index.
type stateTrie struct {
	trie.Trie
}

// loadStateTrie loads an existing StateTrie, an error is returned if no trie
// exists in db
func loadStateTrie(db *bbolt.DB, bucket []byte) (*stateTrie, error) {
	t, err := trie.LoadTrie(trie.NewDiskDB(db, bucket))
	if err != nil {
		return nil, err
	}
	return &stateTrie{
		Trie: *t,
	}, nil
}

// newStateTrie creates a new, disk-based trie.Trie, an error is returned if
// the db already contains a trie.
func newStateTrie(db *bbolt.DB, bucket, nonce []byte) (*stateTrie, error) {
	t, err := trie.NewTrie(trie.NewDiskDB(db, bucket), nonce)
	if err != nil {
		return nil, err
	}
	return &stateTrie{
		Trie: *t,
	}, nil
}

// StoreAll stores the state changes in the Trie.
func (t *stateTrie) StoreAll(scs StateChanges, index int) error {
	pairs := make([]trie.KVPair, len(scs))
	for i := range pairs {
		pairs[i] = &scs[i]
	}
	return t.DB().Update(func(b trie.Bucket) error {
		if err := t.BatchWithBucket(pairs, b); err != nil {
			return err
		}
		indexBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(indexBuf, uint32(index))
		return t.SetMetadataWithBucket([]byte(trieIndexKey), indexBuf, b)
	})
}

// VerifiedStoreAll stores the state changes, the index as metadata. It checks
// whether the expectedRoot hash matches the computed root hash and returns an
// error if it doesn't.
func (t *stateTrie) VerifiedStoreAll(scs StateChanges, index int, expectedRoot []byte) error {
	pairs := make([]trie.KVPair, len(scs))
	for i := range pairs {
		pairs[i] = &scs[i]
	}
	return t.DB().Update(func(b trie.Bucket) error {
		if err := t.BatchWithBucket(pairs, b); err != nil {
			return err
		}
		indexBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(indexBuf, uint32(index))
		if err := t.SetMetadataWithBucket([]byte(trieIndexKey), indexBuf, b); err != nil {
			return err
		}
		if !bytes.Equal(t.GetRootWithBucket(b), expectedRoot) {
			return errors.New("root verfication failed")
		}
		return nil
	})
}

// GetValues returns the associated value, contractID and darcID. An error is
// returned if the key does not exist.
func (t *stateTrie) GetValues(key []byte) (value []byte, version uint64, contractID string, darcID darc.ID, err error) {
	var buf []byte
	buf, err = t.Get(key)
	if err != nil {
		return
	}
	if buf == nil {
		err = errKeyNotSet
		return
	}

	var vals StateChangeBody
	vals, err = decodeStateChangeBody(buf)
	if err != nil {
		return
	}

	value = vals.Value
	version = vals.Version
	contractID = string(vals.ContractID)
	darcID = vals.DarcID
	return
}

// GetIndex gets the latest index.
func (t *stateTrie) GetIndex() int {
	indexBuf := t.GetMetadata([]byte(trieIndexKey))
	if indexBuf == nil {
		return -1
	}
	return int(binary.LittleEndian.Uint32(indexBuf))
}

// MakeStagingStateTrie creates a StagingStateTrie from the StateTrie.
func (t *stateTrie) MakeStagingStateTrie() *StagingStateTrie {
	return &StagingStateTrie{
		StagingTrie: *t.MakeStagingTrie(),
	}
}

// NewMemStagingStateTrie creates an in-memory StagingStateTrie.
func NewMemStagingStateTrie(nonce []byte) (*StagingStateTrie, error) {
	memTrie, err := trie.NewTrie(trie.NewMemDB(), nonce)
	if err != nil {
		return nil, err
	}
	et := StagingStateTrie{
		StagingTrie: *memTrie.MakeStagingTrie(),
	}
	return &et, nil
}
