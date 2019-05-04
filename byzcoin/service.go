// Package byzcoin implements the ByzCoin ledger.
package byzcoin

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/byzcoin/trie"
	"go.dedis.ch/cothority/v3/byzcoin/viewchange"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
	bbolt "go.etcd.io/bbolt"
	uuid "gopkg.in/satori/go.uuid.v1"
)

var pairingSuite = suites.MustFind("bn256.adapter").(*pairing.SuiteBn256)

// This is to boost the acceptable timestamp window when dealing with
// very short block intervals, like in testing. If a production ByzCoin
// had a block interval of 30 seconds, for example, this minimum will
// not trigger, and the acceptable window would be ± 30 sec.
var minTimestampWindow = 10 * time.Second

// For tests to influence when the whole trie will be downloaded if
// some blocks are missing.
var catchupDownloadAll = 100

// How much minimum time between two catch up requests
var catchupMinimumInterval = 10 * time.Minute

// How many blocks it should fetch in one go.
var catchupFetchBlocks = 10

// How many DB-entries to download in one go.
var catchupFetchDBEntries = 100

var rotationWindow time.Duration = 10

const noTimeout time.Duration = 0

const collectTxProtocol = "CollectTxProtocol"

const viewChangeSubFtCosi = "viewchange_sub_ftcosi"
const viewChangeFtCosi = "viewchange_ftcosi"

var viewChangeMsgID network.MessageTypeID

// ByzCoinID can be used to refer to this service.
var ByzCoinID onet.ServiceID

// Verify is the verifier ID for ByzCoin skipchains.
var Verify = skipchain.VerifierID(uuid.NewV5(uuid.NamespaceURL, "ByzCoin"))

func init() {
	var err error
	ByzCoinID, err = onet.RegisterNewServiceWithSuite(ServiceName, pairingSuite, newService)
	log.ErrFatal(err)
	network.RegisterMessages(&bcStorage{}, &DataHeader{}, &DataBody{})
	viewChangeMsgID = network.RegisterMessage(&viewchange.InitReq{})
}

// GenNonce returns a random nonce.
func GenNonce() (n Nonce) {
	random.Bytes(n[:], random.New())
	return n
}

// Service is the ByzCoin service.
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
	// stateTries contains a reference to all the tries that the service is
	// responsible for, one for each skipchain.
	stateTries     map[string]*stateTrie
	stateTriesLock sync.Mutex
	// We need to store the state changes for keeping track
	// of the history of an instance
	stateChangeStorage *stateChangeStorage
	// notifications is used for client transaction and block notification
	notifications bcNotifications

	// pollChan maintains a map of channels that can be used to stop the
	// polling go-routing.
	pollChan    map[string]chan bool
	pollChanMut sync.Mutex
	pollChanWG  sync.WaitGroup

	// NOTE: If we have a lot of skipchains, then using mutex most likely
	// will slow down our service, an improvement is to go-routines to
	// store transactions. But there is more management overhead, e.g.,
	// restarting after shutdown, answer getTxs requests and so on.
	txBuffer txBuffer

	heartbeats             heartbeats
	heartbeatsTimeout      chan string
	closeLeaderMonitorChan chan bool

	// contracts map kinds to kind specific verification functions
	contracts map[string]ContractFn

	storage *bcStorage

	createSkipChainMut sync.Mutex

	darcToSc    map[string]skipchain.SkipBlockID
	darcToScMut sync.Mutex

	stateChangeCache stateChangeCache

	closed        bool
	closedMutex   sync.Mutex
	working       sync.WaitGroup
	viewChangeMan viewChangeManager

	streamingMan streamingManager

	updateTrieLock        sync.Mutex
	catchingUp            bool
	catchingUpHistory     map[string]time.Time
	catchingUpHistoryLock sync.Mutex

	unknownSkipchains map[string]bool

	downloadState downloadState
}

type downloadState struct {
	id    skipchain.SkipBlockID
	nonce uint64
	read  chan DBKeyValue
	stop  chan bool
}

// storageID reflects the data we're storing - we could store more
// than one structure.
var storageID = []byte("ByzCoin")

// defaultInterval is used if the BlockInterval field in the genesis
// transaction is not set.
const defaultInterval = 5 * time.Second

// defaultMaxBlockSize is used when the config cannot be loaded.
const defaultMaxBlockSize = 4 * 1e6

// bcStorage is used to save our data locally.
type bcStorage struct {
	// PropTimeout is used when sending the request to integrate a new block
	// to all nodes.
	PropTimeout time.Duration

	sync.Mutex
}

// CreateGenesisBlock asks the service to create a new skipchain ready to
// store key/value pairs. If it is given exactly one writer, this writer will
// be stored in the skipchain.
// For faster access, all data is also stored locally in the Service.storage
// structure.
func (s *Service) CreateGenesisBlock(req *CreateGenesisBlock) (
	*CreateGenesisBlockResponse, error) {
	// We use a big mutex here because we do not want to allow concurrent
	// creation of genesis blocks.
	// TODO an optimisation would be to lock on the skipchainID.
	s.createSkipChainMut.Lock()
	defer s.createSkipChainMut.Unlock()

	if req.Version != CurrentVersion {
		return nil, fmt.Errorf("version mismatch - got %d but need %d", req.Version, CurrentVersion)
	}
	if req.Roster.List == nil {
		return nil, errors.New("must provide a roster")
	}

	darcBuf, err := req.GenesisDarc.ToProto()
	if err != nil {
		return nil, err
	}
	if req.GenesisDarc.Verify(true) != nil ||
		req.GenesisDarc.Rules.Count() == 0 {
		return nil, errors.New("invalid genesis darc")
	}

	if req.BlockInterval == 0 {
		req.BlockInterval = defaultInterval
	}
	intervalBuf := make([]byte, 8)
	binary.PutVarint(intervalBuf, int64(req.BlockInterval))

	if req.MaxBlockSize == 0 {
		req.MaxBlockSize = defaultMaxBlockSize
	}
	bsBuf := make([]byte, 8)
	binary.PutVarint(bsBuf, int64(req.MaxBlockSize))

	rosterBuf, err := protobuf.Encode(&req.Roster)
	if err != nil {
		return nil, err
	}

	// The user must include at least one contract that can be parsed as a
	// DARC and it must exist.
	if len(req.DarcContractIDs) == 0 {
		return nil, errors.New("must provide at least one DARC contract")
	}
	for _, c := range req.DarcContractIDs {
		if _, ok := s.GetContractConstructor(c); !ok {
			return nil, errors.New("the given contract \"" + c + "\" does not exist")
		}
	}

	dcIDs := darcContractIDs{
		IDs: req.DarcContractIDs,
	}
	darcContractIDsBuf, err := protobuf.Encode(&dcIDs)
	if err != nil {
		return nil, err
	}

	// This is the nonce for the trie.
	// TODO this nonce is picked by the root, how to make sure it's secure?
	nonce := GenNonce()

	spawn := &Spawn{
		ContractID: ContractConfigID,
		Args: Arguments{
			{Name: "darc", Value: darcBuf},
			{Name: "block_interval", Value: intervalBuf},
			{Name: "max_block_size", Value: bsBuf},
			{Name: "roster", Value: rosterBuf},
			{Name: "trie_nonce", Value: nonce[:]},
			{Name: "darc_contracts", Value: darcContractIDsBuf},
		},
	}

	// Create the genesis-transaction with a special key, it acts as a
	// reference to the actual genesis transaction.
	ctx := ClientTransaction{
		Instructions: []Instruction{{
			InstanceID: ConfigInstanceID,
			Spawn:      spawn,
		}},
	}

	sb, err := s.createNewBlock(nil, &req.Roster, NewTxResults(ctx))
	if err != nil {
		return nil, err
	}

	return &CreateGenesisBlockResponse{
		Version:   CurrentVersion,
		Skipblock: sb,
	}, nil
}

// AddTransaction requests to apply a new transaction to the ledger.
func (s *Service) AddTransaction(req *AddTxRequest) (*AddTxResponse, error) {
	if req.Version != CurrentVersion {
		return nil, errors.New("version mismatch")
	}

	if len(req.Transaction.Instructions) == 0 {
		return nil, errors.New("no transactions to add")
	}

	gen := s.db().GetByID(req.SkipchainID)
	if gen == nil || gen.Index != 0 {
		return nil, errors.New("skipchain ID is does not exist")
	}

	latest, err := s.db().GetLatest(gen)
	if err != nil {
		if latest == nil {
			return nil, err
		}
		log.Warn("Got block, but with an error:", err)
	}
	if i, _ := latest.Roster.Search(s.ServerIdentity().ID); i < 0 {
		return nil, errors.New("refusing to accept transaction for a chain we're not part of")
	}

	_, maxsz, err := s.LoadBlockInfo(req.SkipchainID)
	if err != nil {
		return nil, err
	}
	txsz := txSize(TxResult{ClientTransaction: req.Transaction})
	if txsz > maxsz {
		return nil, errors.New("transaction too large")
	}

	for i, instr := range req.Transaction.Instructions {
		log.Lvlf2("Instruction[%d]: %s", i, instr.Action())
	}

	// Note to my future self: s.txBuffer.add used to be out here. It used to work
	// even. But while investigating other race conditions, we realized that
	// IF there will be a wait channel, THEN it must exist before the call to add().
	// If add() comes first, there's a race condition where the block could theoretically
	// be created and (not) notified before the wait channel is created. Moving
	// add() after createWaitChannel() solves this, but then we need a second add() for the
	// no inclusion wait case.

	if req.InclusionWait > 0 {
		// Wait for InclusionWait new blocks and look if our transaction is in it.
		interval, _, err := s.LoadBlockInfo(req.SkipchainID)
		if err != nil {
			return nil, errors.New("couldn't get block info: " + err.Error())
		}

		ctxHash := req.Transaction.Instructions.Hash()
		ch := s.notifications.createWaitChannel(ctxHash)
		defer s.notifications.deleteWaitChannel(ctxHash)

		blockCh := make(chan skipchain.SkipBlockID, 10)
		z := s.notifications.registerForBlocks(blockCh)
		defer s.notifications.unregisterForBlocks(z)

		s.txBuffer.add(string(req.SkipchainID), req.Transaction)

		// In case we don't have any blocks, because there are no transactions,
		// have a hard timeout in twice the minimal expected time to create the
		// blocks.
		tooLongDur := time.Duration(req.InclusionWait) * interval * 2
		tooLong := time.After(tooLongDur)

		blocksLeft := req.InclusionWait

		for found := false; !found; {
			select {
			case success := <-ch:
				if !success {
					return nil, errors.New("transaction is in block, but got refused")
				}
				found = true
			case id := <-blockCh:
				if id.Equal(req.SkipchainID) {
					blocksLeft--
				}
				if blocksLeft == 0 {
					return nil, fmt.Errorf("did not find transaction after %v blocks", req.InclusionWait)
				}
			case <-tooLong:
				return nil, fmt.Errorf("transaction didn't get included after %v (2 * t_block * %d)", tooLongDur, req.InclusionWait)
			}
		}
	} else {
		s.txBuffer.add(string(req.SkipchainID), req.Transaction)
	}

	return &AddTxResponse{
		Version: CurrentVersion,
	}, nil
}

// GetProof searches for a key and returns a proof of the
// presence or the absence of this key.
func (s *Service) GetProof(req *GetProof) (resp *GetProofResponse, err error) {
	s.updateTrieLock.Lock()
	defer s.updateTrieLock.Unlock()
	if s.catchingUp {
		return nil, errors.New("currently catching up on our state")
	}
	if req.Version != CurrentVersion {
		return nil, errors.New("version mismatch")
	}

	log.Lvlf2("Returning proof for %x from chain '%x'", req.Key, req.ID)

	sb := s.db().GetByID(req.ID)
	if sb == nil {
		err = errors.New("cannot find skipblock while getting proof")
		return
	}
	st, err := s.GetReadOnlyStateTrie(sb.SkipChainID())
	if err != nil {
		return nil, err
	}
	proof, err := NewProof(st, s.db(), req.ID, req.Key)
	if err != nil {
		log.Error(s.ServerIdentity(), err)
		return
	}

	// Sanity check
	if err = proof.Verify(sb.SkipChainID()); err != nil {
		return
	}

	_, v := proof.InclusionProof.KeyValue()
	log.Lvlf3("value is %x", v)
	resp = &GetProofResponse{
		Version: CurrentVersion,
		Proof:   *proof,
	}
	return
}

// CheckAuthorization verifies whether a given combination of identities can
// fulfill a given rule of a given darc. Because all darcs are now used in
// an online fashion, we need to offer this check.
func (s *Service) CheckAuthorization(req *CheckAuthorization) (resp *CheckAuthorizationResponse, err error) {
	if req.Version != CurrentVersion {
		return nil, errors.New("version mismatch")
	}
	log.Lvlf2("%s getting authorizations of darc %x", s.ServerIdentity(), req.DarcID)

	resp = &CheckAuthorizationResponse{}
	st, err := s.GetReadOnlyStateTrie(req.ByzCoinID)
	if err != nil {
		return nil, err
	}
	d, err := LoadDarcFromTrie(st, req.DarcID)
	if err != nil {
		return nil, errors.New("couldn't find darc: " + err.Error())
	}
	getDarcs := func(s string, latest bool) *darc.Darc {
		if !latest {
			log.Error("cannot handle intermediate darcs")
			return nil
		}
		id, err := hex.DecodeString(strings.Replace(s, "darc:", "", 1))
		if err != nil || len(id) != 32 {
			log.Error("invalid darc id", s, len(id), err)
			return nil
		}
		d, err := LoadDarcFromTrie(st, id)
		if err != nil {
			log.Error("didn't find darc")
			return nil
		}
		return d
	}
	var ids []string
	for _, i := range req.Identities {
		ids = append(ids, i.String())
	}
	for _, r := range d.Rules.List {
		err = darc.EvalExprDarc(r.Expr, getDarcs, true, ids...)
		if err == nil {
			resp.Actions = append(resp.Actions, r.Action)
		}
	}
	return resp, nil
}

// GetSignerCounters gets the latest signer counters for the given identities.
func (s *Service) GetSignerCounters(req *GetSignerCounters) (*GetSignerCountersResponse, error) {
	st, err := s.GetReadOnlyStateTrie(req.SkipchainID)
	if err != nil {
		return nil, err
	}
	out := make([]uint64, len(req.SignerIDs))

	for i := range req.SignerIDs {
		key := publicVersionKey(req.SignerIDs[i])
		buf, _, _, _, err := st.GetValues(key)
		if err == errKeyNotSet {
			out[i] = 0
			continue
		}

		if err != nil {
			return nil, err
		}
		out[i] = binary.LittleEndian.Uint64(buf)
	}
	resp := GetSignerCountersResponse{
		Counters: out,
	}
	return &resp, nil
}

// DownloadState creates a snapshot of the current state and then returns the
// instances in small chunks.
func (s *Service) DownloadState(req *DownloadState) (resp *DownloadStateResponse, err error) {
	s.updateTrieLock.Lock()
	defer s.updateTrieLock.Unlock()
	if req.Length <= 0 {
		return nil, errors.New("length must be bigger than 0")
	}

	if req.Nonce == 0 {
		log.Lvl2("Creating new download")
		if !s.downloadState.id.IsNull() {
			log.Lvlf2("Aborting download of nonce %x", s.downloadState.nonce)
			close(s.downloadState.stop)
		}
		sb := s.db().GetByID(req.ByzCoinID)
		if sb == nil || sb.Index > 0 {
			return nil, errors.New("unknown byzcoinID")
		}
		s.downloadState.id = req.ByzCoinID
		s.downloadState.read = make(chan DBKeyValue)
		s.downloadState.stop = make(chan bool)
		nonce := binary.LittleEndian.Uint64(random.Bits(64, true, random.New()))
		s.downloadState.nonce = nonce
		go func(ds downloadState) {
			idStr := fmt.Sprintf("%x", ds.id)
			db, bucketName := s.GetAdditionalBucket([]byte(idStr))
			err := db.View(func(tx *bbolt.Tx) error {
				bucket := tx.Bucket(bucketName)
				return bucket.ForEach(func(k []byte, v []byte) error {
					key := make([]byte, len(k))
					copy(key, k)
					value := make([]byte, len(v))
					copy(value, v)
					select {
					case ds.read <- DBKeyValue{key, value}:
					case <-ds.stop:
						return errors.New("closed")
					case <-time.After(time.Minute):
						return errors.New("timed out while waiting for next read")
					}
					return nil
				})
			})
			if err != nil {
				log.Error("while serving current database:", err)
			}
			close(ds.read)
		}(s.downloadState)
	} else if !s.downloadState.id.Equal(req.ByzCoinID) || req.Nonce != s.downloadState.nonce {
		return nil, errors.New("download has been aborted in favor of another download")
	}

	resp = &DownloadStateResponse{
		Nonce: s.downloadState.nonce,
	}
query:
	for i := 0; i < req.Length; i++ {
		select {
		case kv, ok := <-s.downloadState.read:
			if !ok {
				break query
			}
			resp.KeyValues = append(resp.KeyValues, kv)
		}
	}
	return
}

func entryToResponse(sce *StateChangeEntry, ok bool, err error) (*GetInstanceVersionResponse, error) {
	if !ok {
		err = errKeyNotSet
	}
	if err != nil {
		return nil, err
	}

	return &GetInstanceVersionResponse{
		StateChange: sce.StateChange,
		BlockIndex:  sce.BlockIndex,
	}, nil
}

// GetInstanceVersion looks for the version of a given instance and responds
// with the state change and the block index
func (s *Service) GetInstanceVersion(req *GetInstanceVersion) (*GetInstanceVersionResponse, error) {
	sce, ok, err := s.stateChangeStorage.getByVersion(req.InstanceID[:], req.Version, req.SkipChainID)

	return entryToResponse(&sce, ok, err)
}

// GetLastInstanceVersion looks for the last version of an instance and
// responds with the state change and the block when it hits
func (s *Service) GetLastInstanceVersion(req *GetLastInstanceVersion) (*GetInstanceVersionResponse, error) {
	sce, ok, err := s.stateChangeStorage.getLast(req.InstanceID[:], req.SkipChainID)

	return entryToResponse(&sce, ok, err)
}

// GetAllInstanceVersion looks for all the state changes of an instance
// and responds with both the state change and the block index for
// each version
func (s *Service) GetAllInstanceVersion(req *GetAllInstanceVersion) (res *GetAllInstanceVersionResponse, err error) {
	sces, err := s.stateChangeStorage.getAll(req.InstanceID[:], req.SkipChainID)
	if err != nil {
		return nil, err
	}

	scs := make([]GetInstanceVersionResponse, len(sces))
	for i, e := range sces {
		scs[i].StateChange = e.StateChange
		scs[i].BlockIndex = e.BlockIndex
	}

	return &GetAllInstanceVersionResponse{StateChanges: scs}, nil
}

// CheckStateChangeValidity gets the list of state changes belonging to the same
// block as the targeted one so that a hash can be computed and compared to the
// one stored in the block
func (s *Service) CheckStateChangeValidity(req *CheckStateChangeValidity) (*CheckStateChangeValidityResponse, error) {
	sce, ok, err := s.stateChangeStorage.getByVersion(req.InstanceID[:], req.Version, req.SkipChainID)
	if !ok {
		err = errKeyNotSet
	}
	if err != nil {
		return nil, err
	}

	sb, err := s.skService().GetSingleBlockByIndex(&skipchain.GetSingleBlockByIndex{
		Genesis: req.SkipChainID,
		Index:   sce.BlockIndex,
	})
	if err != nil {
		return nil, err
	}

	sces, err := s.stateChangeStorage.getByBlock(req.SkipChainID, sce.BlockIndex)
	if err != nil {
		return nil, err
	}

	scs := make(StateChanges, len(sces))
	for i, e := range sces {
		scs[i] = e.StateChange.Copy()
	}

	return &CheckStateChangeValidityResponse{
		StateChanges: scs,
		BlockID:      sb.SkipBlock.Hash,
	}, nil
}

type leafNode struct {
	Prefix []bool
	Key    []byte
	Value  []byte
}

// ProcessClientRequest implements onet.Service. We override the version
// we normally get from embedding onet.ServiceProcessor in order to
// hook it and get a look at the http.Request.
func (s *Service) ProcessClientRequest(req *http.Request, path string, buf []byte) ([]byte, *onet.StreamingTunnel, error) {
	if path == "Debug" {
		h, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			return nil, nil, err
		}
		ip := net.ParseIP(h)

		if !ip.IsLoopback() {
			return nil, nil, errors.New("the 'debug'-endpoint is only allowed on loopback")
		}
	}

	return s.ServiceProcessor.ProcessClientRequest(req, path, buf)
}

// Debug can be used to dump things from a byzcoin service. If byzcoinID is nil, it will return all
// existing byzcoin instances. If byzcoinID is given, it will return all instances for that ID.
func (s *Service) Debug(req *DebugRequest) (resp *DebugResponse, err error) {
	resp = &DebugResponse{}
	if len(req.ByzCoinID) != 32 {
		rep, err := s.skService().GetAllSkipChainIDs(nil)
		if err != nil {
			return nil, err
		}

		for _, scID := range rep.IDs {
			latest, err := s.db().GetLatestByID(scID)
			if err != nil {
				continue
			}
			if !s.hasByzCoinVerification(skipchain.SkipBlockID(latest.SkipChainID())) {
				continue
			}
			genesis := s.db().GetByID(latest.SkipChainID())
			resp.Byzcoins = append(resp.Byzcoins, DebugResponseByzcoin{
				ByzCoinID: latest.SkipChainID(),
				Genesis:   genesis,
				Latest:    latest,
			})
		}
		return resp, nil
	}
	st, err := s.getStateTrie(skipchain.SkipBlockID(req.ByzCoinID))
	if err != nil {
		return nil, errors.New("didn't find this byzcoin instance: " + err.Error())
	}
	err = st.DB().View(func(b trie.Bucket) error {
		err := b.ForEach(func(k, v []byte) error {
			if len(k) == 32 {
				if v[0] == byte(3) {
					ln := leafNode{}
					err = protobuf.Decode(v[1:], &ln)
					if err != nil {
						log.Error(err)
						// Not all key/value pairs are valid statechanges
						return nil
					}
					scb := StateChangeBody{}
					err = protobuf.Decode(ln.Value, &scb)
					resp.Dump = append(resp.Dump, DebugResponseState{Key: ln.Key, State: scb})
				}
			}
			return nil
		})
		return err
	})
	return
}

// DebugRemove deletes an existing byzcoin-instance from the conode.
func (s *Service) DebugRemove(req *DebugRemoveRequest) (*DebugResponse, error) {
	if err := schnorr.Verify(cothority.Suite, s.ServerIdentity().Public, req.ByzCoinID, req.Signature); err != nil {
		log.Error("Signature failure:", err)
		return nil, err
	}
	idStr := string(req.ByzCoinID)
	if s.heartbeats.exists(idStr) {
		log.Lvl2("Removing heartbeat")
		s.heartbeats.stop(idStr)
	}

	s.pollChanMut.Lock()
	pc, exists := s.pollChan[idStr]
	if exists {
		log.Lvl2("Closing polling-channel")
		close(pc)
		delete(s.pollChan, idStr)
	}
	s.pollChanMut.Unlock()

	s.stateTriesLock.Lock()
	idStrHex := fmt.Sprintf("%x", req.ByzCoinID)
	_, exists = s.stateTries[idStrHex]
	if exists {
		log.Lvl2("Removing state-trie")
		db, bn := s.GetAdditionalBucket([]byte(idStrHex))
		if db == nil {
			return nil, errors.New("didn't find trie for this byzcoin-ID")
		}
		err := db.Update(func(tx *bbolt.Tx) error {
			return tx.DeleteBucket(bn)
		})
		if err != nil {
			return nil, err
		}
		delete(s.stateTries, idStr)
		err = s.db().RemoveSkipchain(req.ByzCoinID)
		if err != nil {
			log.Error("couldn't remove the whole chain:", err)
		}
	}
	s.stateTriesLock.Unlock()

	s.darcToScMut.Lock()
	for k, sc := range s.darcToSc {
		if sc.Equal(skipchain.SkipBlockID(req.ByzCoinID)) {
			log.Lvl2("Removing darc-to-skipchain mapping")
			delete(s.darcToSc, k)
		}
	}
	s.darcToScMut.Unlock()

	log.Lvl2("Stopping view change monitor")
	s.viewChangeMan.stop(skipchain.SkipBlockID(req.ByzCoinID))

	s.save()
	return &DebugResponse{}, nil
}

// SetPropagationTimeout overrides the default propagation timeout that is used
// when a new block is announced to the nodes as well as the skipchain
// propagation timeout.
func (s *Service) SetPropagationTimeout(p time.Duration) {
	s.storage.Lock()
	s.storage.PropTimeout = p
	s.storage.Unlock()
	s.save()
	s.skService().SetPropTimeout(p)
}

// createNewBlock creates a new block and proposes it to the
// skipchain-service. Once the block has been created, we
// inform all nodes to update their internal trie
// to include the new transactions.
func (s *Service) createNewBlock(scID skipchain.SkipBlockID, r *onet.Roster, tx []TxResult) (*skipchain.SkipBlock, error) {
	var sb *skipchain.SkipBlock
	var mr []byte
	var sst *StagingStateTrie

	if scID.IsNull() {
		// For a genesis block, we create a throwaway staging trie.
		// There is no need to verify the darc because the caller does
		// it.
		if r == nil {
			return nil, errors.New("need roster for genesis block")
		}
		sb = skipchain.NewSkipBlock()
		sb.MaximumHeight = 32
		sb.BaseHeight = 4
		// We have to register the verification functions in the genesis block
		sb.VerifierIDs = []skipchain.VerifierID{skipchain.VerifyBase, Verify}

		nonce, err := s.LoadNonceFromTxs(tx)
		if err != nil {
			return nil, err
		}
		et, err := NewMemStagingStateTrie(nonce)
		if err != nil {
			return nil, err
		}
		sst = et
	} else {
		// For all other blocks, we try to verify the signature using
		// the darcs and remove those that do not have a valid
		// signature before continuing.
		sbLatest, err := s.db().GetLatestByID(scID)
		if err != nil {
			return nil, errors.New(
				"Could not get latest block from the skipchain: " + err.Error())
		}
		log.Lvlf3("Creating block #%d with %d transactions", sbLatest.Index+1,
			len(tx))
		sb = sbLatest.Copy()

		st, err := s.getStateTrie(scID)
		if err != nil {
			return nil, err
		}
		sst = st.MakeStagingStateTrie()
	}

	// Create header of skipblock containing only hashes
	var scs StateChanges
	var err error
	var txRes TxResults

	log.Lvl3("Creating state changes")
	mr, txRes, scs, _ = s.createStateChanges(sst, scID, tx, noTimeout)
	if len(txRes) == 0 {
		return nil, errors.New("no transactions")
	}

	// Store transactions in the body
	body := &DataBody{TxResults: txRes}
	sb.Payload, err = protobuf.Encode(body)
	if err != nil {
		return nil, errors.New("Couldn't marshal data: " + err.Error())
	}

	header := &DataHeader{
		TrieRoot:              mr,
		ClientTransactionHash: txRes.Hash(),
		StateChangesHash:      scs.Hash(),
		Timestamp:             time.Now().UnixNano(),
	}
	sb.Data, err = protobuf.Encode(header)
	if err != nil {
		return nil, errors.New("Couldn't marshal data: " + err.Error())
	}

	if r != nil {
		sb.Roster = r
	}
	var ssb = skipchain.StoreSkipBlock{
		NewBlock:          sb,
		TargetSkipChainID: scID,
	}

	log.Lvlf3("Storing skipblock with %d transactions.", len(txRes))
	var ssbReply *skipchain.StoreSkipBlockReply

	if sb.Roster.List[0].Equal(s.ServerIdentity()) {
		ssbReply, err = s.skService().StoreSkipBlockInternal(&ssb)
	} else {
		log.Lvl2("Sending new block to other node", sb.Roster.List[0])
		ssbReply = &skipchain.StoreSkipBlockReply{}
		err = skipchain.NewClient().SendProtobuf(sb.Roster.List[0], &ssb, ssbReply)
		if err != nil {
			return nil, err
		}

		if ssbReply.Latest == nil {
			return nil, errors.New("got an empty reply")
		}

		// we're not doing more verification because the block should not be used
		// as is. It's up to the client to fetch the forward link of the previous
		// block to insure the new one has been validated but at this moment we
		// can't do it because it might not be propagated to this node yet
	}

	if err != nil {
		return nil, err
	}

	// State changes are cached only when the block is confirmed
	err = s.stateChangeStorage.append(scs, ssbReply.Latest)
	if err != nil {
		log.Error(err)
	}

	return ssbReply.Latest, nil
}

// downloadDB downloads the full database over the network from a remote block.
// It does so by copying the bboltDB database entry by entry over the network,
// and recreating it on the remote side.
// sb is a block in the byzcoin instance that we want
// to download.
func (s *Service) downloadDB(sb *skipchain.SkipBlock) error {
	log.Lvlf2("%s: downloading DB", s.ServerIdentity())
	idStr := fmt.Sprintf("%x", sb.SkipChainID())

	// Loop over all nodes that are not the leader and
	// not subleaders, to avoid overloading those nodes.
	nodes := len(sb.Roster.List)
	subLeaders := int(math.Ceil(math.Pow(float64(nodes), 1./3.)))
	for ri := 1 + subLeaders; ri < nodes; ri++ {
		// Create a roster with just the node we want to
		// download from.
		roster := onet.NewRoster(sb.Roster.List[ri : ri+1])

		err := func() error {
			// First delete an existing stateTrie. There
			// cannot be another write-access to the
			// database because s.catchingUp == true.
			_, err := s.getStateTrie(sb.SkipChainID())
			if err == nil {
				// Suppose we _do_ have a statetrie
				db, stBucket := s.GetAdditionalBucket(sb.SkipChainID())
				err := db.Update(func(tx *bbolt.Tx) error {
					return tx.DeleteBucket(stBucket)
				})
				if err != nil {
					log.Fatal("Cannot delete existing trie while trying to download:", err)
				}
				s.stateTriesLock.Lock()
				delete(s.stateTries, idStr)
				s.stateTriesLock.Unlock()
			}

			// Then start downloading the stateTrie over the network.
			cl := NewClient(sb.SkipChainID(), *roster)
			var db *bbolt.DB
			var bucketName []byte
			var nonce uint64
			for {
				// Note: we trust the chain therefore even if the reply is corrupted,
				// it will be detected by difference in the root hash
				resp, err := cl.DownloadState(sb.SkipChainID(), nonce, catchupFetchDBEntries)
				if err != nil {
					return errors.New("cannot download trie: " + err.Error())
				}
				if db == nil {
					db, bucketName = s.GetAdditionalBucket([]byte(idStr))
					nonce = resp.Nonce
				}
				// And store all entries in our local database.
				err = db.Update(func(tx *bbolt.Tx) error {
					bucket := tx.Bucket(bucketName)
					for _, kv := range resp.KeyValues {
						err := bucket.Put(kv.Key, kv.Value)
						if err != nil {
							return err
						}
					}
					return nil
				})
				if err != nil {
					log.Fatal("Couldn't store entries:", err)
				}
				if len(resp.KeyValues) < catchupFetchDBEntries {
					break
				}
			}

			// Check the new trie is correct
			st, err := loadStateTrie(db, bucketName)
			if err != nil {
				return errors.New("couldn't load state trie: " + err.Error())
			}
			if sb.Index != st.GetIndex() {
				log.Lvl2("Downloading corresponding block")
				skCl := skipchain.NewClient()
				// TODO: add a client API to fetch a specific block and its proof
				search, err := skCl.GetSingleBlockByIndex(roster, sb.SkipChainID(), st.GetIndex())
				if err != nil {
					return errors.New("couldn't get correct block for verification: " + err.Error())
				}
				sb = search.SkipBlock
			}
			var header DataHeader
			err = protobuf.Decode(sb.Data, &header)
			if err != nil {
				return errors.New("couldn't unmarshal header: " + err.Error())
			}
			if !bytes.Equal(st.GetRoot(), header.TrieRoot) {
				return errors.New("got wrong database, merkle roots don't work out")
			}

			// Finally initialize the stateTrie using the new database.
			s.stateTriesLock.Lock()
			s.stateTries[idStr] = st
			s.stateTriesLock.Unlock()
			log.Lvlf1("%s: successfully downloaded database for chain %s", s.ServerIdentity(),
				idStr)
			return nil
		}()
		if err == nil {
			return nil
		}
		log.Errorf("Couldn't load database from %s - got error %s", roster.List[0], err)
	}
	return errors.New("none of the non-leader and non-subleader nodes were able to give us a copy of the state")
}

// catchupAll calls catchup for every byzcoin instance stored in this system.
func (s *Service) catchupAll() error {
	s.closedMutex.Lock()
	if s.closed {
		s.closedMutex.Unlock()
		return errors.New("cannot sync all while closing")
	}
	s.working.Add(1)
	defer s.working.Done()
	s.closedMutex.Unlock()
	gas := &skipchain.GetAllSkipChainIDs{}
	gasr, err := s.skService().GetAllSkipChainIDs(gas)
	if err != nil {
		return err
	}

	for _, scID := range gasr.IDs {
		sb, err := s.db().GetLatestByID(scID)
		if err != nil {
			return err
		}

		s.updateTrieLock.Lock()
		s.catchingUp = true
		s.updateTrieLock.Unlock()
		s.catchUp(sb)
	}
	return nil
}

// catchupFromID takes a roster and a skipchain-ID, and then searches to update this
// skipchain. This is useful in case there is no block stored yet in the system, but
// we get a roster, e.g., from getTxs.
// To prevent distributed denial-of-service, we first check that the skipchain is
// known and then we limit the number of catch up requests per skipchain by waiting
// for a minimal amount of time
func (s *Service) catchupFromID(r *onet.Roster, scID skipchain.SkipBlockID, sbID skipchain.SkipBlockID) error {
	// Catch up only friendly skipchains to avoid unnecessary requests
	if s.db().GetByID(scID) == nil {
		if _, found := s.unknownSkipchains[string(scID)]; found {
			log.Lvlf3("got asked for unknown skipchain: %x", scID)
			return nil
		}
		s.unknownSkipchains[string(scID)] = true
		return fmt.Errorf("got asked for an unknown skipchain: %x", scID)
	}

	// The size of the map is limited here by the number of known skipchains
	s.catchingUpHistoryLock.Lock()
	ts := s.catchingUpHistory[string(scID)]
	if ts.After(time.Now()) {
		s.catchingUpHistoryLock.Unlock()
		return errors.New("catch up request already processed recently")
	}

	s.catchingUpHistory[string(scID)] = time.Now().Add(catchupMinimumInterval)
	s.catchingUpHistoryLock.Unlock()

	log.Lvlf1("%s: catching up with chain %x", s.ServerIdentity(), scID)

	s.updateTrieLock.Lock()
	if s.catchingUp {
		s.updateTrieLock.Unlock()
		return errors.New("already catching up")
	}
	s.catchingUp = true
	s.updateTrieLock.Unlock()

	cl := skipchain.NewClient()
	sb, err := cl.GetSingleBlock(r, sbID)
	if err != nil {
		return err
	}

	// catch up the intermediate missing blocks
	s.catchUp(sb)
	return nil
}

// catchUp takes a skipblock as reference for the roster, the current index,
// and the skipchainID to download either new blocks if it's less than
// `catchupDownloadAll` behind, or calls downloadDB to start the download of
// the full DB over the network.
func (s *Service) catchUp(sb *skipchain.SkipBlock) {
	defer func() {
		s.updateTrieLock.Lock()
		s.catchingUp = false
		s.updateTrieLock.Unlock()
	}()

	log.Lvlf2("%v Catching up %x / %d", s.ServerIdentity(), sb.SkipChainID(), sb.Index)

	// Load the trie.
	download := false
	st, err := s.getStateTrie(sb.SkipChainID())
	if err != nil {
		log.Warn(s.ServerIdentity(), "problem with trie:", err)
		download = true
	} else {
		download = sb.Index-st.GetIndex() > catchupDownloadAll
	}

	// Check if we are updating the right index.
	if download {
		log.Lvl2(s.ServerIdentity(), "Downloading whole DB for catching up")
		err := s.downloadDB(sb)
		if err != nil {
			log.Error("Error while downloading trie:", err)
		}

		// Note: in that case we don't get the previous blocks and therefore we can't
		// recreate the state changes. The storage will then be filled with new
		// incoming blocks
		return
	}

	// Get the latest block known and processed by the conode
	trieIndex := st.GetIndex()
	req, err := s.skService().GetSingleBlockByIndex(&skipchain.GetSingleBlockByIndex{
		Genesis: sb.SkipChainID(),
		Index:   trieIndex,
	})
	if err != nil {
		// because we rely on the trie index, this should never happen because we're only
		// asking locally to get the block associated with the index (thus processed already)
		log.Errorf("%v cannot find latest block to catch up", s.ServerIdentity())
		return
	}

	latest := req.SkipBlock

	// Fetch all missing blocks to fill the hole
	cl := skipchain.NewClient()
	for trieIndex < sb.Index {
		log.Lvlf1("%s: our index: %d - latest known index: %d", s.ServerIdentity(), trieIndex, sb.Index)
		updates, err := cl.GetUpdateChainLevel(sb.Roster, latest.Hash, 1, catchupFetchBlocks)
		if err != nil {
			log.Error("Couldn't update blocks: " + err.Error())
			return
		}

		// This will call updateTrieCallback with the next block to add
		_, err = s.db().StoreBlocks(updates)
		if err != nil {
			log.Error("Got an invalid, unlinkable block: " + err.Error())
			return
		}
		latest = updates[len(updates)-1]
		trieIndex = latest.Index
	}
	log.Lvlf2("%v Done catch up %x / %d", s.ServerIdentity(), sb.SkipChainID(), trieIndex)
}

// updateTrieCallback is registered in skipchain and is called after a
// skipblock is updated. When this function is called, it is not always after
// the addition of a new block, but an updates to forward links, for example.
// Hence, we need to figure out when a new block is added. This can be done by
// looking at the latest skipblock cache from Service.state.
func (s *Service) updateTrieCallback(sbID skipchain.SkipBlockID) error {
	s.updateTrieLock.Lock()
	defer s.updateTrieLock.Unlock()

	s.closedMutex.Lock()
	defer s.closedMutex.Unlock()
	if s.closed {
		return nil
	}

	defer log.Lvlf4("%s updated trie for %x", s.ServerIdentity(), sbID)

	// Verification it's really a skipchain for us.
	if !s.hasByzCoinVerification(sbID) {
		log.Lvl4("Not our chain...")
		return nil
	}
	sb := s.db().GetByID(sbID)
	if sb == nil {
		panic("This should never happen because the callback runs " +
			"only after the skipblock is stored. There is a " +
			"programmer error if you see this message.")
	}

	// Checks if the block has forward links, which means that it is not a
	// new block but either a forward link update or a skipchain propagation
	// meaning the last block will be called later.
	// In the case of a genesis block, we need to let it pass so we
	// learn about it because the callback won't be called after the
	// catch up
	if len(sb.ForwardLink) > 0 && !s.catchingUp && sb.Index != 0 {
		return nil
	}

	// Create the trie for the genesis block if it has not been
	// created yet.
	// We don't need to wrap the check and use another
	// lock because the callback is already locked and we only
	// create state trie here.
	if sb.Index == 0 && !s.hasStateTrie(sb.SkipChainID()) {
		var body DataBody
		err := protobuf.Decode(sb.Payload, &body)
		if err != nil {
			log.Error(s.ServerIdentity(), "could not unmarshal body for genesis block", err)
			return errors.New("couldn't unmarshal body for genesis block")
		}
		nonce, err := s.LoadNonceFromTxs(body.TxResults)
		if err != nil {
			return err
		}
		// We don't care about the state trie that is returned in this
		// function because we load the trie again in getStateTrie
		// right afterwards.
		_, err = s.createStateTrie(sb.SkipChainID(), nonce)
		if err != nil {
			return fmt.Errorf("could not create trie: %v", err)
		}
	}

	// Load the trie.
	st, err := s.getStateTrie(sb.SkipChainID())
	if err != nil {
		return fmt.Errorf("could not load trie: %v", err)
	}

	// Check if we are updating the right index.
	trieIndex := st.GetIndex()
	if sb.Index <= trieIndex {
		// This is because skipchains will inform us about new forwardLinks, but we
		// don't need to update the trie in that case.
		log.Lvlf4("%v updating trie for block %d refused, current trie block is %d", s.ServerIdentity(), sb.Index, trieIndex)
		return nil
	} else if sb.Index > trieIndex+1 {
		if s.catchingUp {
			log.Warn(s.ServerIdentity(), "Got new block while catching up - ignoring block for now")
			return nil
		}

		s.catchingUp = true
		go s.catchUp(sb)
		return nil
	}

	// Get the DataHeader and the DataBody of the block.
	var header DataHeader
	err = protobuf.Decode(sb.Data, &header)
	if err != nil {
		log.Error(s.ServerIdentity(), "could not unmarshal header", err)
		return errors.New("couldn't unmarshal header")
	}

	var body DataBody
	err = protobuf.Decode(sb.Payload, &body)
	if err != nil {
		log.Error(s.ServerIdentity(), "could not unmarshal body", err)
		return errors.New("couldn't unmarshal body")
	}

	log.Lvlf2("%s Updating transactions for %x on index %v", s.ServerIdentity(), sb.SkipChainID(), sb.Index)
	_, _, scs, _ := s.createStateChanges(st.MakeStagingStateTrie(), sb.SkipChainID(), body.TxResults, noTimeout)

	log.Lvlf3("%s Storing index %d with %d state changes %v", s.ServerIdentity(), sb.Index, len(scs), scs.ShortStrings())
	// Update our global state using all state changes.
	if err = st.VerifiedStoreAll(scs, sb.Index, header.TrieRoot); err != nil {
		return err
	}

	err = s.stateChangeStorage.append(scs, sb)
	if err != nil {
		panic("Couldn't append the state changes to the storage - this might " +
			"mean that the db is broken. Error: " + err.Error())
	}

	// Notify all waiting channels for processed ClientTransactions.
	for _, t := range body.TxResults {
		s.notifications.informWaitChannel(t.ClientTransaction.Instructions.Hash(), t.Accepted)
	}
	s.notifications.informBlock(sb.SkipChainID())

	// If we are adding a genesis block, then look into it for the darc ID
	// and add it to the darcToSc hash map.
	if sb.Index == 0 {
		// the information should already be in the trie
		d, err := s.LoadGenesisDarc(sb.SkipChainID())
		if err != nil {
			return err
		}
		s.darcToScMut.Lock()
		s.darcToSc[string(d.GetBaseID())] = sb.SkipChainID()
		s.darcToScMut.Unlock()
	}

	// Get the latest configuration of the global state, which includes the latest
	// ClientTransactions received.
	bcConfig, err := s.LoadConfig(sb.SkipChainID())
	if err != nil {
		panic("Couldn't get configuration of the block - this might " +
			"mean that the db is broken. Error: " + err.Error())
	}

	// Variables for easy understanding what's being tested. Node in this context
	// is this node.
	i, _ := bcConfig.Roster.Search(s.ServerIdentity().ID)
	nodeInNew := i >= 0
	nodeIsLeader := bcConfig.Roster.List[0].Equal(s.ServerIdentity())
	initialDur, err := s.computeInitialDuration(sb.Hash)
	if err != nil {
		return err
	}
	// Check if the polling needs to be updated.
	s.pollChanMut.Lock()
	scIDstr := string(sb.SkipChainID())
	if nodeIsLeader {
		if _, ok := s.pollChan[scIDstr]; !ok {
			log.Lvlf2("%s new leader started polling for %x", s.ServerIdentity(), sb.SkipChainID())
			s.pollChan[scIDstr] = s.startPolling(sb.SkipChainID())
		}
	} else {
		if c, ok := s.pollChan[scIDstr]; ok {
			log.Lvlf2("%s old leader stopped polling for %x", s.ServerIdentity(), sb.SkipChainID())
			close(c)
			delete(s.pollChan, scIDstr)
		}
	}
	s.pollChanMut.Unlock()

	// Check if viewchange needs to be started/stopped
	// Check whether the heartbeat monitor exists, if it doesn't we start a
	// new one
	interval, _, err := s.LoadBlockInfo(sb.SkipChainID())
	if err != nil {
		return err
	}
	if nodeInNew {
		// Update or start heartbeats
		if s.heartbeats.exists(string(sb.SkipChainID())) {
			log.Lvlf3("%s sending heartbeat monitor for %x with window %v", s.ServerIdentity(), sb.SkipChainID(), interval*rotationWindow)
			s.heartbeats.updateTimeout(string(sb.SkipChainID()), interval*rotationWindow)
		} else {
			log.Lvlf2("%s starting heartbeat monitor for %x with window %v", s.ServerIdentity(), sb.SkipChainID(), interval*rotationWindow)
			err = s.heartbeats.start(string(sb.SkipChainID()), interval*rotationWindow, s.heartbeatsTimeout)
			if err != nil {
				log.Errorf("%s heartbeat failed to start with error: %s", s.ServerIdentity(), err.Error())
			}
		}

		// If it is a view-change transaction, confirm it's done
		view := isViewChangeTx(body.TxResults)

		if s.viewChangeMan.started(sb.SkipChainID()) && view != nil {
			s.viewChangeMan.done(*view)
		} else {
			// clean previous states as a new block has been added in the mean time
			// making them thus invalid
			s.viewChangeMan.stop(sb.SkipChainID())

			// Start viewchange monitor that will fire if we don't get updates in time.
			log.Lvlf2("%s started viewchangeMonitor for %x", s.ServerIdentity(), sb.SkipChainID())
			s.viewChangeMan.add(s.sendViewChangeReq, s.sendNewView, s.isLeader, string(sb.SkipChainID()))
			s.viewChangeMan.start(s.ServerIdentity().ID, sb.SkipChainID(), initialDur, s.getFaultThreshold(sb.Hash))
		}
	} else {
		if s.heartbeats.exists(scIDstr) {
			log.Lvlf2("%s stopping heartbeat monitor for %x with window %v", s.ServerIdentity(), sb.SkipChainID(), interval*rotationWindow)
			s.heartbeats.stop(scIDstr)
		}
	}
	if !nodeInNew && s.viewChangeMan.started(sb.SkipChainID()) {
		log.Lvlf2("%s not in roster, but viewChangeMonitor started - stopping now for %x", s.ServerIdentity(), sb.SkipChainID())
		s.viewChangeMan.stop(sb.SkipChainID())
	}

	// At this point everything should be stored.
	s.streamingMan.notify(string(sb.SkipChainID()), sb)

	log.Lvlf4("%s updated trie for %x with root %x", s.ServerIdentity(), sb.SkipChainID(), st.GetRoot())
	return nil
}

func isViewChangeTx(txs TxResults) *viewchange.View {
	if len(txs) != 1 {
		// view-change block must only have one transaction
		return nil
	}
	if len(txs[0].ClientTransaction.Instructions) != 1 {
		// view-change transaction must have one instruction
		return nil
	}

	invoke := txs[0].ClientTransaction.Instructions[0].Invoke
	if invoke == nil {
		return nil
	}
	if invoke.Command != "view_change" {
		return nil
	}
	var req viewchange.NewViewReq
	if err := protobuf.Decode(invoke.Args.Search("newview"), &req); err != nil {
		log.Error("failed to decode new-view req")
		return nil
	}
	return req.GetView()
}

// GetReadOnlyStateTrie returns a read-only accessor to the trie for the given
// skipchain.
func (s *Service) GetReadOnlyStateTrie(scID skipchain.SkipBlockID) (ReadOnlyStateTrie, error) {
	return s.getStateTrie(scID)
}

func (s *Service) hasStateTrie(id skipchain.SkipBlockID) bool {
	s.stateTriesLock.Lock()
	defer s.stateTriesLock.Unlock()

	idStr := fmt.Sprintf("%x", id)
	_, ok := s.stateTries[idStr]

	return ok
}

func (s *Service) getStateTrie(id skipchain.SkipBlockID) (*stateTrie, error) {
	if len(id) == 0 {
		return nil, errors.New("no skipchain ID")
	}
	s.stateTriesLock.Lock()
	defer s.stateTriesLock.Unlock()
	idStr := fmt.Sprintf("%x", id)
	col := s.stateTries[idStr]
	if col == nil {
		db, name := s.GetAdditionalBucket([]byte(idStr))
		st, err := loadStateTrie(db, name)
		if err != nil {
			return nil, err
		}
		s.stateTries[idStr] = st
		return s.stateTries[idStr], nil
	}
	return col, nil
}

func (s *Service) createStateTrie(id skipchain.SkipBlockID, nonce []byte) (*stateTrie, error) {
	if len(id) == 0 {
		return nil, errors.New("no skipchain ID")
	}
	s.stateTriesLock.Lock()
	defer s.stateTriesLock.Unlock()
	idStr := fmt.Sprintf("%x", id)
	if s.stateTries[idStr] != nil {
		return nil, errors.New("state trie already exists")
	}
	db, name := s.GetAdditionalBucket([]byte(idStr))
	st, err := newStateTrie(db, name, nonce)
	if err != nil {
		return nil, err
	}
	s.stateTries[idStr] = st
	return s.stateTries[idStr], nil
}

// interface to skipchain.Service
func (s *Service) skService() *skipchain.Service {
	return s.Service(skipchain.ServiceName).(*skipchain.Service)
}

func (s *Service) isLeader(view viewchange.View) bool {
	if view.LeaderIndex < 0 {
		// no guaranties on the leader index value
		return false
	}

	sb := s.db().GetByID(view.ID)

	idx := view.LeaderIndex % len(sb.Roster.List)
	sid := sb.Roster.List[idx]
	return sid.ID.Equal(s.ServerIdentity().ID)
}

// gives us access to the skipchain's database, so we can get blocks by ID
func (s *Service) db() *skipchain.SkipBlockDB {
	return s.skService().GetDB()
}

// LoadConfig loads the configuration from a skipchain ID.
func (s *Service) LoadConfig(scID skipchain.SkipBlockID) (*ChainConfig, error) {
	st, err := s.GetReadOnlyStateTrie(scID)
	if err != nil {
		return nil, err
	}
	return LoadConfigFromTrie(st)
}

// LoadGenesisDarc loads the genesis darc of the given skipchain ID.
func (s *Service) LoadGenesisDarc(scID skipchain.SkipBlockID) (*darc.Darc, error) {
	st, err := s.GetReadOnlyStateTrie(scID)
	if err != nil {
		return nil, err
	}
	config, err := s.LoadConfig(scID)
	if err != nil {
		return nil, err
	}
	return getInstanceDarc(st, ConfigInstanceID, config.DarcContractIDs)
}

// LoadBlockInfo loads the block interval and the maximum size from the
// skipchain ID. If the config instance does not exist, it will return the
// default values without an error.
func (s *Service) LoadBlockInfo(scID skipchain.SkipBlockID) (time.Duration, int, error) {
	if scID == nil {
		return defaultInterval, defaultMaxBlockSize, nil
	}
	st, err := s.GetReadOnlyStateTrie(scID)
	if err != nil {
		return defaultInterval, defaultMaxBlockSize, nil
	}
	config, err := LoadConfigFromTrie(st)
	if err != nil {
		if err == errKeyNotSet {
			err = nil
		}
		return defaultInterval, defaultMaxBlockSize, err
	}
	return config.BlockInterval, config.MaxBlockSize, nil
}

func (s *Service) startPolling(scID skipchain.SkipBlockID) chan bool {
	pipeline := txPipeline{
		processor: &defaultTxProcessor{
			stopCollect: make(chan bool),
			scID:        scID,
			Service:     s,
		},
	}
	st, err := s.getStateTrie(scID)
	if err != nil {
		panic("the state trie must exist because we only start polling after creating/loading the skipchain")
	}
	initialState := txProcessorState{
		sst: st.MakeStagingStateTrie(),
	}

	stopChan := make(chan bool)
	go func() {
		s.pollChanWG.Add(1)
		defer s.pollChanWG.Done()

		s.closedMutex.Lock()
		if s.closed {
			s.closedMutex.Unlock()
			return
		}

		s.working.Add(1)
		defer s.working.Done()
		s.closedMutex.Unlock()

		pipeline.start(&initialState, stopChan)
	}()

	return stopChan
}

// We use the ByzCoin as a receiver (as is done in the identity service),
// so we can access e.g. the StateTrie of the service.
func (s *Service) verifySkipBlock(newID []byte, newSB *skipchain.SkipBlock) bool {
	start := time.Now()
	defer func() {
		log.Lvlf3("%s Verify done after %s", s.ServerIdentity(), time.Now().Sub(start))
	}()

	var header DataHeader
	err := protobuf.Decode(newSB.Data, &header)
	if err != nil {
		log.Error(s.ServerIdentity(), "verifySkipblock: couldn't unmarshal header")
		return false
	}

	// Check the contents of the DataHeader before proceeding.
	// We'll check the timestamp later, once we have the config loaded.
	err = func() error {
		if len(header.TrieRoot) != sha256.Size {
			return errors.New("trie root is wrong size")
		}
		if len(header.ClientTransactionHash) != sha256.Size {
			return errors.New("client transaction hash is wrong size")
		}
		if len(header.StateChangesHash) != sha256.Size {
			return errors.New("state changes hash is wrong size")
		}
		return nil
	}()

	if err != nil {
		log.Errorf("data header failed check: %v", err)
		return false
	}

	var body DataBody
	err = protobuf.Decode(newSB.Payload, &body)
	if err != nil {
		log.Error("verifySkipblock: couldn't unmarshal body")
		return false
	}

	if s.viewChangeMan.waiting(string(newSB.SkipChainID())) && isViewChangeTx(body.TxResults) == nil {
		log.Error(s.ServerIdentity(), "we are not accepting blocks when a view-change is in progress")
		return false
	}

	// Load/create a staging trie to add the state changes to it and
	// compute the Merkle root.
	var sst *StagingStateTrie
	if newSB.Index == 0 {
		nonce, err := s.LoadNonceFromTxs(body.TxResults)
		if err != nil {
			log.Error(s.ServerIdentity(), err)
			return false
		}
		sst, err = NewMemStagingStateTrie(nonce)
		if err != nil {
			log.Error(s.ServerIdentity(), err)
			return false
		}
	} else {
		st, err := s.getStateTrie(newSB.SkipChainID())
		if err != nil {
			log.Error(s.ServerIdentity(), err)
			return false
		}
		sst = st.MakeStagingStateTrie()
	}
	mtr, txOut, scs, _ := s.createStateChanges(sst, newSB.SkipChainID(), body.TxResults, noTimeout)

	// Check that the locally generated list of accepted/rejected txs match the list
	// the leader proposed.
	if len(txOut) != len(body.TxResults) {
		log.Lvl2(s.ServerIdentity(), "transaction list length mismatch after execution")
		return false
	}

	for i := range txOut {
		if txOut[i].Accepted != body.TxResults[i].Accepted {
			log.Lvl2(s.ServerIdentity(), "Client Transaction accept mistmatch on tx", i)
			return false
		}
	}

	// Check that the hashes in DataHeader are right.
	if bytes.Compare(header.ClientTransactionHash, txOut.Hash()) != 0 {
		log.Lvl2(s.ServerIdentity(), "Client Transaction Hash doesn't verify")
		return false
	}

	if bytes.Compare(header.TrieRoot, mtr) != 0 {
		log.Lvl2(s.ServerIdentity(), "Trie root doesn't verify")
		return false
	}
	if bytes.Compare(header.StateChangesHash, scs.Hash()) != 0 {
		log.Lvl2(s.ServerIdentity(), "State Changes hash doesn't verify")
		return false
	}

	// Compute the new state and check whether the roster in newSB matches
	// the config.
	if err := sst.StoreAll(scs); err != nil {
		log.Error(s.ServerIdentity(), err)
		return false
	}

	config, err := LoadConfigFromTrie(sst)
	if err != nil {
		log.Error(s.ServerIdentity(), err)
		return false
	}
	if newSB.Index > 0 {
		if err := config.checkNewRoster(*newSB.Roster); err != nil {
			log.Error("Didn't accept the new roster:", err)
			return false
		}
	}

	window := 4 * config.BlockInterval
	if window < minTimestampWindow {
		window = minTimestampWindow
	}

	now := time.Now()
	t1 := now.Add(-window)
	t2 := now.Add(window)
	ts := time.Unix(0, header.Timestamp)
	if ts.Before(t1) || ts.After(t2) {
		log.Errorf("timestamp %v is outside the acceptable range %v to %v", ts, t1, t2)
		return false
	}

	log.Lvl4(s.ServerIdentity(), "verification completed")
	return true
}

func txSize(txr ...TxResult) (out int) {
	// It's too bad to have to marshal this and throw it away just to know
	// how big it would be. Protobuf should support finding the length without
	// copying the data.
	for _, x := range txr {
		buf, err := protobuf.Encode(&x)
		if err != nil {
			// It's fairly inconceivable that we're going to be getting
			// error from this Encode() but return a big number in case,
			// so that the caller will reject whatever this bad input is.
			return math.MaxInt32
		}
		out += len(buf)
	}
	return
}

// createStateChanges goes through all the proposed transactions one by one,
// creating the appropriate StateChanges, by sorting out which transactions can
// be run, which fail, and which cannot be attempted yet (due to timeout).
//
// If timeout is not 0, createStateChanges will stop running instructions after
// that long, in order for the caller to determine how many instructions fit in
// a block interval.
//
// State caching is implemented here, which is critical to performance, because
// on the leader it reduces the number of contract executions by 1/3 and on
// followers by 1/2.
func (s *Service) createStateChanges(sst *StagingStateTrie, scID skipchain.SkipBlockID, txIn TxResults, timeout time.Duration) (merkleRoot []byte, txOut TxResults, states StateChanges, sstTemp *StagingStateTrie) {
	// If what we want is in the cache, then take it from there. Otherwise
	// ignore the error and compute the state changes.
	var err error
	merkleRoot, txOut, states, err = s.stateChangeCache.get(scID, txIn.Hash())
	if err == nil {
		log.Lvlf3("%s: loaded state changes %x from cache", s.ServerIdentity(), scID)
		return
	}
	log.Lvl3(s.ServerIdentity(), "state changes from cache: MISS")
	err = nil

	var maxsz, blocksz int
	_, maxsz, err = s.LoadBlockInfo(scID)
	// no error or expected "no trie" err, so keep going with the
	// maxsz we got.
	err = nil

	deadline := time.Now().Add(timeout)

	sstTemp = sst.Clone()

	for _, tx := range txIn {
		txsz := txSize(tx)

		var sstTempC *StagingStateTrie
		var statesTemp StateChanges
		statesTemp, sstTempC, err = s.ProcessOneTx(sstTemp, tx.ClientTransaction)
		if err != nil {
			tx.Accepted = false
			txOut = append(txOut, tx)
			log.Error(err)
		} else {
			// We would like to be able to check if this txn is so big it could never fit into a block,
			// and if so, drop it. But we can't with the current API of createStateChanges.
			// For now, the only thing we can do is accept or refuse them, but they will go into a block
			// one way or the other.
			// TODO: In issue #1409, we will refactor things such that we can drop transactions in here.
			//if txsz > maxsz {
			//	log.Errorf("%s transaction size %v is bigger than one block (%v), dropping it.", s.ServerIdentity(), txsz, maxsz)
			//	continue clientTransactions
			//}

			// Planning mode:
			//
			// Timeout is used when the leader calls createStateChanges as
			// part of planning which transactions fit into one block.
			if timeout != noTimeout {
				if time.Now().After(deadline) {
					log.Warnf("%s ran out of time after %v", s.ServerIdentity(), timeout)
					return
				}

				// If the last txn would have made the state changes too big, return
				// just like we do for a timeout. The caller will make a block with
				// what's in txOut.
				if blocksz+txsz > maxsz {
					log.Lvlf3("stopping block creation when %v > %v, with len(txOut) of %v", blocksz+txsz, maxsz, len(txOut))
					return
				}
			}

			tx.Accepted = true
			sstTemp = sstTempC
			blocksz += txsz
			states = append(states, statesTemp...)
			txOut = append(txOut, tx)
		}
	}

	// Store the result in the cache before returning.
	merkleRoot = sstTemp.GetRoot()
	if len(states) != 0 && len(txOut) != 0 {
		s.stateChangeCache.update(scID, txOut.Hash(), merkleRoot, txOut, states)
	}
	return
}

// ProcessOneTx takes one transaction and creates a set of StateChanges. It also returns the temporary StateTrie
// with the StateChanges applied.
func (s *Service) ProcessOneTx(sst *StagingStateTrie, tx ClientTransaction) (StateChanges, *StagingStateTrie, error) {
	// Make a new trie for each instruction. If the instruction is
	// sucessfully implemented and changes applied, then keep it
	// otherwise dump it.
	sst = sst.Clone()
	h := tx.Instructions.Hash()
	var statesTemp StateChanges
	var cin []Coin
	for _, instr := range tx.Instructions {
		scs, cout, err := s.executeInstruction(sst, cin, instr, h)
		if err != nil {
			_, _, cid, _, err2 := sst.GetValues(instr.InstanceID.Slice())
			if err2 != nil {
				err = fmt.Errorf("%s - while getting value: %s", err, err2)
			}
			return nil, nil, fmt.Errorf("%s Contract %s got Instruction %s and returned error: %s", s.ServerIdentity(), cid, instr, err)
		}
		var counterScs StateChanges
		if counterScs, err = incrementSignerCounters(sst, instr.SignerIdentities); err != nil {
			return nil, nil, fmt.Errorf("%s failed to update signature counters: %s", s.ServerIdentity(), err)
		}

		// Verify the validity of the state-changes:
		//  - refuse to update non-existing instances
		//  - refuse to create existing instances
		//  - refuse to delete non-existing instances
		for _, sc := range scs {
			var reason string
			switch sc.StateAction {
			case Create:
				if v, err := sst.Get(sc.InstanceID); err != nil || v != nil {
					reason = "tried to create existing instanceID"
				}
			case Update:
				if v, err := sst.Get(sc.InstanceID); err != nil || v == nil {
					reason = "tried to update non-existing instanceID"
				}
			case Remove:
				if v, err := sst.Get(sc.InstanceID); err != nil || v == nil {
					reason = "tried to remove non-existing instanceID"
				}
			}
			if reason != "" {
				_, _, contractID, _, err := sst.GetValues(instr.InstanceID.Slice())
				if err != nil {
					return nil, nil, fmt.Errorf("%s couldn't get contractID from instruction %+v", s.ServerIdentity(), instr)
				}
				return nil, nil, fmt.Errorf("%s: contract %s %s", s.ServerIdentity(), contractID, reason)
			}
			log.Lvlf2("StateChange %s for id %x - contract: %s", sc.StateAction, sc.InstanceID, sc.ContractID)
			err = sst.StoreAll(StateChanges{sc})
			if err != nil {
				return nil, nil, fmt.Errorf("%s StoreAll failed: %s", s.ServerIdentity(), err)
			}
		}
		if err = sst.StoreAll(counterScs); err != nil {
			return nil, nil, fmt.Errorf("%s StoreAll failed to add counter changes: %s", s.ServerIdentity(), err)
		}
		statesTemp = append(statesTemp, scs...)
		statesTemp = append(statesTemp, counterScs...)
		cin = cout
	}
	if len(cin) != 0 {
		log.Warn(s.ServerIdentity(), "Leftover coins detected, discarding.")
	}
	return statesTemp, sst, nil
}

// GetContractConstructor gets the contract constructor of the contract
// contractName.
func (s *Service) GetContractConstructor(contractName string) (ContractFn, bool) {
	fn, exists := s.contracts[contractName]
	return fn, exists
}

func (s *Service) executeInstruction(st ReadOnlyStateTrie, cin []Coin, instr Instruction, ctxHash []byte) (scs StateChanges, cout []Coin, err error) {
	defer func() {
		if re := recover(); re != nil {
			err = fmt.Errorf("%s", re)
		}
	}()

	contents, _, contractID, _, err := st.GetValues(instr.InstanceID.Slice())
	if err != errKeyNotSet && err != nil {
		err = errors.New("Couldn't get contract type of instruction: " + err.Error())
		return
	}

	contractFactory, exists := s.contracts[contractID]
	if !exists && ConfigInstanceID.Equal(instr.InstanceID) {
		// Special case: first time call to genesis-configuration must return
		// correct contract type.
		contractFactory, exists = s.contracts[ContractConfigID]
	}

	// If the leader does not have a verifier for this contract, it drops the
	// transaction.
	if !exists {
		err = fmt.Errorf("leader is dropping instruction of unknown contract \"%s\" on instance \"%x\"", contractID, instr.InstanceID.Slice())
		return
	}
	// Now we call the contract function with the data of the key.
	log.Lvlf3("calling contract '%s'", contractID)

	c, err := contractFactory(contents)
	if err != nil {
		return nil, nil, err
	}
	if c == nil {
		return nil, nil, errors.New("contract factory returned nil contract instance")
	}

	err = c.VerifyInstruction(st, instr, ctxHash)
	if err != nil {
		return nil, nil, fmt.Errorf("instruction verification failed: %v", err)
	}

	switch instr.GetType() {
	case SpawnType:
		scs, cout, err = c.Spawn(st, instr, cin)
	case InvokeType:
		scs, cout, err = c.Invoke(st, instr, cin)
	case DeleteType:
		scs, cout, err = c.Delete(st, instr, cin)
	default:
		return nil, nil, errors.New("unexpected contract type")
	}

	// As the InstanceID of each sc is not necessarily the same as the
	// instruction, we need to get the version from the trie
	vv := make(map[string]uint64)
	for i, sc := range scs {
		ver, ok := vv[hex.EncodeToString(sc.InstanceID)]
		if !ok {
			_, ver, _, _, err = st.GetValues(sc.InstanceID)
		}

		// this is done at this scope because we must increase
		// the version only when it's not the first one
		if err == errKeyNotSet {
			ver = 0
			err = nil
		} else if err != nil {
			return
		} else {
			ver++
		}

		scs[i].Version = ver
		vv[hex.EncodeToString(sc.InstanceID)] = ver
	}

	return
}

func (s *Service) getLeader(scID skipchain.SkipBlockID) (*network.ServerIdentity, error) {
	scConfig, err := s.LoadConfig(scID)
	if err != nil {
		return nil, err
	}
	if len(scConfig.Roster.List) < 1 {
		return nil, errors.New("roster is empty")
	}
	return scConfig.Roster.List[0], nil
}

// getTxs is primarily used as a callback in the CollectTx protocol to retrieve
// a set of pending transactions. However, it is a very useful way to piggy
// back additional functionalities that need to be executed at every interval,
// such as updating the heartbeat monitor and synchronising the state.
func (s *Service) getTxs(leader *network.ServerIdentity, roster *onet.Roster, scID skipchain.SkipBlockID, latestID skipchain.SkipBlockID) []ClientTransaction {
	s.closedMutex.Lock()
	if s.closed {
		s.closedMutex.Unlock()
		return nil
	}
	s.working.Add(1)
	s.closedMutex.Unlock()
	defer s.working.Done()

	// First we check if we are up-to-date with this chain (and that we know it)
	latestSB, doCatchUp := s.skService().WaitBlock(scID, latestID)
	if latestSB == nil {
		if doCatchUp {
			// The function will prevent multiple request to catch up so we can securely call it here
			err := s.catchupFromID(roster, scID, latestID)
			if err != nil {
				log.Error(s.ServerIdentity(), err)
			}
		}

		// Give up the current request and wait for the next one, and keep skipping requests
		// until the catching up is done
		return []ClientTransaction{}
	}

	// Then we make sure who's the leader
	actualLeader, err := s.getLeader(scID)
	if err != nil {
		log.Lvlf2("%s: could not find a leader on %x with error: %s", s.ServerIdentity(), scID, err)
		return []ClientTransaction{}
	}
	if !leader.Equal(actualLeader) {
		log.Warn(s.ServerIdentity(), "getTxs came from a wrong leader", leader,
			"should be", actualLeader)
		return []ClientTransaction{}
	}

	s.heartbeats.beat(string(scID))

	return s.txBuffer.take(string(scID))
}

// LoadNonceFromTxs gets the nonce from a TxResults. This only works for the genesis-block.
func (s *Service) LoadNonceFromTxs(txs TxResults) ([]byte, error) {
	if len(txs) == 0 {
		return nil, errors.New("no transactions")
	}
	instrs := txs[0].ClientTransaction.Instructions
	if len(instrs) != 1 {
		return nil, fmt.Errorf("expected 1 instruction, got %v", len(instrs))
	}
	if instrs[0].Spawn == nil {
		return nil, errors.New("first instruction is not a Spawn")
	}
	nonce := instrs[0].Spawn.Args.Search("trie_nonce")
	if len(nonce) == 0 {
		return nil, errors.New("nonce is empty")
	}
	return nonce, nil
}

// TestClose closes the go-routines that are polling for transactions. It is
// exported because we need it in tests, it should not be used in non-test code
// outside of this package.
func (s *Service) TestClose() {
	s.closedMutex.Lock()
	if !s.closed {
		s.closed = true
		s.closedMutex.Unlock()
		s.cleanupGoroutines()
		s.working.Wait()
	} else {
		s.closedMutex.Unlock()
	}
}

func (s *Service) cleanupGoroutines() {
	log.Lvl1(s.ServerIdentity(), "closing go-routines")
	s.heartbeats.closeAll()
	s.closeLeaderMonitorChan <- true
	s.viewChangeMan.closeAll()

	s.pollChanMut.Lock()
	for k, c := range s.pollChan {
		close(c)
		delete(s.pollChan, k)
	}
	s.pollChanMut.Unlock()
	s.pollChanWG.Wait()
}

func (s *Service) monitorLeaderFailure() {
	s.closedMutex.Lock()
	if s.closed {
		s.closedMutex.Unlock()
		return
	}
	s.working.Add(1)
	defer s.working.Done()
	s.closedMutex.Unlock()

	go func() {
		for {
			select {
			case key := <-s.heartbeatsTimeout:
				log.Lvlf3("%s: missed heartbeat for %x", s.ServerIdentity(), key)
				gen := []byte(key)

				genBlock := s.db().GetByID(gen)
				if genBlock == nil {
					// This should not happen as the heartbeats are started after
					// a new skipchain is created or when the conode starts ..
					log.Error("heartbeat monitors are started after " +
						"the creation of the genesis block, " +
						"so the block should always exist")
					// .. but just in case we stop the heartbeat
					s.heartbeats.stop(key)
				}

				latest, err := s.db().GetLatestByID(gen)
				if err != nil {
					log.Errorf("failed to get the latest block: %v", err)
				} else {
					// Send only if the latest block is consistent as it wouldn't
					// anyway if we're out of sync with the chain
					req := viewchange.InitReq{
						SignerID: s.ServerIdentity().ID,
						View: viewchange.View{
							ID:          latest.Hash,
							Gen:         gen,
							LeaderIndex: 1,
						},
					}
					s.viewChangeMan.addReq(req)
				}
			case <-s.closeLeaderMonitorChan:
				log.Lvl2(s.ServerIdentity(), "closing heartbeat timeout monitor")
				return
			}
		}
	}()
}

// registerContract stores the contract in a map and will
// call it whenever a contract needs to be done.
func (s *Service) registerContract(contractID string, c ContractFn) error {
	s.contracts[contractID] = c
	return nil
}

// startAllChains loads the configuration, updates the data in the service if
// it finds a valid config-file and synchronises skipblocks if it can contact
// other nodes.
func (s *Service) startAllChains() error {
	s.closedMutex.Lock()
	defer s.closedMutex.Unlock()
	if !s.closed {
		return errors.New("can only call startAllChains if the service has been closed before")
	}
	s.SetPropagationTimeout(120 * time.Second)
	msg, err := s.Load(storageID)
	if err != nil {
		return err
	}
	if msg != nil {
		var ok bool
		s.storage, ok = msg.(*bcStorage)
		if !ok {
			return errors.New("data of wrong type")
		}
	}
	s.stateTries = make(map[string]*stateTrie)
	s.notifications = bcNotifications{
		waitChannels: make(map[string]chan bool),
	}
	s.closed = false

	// Recreate the polling channles.
	s.pollChanMut.Lock()
	s.pollChan = make(map[string]chan bool)
	s.pollChanMut.Unlock()

	gas := &skipchain.GetAllSkipChainIDs{}
	gasr, err := s.skService().GetAllSkipChainIDs(gas)
	if err != nil {
		return err
	}

	for _, gen := range gasr.IDs {
		if !s.hasByzCoinVerification(gen) {
			continue
		}

		interval, _, err := s.LoadBlockInfo(gen)
		if err != nil {
			log.Errorf("%s Ignoring chain %x because we can't load blockInterval: %s", s.ServerIdentity(), gen, err)
			continue
		}

		if s.db().GetByID(gen) == nil {
			log.Errorf("%s ignoring chain with missing genesis-block %x", s.ServerIdentity(), gen)
			continue
		}
		latest, err := s.db().GetLatestByID(gen)
		if err != nil {
			log.Errorf("%s ignoring chain %x where latest block cannot be found: %s",
				s.ServerIdentity(), gen, err)
		}

		leader, err := s.getLeader(gen)
		if err != nil {
			log.Error("getLeader should not return an error if roster is initialised:", err)
			continue
		}
		if leader.Equal(s.ServerIdentity()) {
			log.Lvlf2("%s: Starting as a leader for chain %x", s.ServerIdentity(), latest.SkipChainID())
			s.pollChanMut.Lock()
			s.pollChan[string(gen)] = s.startPolling(gen)
			s.pollChanMut.Unlock()
		}

		// populate the darcID to skipchainID mapping
		d, err := s.LoadGenesisDarc(gen)
		if err != nil {
			return err
		}
		s.darcToScMut.Lock()
		s.darcToSc[string(d.GetBaseID())] = gen
		s.darcToScMut.Unlock()

		// start the heartbeat
		if s.heartbeats.exists(string(gen)) {
			return errors.New("we are just starting the service, there should be no existing heartbeat monitors")
		}
		log.Lvlf2("%s started heartbeat monitor for block %d of %x", s.ServerIdentity(), latest.Index, gen)
		s.heartbeats.start(string(gen), interval*rotationWindow, s.heartbeatsTimeout)

		// initiate the view-change manager
		initialDur, err := s.computeInitialDuration(gen)
		if err != nil {
			return err
		}
		s.viewChangeMan.add(s.sendViewChangeReq, s.sendNewView, s.isLeader, string(gen))
		s.viewChangeMan.start(s.ServerIdentity().ID, gen, initialDur, s.getFaultThreshold(gen))
		// TODO fault threshold might change
	}

	// Running catchupAll in background so it doesn't stop the other
	// services from starting.
	go func() {
		s.monitorLeaderFailure()
		err := s.catchupAll()
		if err != nil {
			log.Error(s.ServerIdentity(), "couldn't sync:", err)
		}
	}()

	return nil
}

// checks that a given chain has a verifier we recognize
func (s *Service) hasByzCoinVerification(gen skipchain.SkipBlockID) bool {
	sb := s.db().GetByID(gen)
	if sb == nil {
		// Not finding this ID should not happen, but
		// if it does, just say "not ours".
		return false
	}
	for _, x := range sb.VerifierIDs {
		if x.Equal(Verify) {
			return true
		}
	}
	return false
}

// saves this service's config information
func (s *Service) save() {
	s.storage.Lock()
	defer s.storage.Unlock()
	err := s.Save(storageID, s.storage)
	if err != nil {
		log.Error(s.ServerIdentity(), "Couldn't save file:", err)
	}
}

// getBlockTx fetches the block with the given id and then decodes the payload
// to return the list of transactions
func (s *Service) getBlockTx(sid skipchain.SkipBlockID) (TxResults, *skipchain.SkipBlock, error) {
	sb, err := s.skService().GetSingleBlock(&skipchain.GetSingleBlock{ID: sid})
	if err != nil {
		return nil, nil, err
	}

	var body DataBody
	err = protobuf.Decode(sb.Payload, &body)
	if err != nil {
		return nil, nil, err
	}

	return body.TxResults, sb, nil
}

var existingDB = regexp.MustCompile(`^ByzCoin_[0-9a-f]+$`)

// newService receives the context that holds information about the node it's
// running on. Saving and loading can be done using the context. The data will
// be stored in memory for tests and simulations, and on disk for real
// deployments.
func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor:       onet.NewServiceProcessor(c),
		contracts:              make(map[string]ContractFn),
		txBuffer:               newTxBuffer(),
		storage:                &bcStorage{},
		darcToSc:               make(map[string]skipchain.SkipBlockID),
		stateChangeCache:       newStateChangeCache(),
		stateChangeStorage:     newStateChangeStorage(c),
		heartbeatsTimeout:      make(chan string, 1),
		closeLeaderMonitorChan: make(chan bool, 1),
		heartbeats:             newHeartbeats(),
		viewChangeMan:          newViewChangeManager(),
		streamingMan:           streamingManager{},
		closed:                 true,
		catchingUpHistory:      make(map[string]time.Time),
		unknownSkipchains:      make(map[string]bool),
	}

	err := s.RegisterHandlers(
		s.CreateGenesisBlock,
		s.AddTransaction,
		s.GetProof,
		s.CheckAuthorization,
		s.GetSignerCounters,
		s.DownloadState,
		s.GetInstanceVersion,
		s.GetLastInstanceVersion,
		s.GetAllInstanceVersion,
		s.CheckStateChangeValidity,
		s.Debug,
		s.DebugRemove)
	if err != nil {
		return nil, err
	}

	if err := s.RegisterStreamingHandlers(s.StreamTransactions); err != nil {
		return nil, err
	}
	s.RegisterProcessorFunc(viewChangeMsgID, s.handleViewChangeReq)

	err = s.registerContract(ContractConfigID, contractConfigFromBytes)
	if err != nil {
		return nil, err
	}
	err = s.registerContract(ContractDarcID, s.contractSecureDarcFromBytes)
	if err != nil {
		return nil, err
	}

	skipchain.RegisterVerification(c, Verify, s.verifySkipBlock)
	if _, err := s.ProtocolRegister(collectTxProtocol, NewCollectTxProtocol(s.getTxs)); err != nil {
		return nil, err
	}
	s.skService().RegisterStoreSkipblockCallback(s.updateTrieCallback)

	// Register the view-change cosi protocols.
	_, err = s.ProtocolRegister(viewChangeSubFtCosi, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return protocol.NewSubBlsCosi(n, s.verifyViewChange, pairingSuite)
	})
	if err != nil {
		return nil, err
	}
	_, err = s.ProtocolRegister(viewChangeFtCosi, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return protocol.NewBlsCosi(n, s.verifyViewChange, viewChangeSubFtCosi, pairingSuite)
	})
	if err != nil {
		return nil, err
	}

	ver, err := s.LoadVersion()
	if err != nil {
		return nil, err
	}
	switch ver {
	case 0:
		// Version 0 means it hasn't been set yet. If there are any ByzCoin_[0-9af]+
		// buckets, then they must be old format.
		db, _ := s.GetAdditionalBucket([]byte("check-db-version"))

		// Look for a bucket that has a byzcoin database in it.
		err := db.View(func(tx *bbolt.Tx) error {
			c := tx.Cursor()
			for k, _ := c.First(); k != nil; k, _ = c.Next() {
				log.Lvlf4("looking for old ByzCoin data in bucket %v", string(k))
				if existingDB.Match(k) {
					return fmt.Errorf("database format is too old; rm '%v' to lose all data and make a new database", db.Path())
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}

		// Otherwise set the db version to 1, because we've confirmed there are
		// no old-style ones.
		err = s.SaveVersion(1)
		if err != nil {
			return nil, err
		}
	case 1:
		// This is where any necessary future migration fron version 1 -> 2 will happen.
	default:
		return nil, fmt.Errorf("unknown db version number %v", ver)
	}

	// initialize the stats of the storage
	s.stateChangeStorage.calculateSize()

	if err := s.startAllChains(); err != nil {
		return nil, err
	}
	return s, nil
}
