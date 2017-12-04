package stores

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/go-nats-streaming/pb"
	"golang.org/x/crypto/chacha20poly1305"
)

// CryptStore specific errors
var (
	ErrCryptoStoreRequiresKey = errors.New("crypto store requires a key")
)

const (
	// CryptoStoreEnvKeyName is the environment variable name
	// that the CryptoStore looks up if no key is passed as
	// a parameter.
	CryptoStoreEnvKeyName = "NATS_STREAMING_ENCRYPTION_KEY"

	// Seal() should be called at most 2^32 with the same nonce.
	// Use this as the max threshold, after which the nonce is
	// renewed.
	csDefaultMaxEncryptCallsPerNonce = int64(0x100000000) - 10000
)

var (
	// Use variable so we can change it for tests.
	csMaxEncryptCallsPerNonce = csDefaultMaxEncryptCallsPerNonce
)

// CryptoStore is a store wrapping a store implementation
// and adds encryption support.
type CryptoStore struct {
	// These are used with atomic operations. Keep them 64-bit aligned.
	inEncrypt int64
	encrypted int64

	sync.Mutex
	Store

	gcm            cipher.AEAD
	nonce          []byte
	nonceSize      int
	cryptoOverhead int
}

// CryptoMsgStore is a store wrappeing a SubStore implementation
// and adds encryption support.
type CryptoMsgStore struct {
	MsgStore

	cs *CryptoStore
}

// NewCryptoStore returns a CryptoStore instance with
// given underlying store.
func NewCryptoStore(s Store, key string) (*CryptoStore, error) {
	if key == "" {
		// Check env variable.
		key = os.Getenv(CryptoStoreEnvKeyName)
		if key == "" {
			return nil, ErrCryptoStoreRequiresKey
		}
	}

	cs := &CryptoStore{Store: s}

	h := sha256.New()
	h.Write([]byte(key))
	keyHash := h.Sum(nil)
	gcm, err := chacha20poly1305.New(keyHash)
	if err != nil {
		return nil, err
	}
	cs.gcm = gcm
	cs.cryptoOverhead = gcm.Overhead()
	cs.nonceSize = gcm.NonceSize()
	if err := cs.generateNewNonce(); err != nil {
		return nil, err
	}
	return cs, nil
}

func (cs *CryptoStore) generateNewNonce() error {
	nonce := make([]byte, cs.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	cs.nonce = nonce
	atomic.StoreInt64(&cs.encrypted, 0)
	return nil
}

// Recover implements the Store interface
func (cs *CryptoStore) Recover() (*RecoveredState, error) {
	cs.Lock()
	defer cs.Unlock()
	rs, err := cs.Store.Recover()
	if rs == nil || err != nil {
		return rs, err
	}
	for _, rc := range rs.Channels {
		rc.Channel.Msgs = &CryptoMsgStore{MsgStore: rc.Channel.Msgs, cs: cs}
	}
	return rs, nil
}

// CreateChannel implements the Store interface
func (cs *CryptoStore) CreateChannel(channel string) (*Channel, error) {
	cs.Lock()
	defer cs.Unlock()

	c, err := cs.Store.CreateChannel(channel)
	if err != nil {
		return nil, err
	}
	c.Msgs = &CryptoMsgStore{MsgStore: c.Msgs, cs: cs}
	return c, nil
}

func (cs *CryptoStore) encrypt(data []byte) ([]byte, error) {
CHECK_ENCRYPTED_COUNT:
	atomic.AddInt64(&cs.inEncrypt, 1)
	if count := atomic.AddInt64(&cs.encrypted, 1); count >= csMaxEncryptCallsPerNonce {
		atomic.AddInt64(&cs.inEncrypt, -1)
		cs.Lock()
		if count == csMaxEncryptCallsPerNonce {
			for atomic.LoadInt64(&cs.inEncrypt) > 0 {
				time.Sleep(15 * time.Millisecond)
			}
			if err := cs.generateNewNonce(); err != nil {
				cs.Unlock()
				return nil, err
			}
			cs.Unlock()
			atomic.AddInt64(&cs.inEncrypt, 1)
		} else {
			cs.Unlock()
			goto CHECK_ENCRYPTED_COUNT
		}
	}
	buf := make([]byte, cs.nonceSize+cs.cryptoOverhead+len(data))
	copy(buf, cs.nonce)
	copy(buf[cs.nonceSize:], data)
	dst := buf[cs.nonceSize : cs.nonceSize+len(data)]
	ret := cs.gcm.Seal(dst[:0], cs.nonce, dst, nil)
	atomic.AddInt64(&cs.inEncrypt, -1)
	return buf[:cs.nonceSize+len(ret)], nil
}

func (cs *CryptoStore) decrypt(data []byte) ([]byte, error) {
	return cs.gcm.Open(nil, data[:cs.nonceSize], data[cs.nonceSize:], nil)
}

// Store implements the MsgStore interface
func (cms *CryptoMsgStore) Store(data []byte) (uint64, error) {
	if len(data) == 0 {
		return cms.MsgStore.Store(data)
	}
	ed, err := cms.cs.encrypt(data)
	if err != nil {
		return 0, err
	}
	return cms.MsgStore.Store(ed)
}

func (cms *CryptoMsgStore) decryptedMsg(m *pb.MsgProto) (*pb.MsgProto, error) {
	dd, err := cms.cs.decrypt(m.Data)
	if err != nil {
		return nil, err
	}
	retMsg := *m
	retMsg.Data = dd
	return &retMsg, nil
}

// Lookup implements the MsgStore interface
func (cms *CryptoMsgStore) Lookup(seq uint64) (*pb.MsgProto, error) {
	m, err := cms.MsgStore.Lookup(seq)
	if m == nil || m.Data == nil || err != nil {
		return m, err
	}
	return cms.decryptedMsg(m)
}

// FirstMsg implements the MsgStore interface
func (cms *CryptoMsgStore) FirstMsg() (*pb.MsgProto, error) {
	m, err := cms.MsgStore.FirstMsg()
	if m == nil || m.Data == nil || err != nil {
		return m, err
	}
	return cms.decryptedMsg(m)
}

// LastMsg implements the MsgStore interface
func (cms *CryptoMsgStore) LastMsg() (*pb.MsgProto, error) {
	m, err := cms.MsgStore.LastMsg()
	if m == nil || m.Data == nil || err != nil {
		return m, err
	}
	return cms.decryptedMsg(m)
}
