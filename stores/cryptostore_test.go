package stores

import (
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"
)

func TestCryptoStore(t *testing.T) {
	cleanupFSDatastore(t)
	defer cleanupFSDatastore(t)

	os.Unsetenv(CryptoStoreEnvKeyName)

	s := createDefaultFileStore(t)
	defer s.Close()

	cs, err := NewCryptoStore(s, "")
	if cs != nil || err != ErrCryptoStoreRequiresKey {
		t.Fatalf("Expected no store and error %q, got %v - %v", ErrCryptoStoreRequiresKey.Error(), cs, err)
	}
	goodKey := "ivan"
	cs, err = NewCryptoStore(s, goodKey)
	if err != nil {
		t.Fatalf("Unable to create crypto store: %v", err)
	}
	defer cs.Close()

	c := storeCreateChannel(t, cs, "foo")
	for i := 0; i < 10; i++ {
		storeMsg(t, c, "foo", []byte(fmt.Sprintf("msg%d", i)))
	}
	cs.Close()

	// Reopen the file and do Recover() without crypto. the
	// content of messages should be encrypted.
	s, rs := openDefaultFileStore(t)
	rc := getRecoveredChannel(t, rs, "foo")
	for i := 0; i < 10; i++ {
		msg, err := rc.Msgs.Lookup(uint64(i + 1))
		if err != nil {
			t.Fatalf("Error looking up message: %v", err)
		}
		if reflect.DeepEqual(msg.Data, []byte(fmt.Sprintf("msg%d", i))) {
			t.Fatalf("Unexpected message: %v", string(msg.Data))
		}
	}
	s.Close()

	// Now create the file store and wrap with CryptoStore.
	// First use wrong key and lookup should fail, then
	// correct key and all should be good.
	keys := []string{"wrongkey", goodKey}
	for _, k := range keys {
		s, err = NewFileStore(testLogger, testFSDefaultDatastore, nil)
		if err != nil {
			t.Fatalf("Error opening store: %v", err)
		}
		defer s.Close()
		cs, err = NewCryptoStore(s, k)
		if err != nil {
			t.Fatalf("Error creating crypto store: %v", err)
		}
		rs, err = cs.Recover()
		if err != nil {
			t.Fatalf("Error recovering state: %v", err)
		}
		rc = getRecoveredChannel(t, rs, "foo")
		for i := 0; i < 10; i++ {
			msg, err := rc.Msgs.Lookup(uint64(i + 1))
			if k != goodKey {
				if msg != nil || err == nil {
					t.Fatalf("Expected failure to lookup message, got m=%v err=%v", msg, err)
				}
			} else {
				if err != nil {
					t.Fatalf("Error looking up message: %v", err)
				}
				if !reflect.DeepEqual(msg.Data, []byte(fmt.Sprintf("msg%d", i))) {
					t.Fatalf("Unexpected message: %v", string(msg.Data))
				}
			}
		}
		if k == goodKey {
			fm := msgStoreFirstMsg(t, rc.Msgs)
			if !reflect.DeepEqual(fm.Data, []byte("msg0")) {
				t.Fatalf("Unexpected message: %v", string(fm.Data))
			}
			lm := msgStoreLastMsg(t, rc.Msgs)
			if !reflect.DeepEqual(lm.Data, []byte("msg9")) {
				t.Fatalf("Unexpected message: %v", string(fm.Data))
			}
		}
		cs.Close()
	}
}

func TestCryptoStoreEmptyMsg(t *testing.T) {
	s := createDefaultMemStore(t)
	defer s.Close()

	os.Unsetenv(CryptoStoreEnvKeyName)

	cs, err := NewCryptoStore(s, "ivan")
	if err != nil {
		t.Fatalf("Error creating store: %v", err)
	}
	defer cs.Close()

	c := storeCreateChannel(t, cs, "foo")
	seq, err := c.Msgs.Store(nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	m := msgStoreLookup(t, c.Msgs, seq)
	if m.Data != nil {
		t.Fatalf("Unexpected content: %s", m.Data)
	}
	m = msgStoreFirstMsg(t, c.Msgs)
	if m.Data != nil {
		t.Fatalf("Unexpected content: %s", m.Data)
	}
	m = msgStoreLastMsg(t, c.Msgs)
	if m.Data != nil {
		t.Fatalf("Unexpected content: %s", m.Data)
	}
}

func TestCryptoStoreUseEnvKey(t *testing.T) {
	cleanupFSDatastore(t)
	defer cleanupFSDatastore(t)

	os.Unsetenv(CryptoStoreEnvKeyName)
	defer os.Unsetenv(CryptoStoreEnvKeyName)

	if err := os.Setenv(CryptoStoreEnvKeyName, "ivan"); err != nil {
		t.Fatalf("Unable to set environment variable: %v", err)
	}

	s := createDefaultFileStore(t)
	defer s.Close()

	cs, err := NewCryptoStore(s, "")
	if err != nil {
		t.Fatalf("Unable to create crypto store: %v", err)
	}
	defer cs.Close()
}

func TestCryptoStoreRenewNonce(t *testing.T) {
	s := createDefaultMemStore(t)
	defer s.Close()

	os.Unsetenv(CryptoStoreEnvKeyName)

	csMaxEncryptCallsPerNonce = 10
	defer func() { csMaxEncryptCallsPerNonce = csDefaultMaxEncryptCallsPerNonce }()

	cs, err := NewCryptoStore(s, "ivan")
	if err != nil {
		t.Fatalf("Error creating store: %v", err)
	}
	defer cs.Close()

	cs.Lock()
	orgNonce := cs.nonce
	cs.Unlock()
	c := storeCreateChannel(t, cs, "foo")
	nr := 20
	wg := sync.WaitGroup{}
	wg.Add(nr)
	for i := 0; i < nr; i++ {
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				storeMsg(t, c, "foo", []byte("hello"))
			}
		}()
	}
	wg.Wait()
	cs.Lock()
	currentNonce := cs.nonce
	cs.Unlock()
	if reflect.DeepEqual(orgNonce, currentNonce) {
		t.Fatal("Nonce should have changed")
	}
}
