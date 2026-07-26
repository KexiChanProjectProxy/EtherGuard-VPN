package device

import (
	"encoding/binary"
	"testing"

	"github.com/pion/stun/v3"
)

func TestReceiveDemultiplexesSTUNBeforeWireGuard(t *testing.T) {
	transactionID := [stun.TransactionIDSize]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	valid, err := stun.Build(
		stun.BindingSuccess,
		stun.NewTransactionIDSetter(transactionID),
		&stun.XORMappedAddress{IP: []byte{198, 51, 100, 9}, Port: 32123},
		stun.Fingerprint,
	)
	if err != nil {
		t.Fatalf("build STUN response: %v", err)
	}

	t.Run("accepts known valid transaction", func(t *testing.T) {
		// Given
		manager := newPendingSTUNManagerForTest(transactionID)

		// When
		handled := manager.HandlePacket(valid.Raw)

		// Then
		if !handled {
			t.Fatal("valid pending STUN response was not handled")
		}
	})

	t.Run("rejects unknown transaction", func(t *testing.T) {
		// Given
		manager := newPendingSTUNManagerForTest([stun.TransactionIDSize]byte{99})

		// When
		handled := manager.HandlePacket(valid.Raw)

		// Then
		if handled {
			t.Fatal("unknown STUN transaction bypassed WireGuard validation")
		}
	})

	t.Run("rejects malformed fingerprint", func(t *testing.T) {
		// Given
		manager := newPendingSTUNManagerForTest(transactionID)
		malformed := append([]byte(nil), valid.Raw...)
		malformed[len(malformed)-1] ^= 0xff

		// When
		handled := manager.HandlePacket(malformed)

		// Then
		if handled {
			t.Fatal("bad STUN fingerprint was accepted")
		}
	})

	t.Run("rejects bad magic cookie", func(t *testing.T) {
		// Given
		manager := newPendingSTUNManagerForTest(transactionID)
		badCookie := append([]byte(nil), valid.Raw...)
		binary.BigEndian.PutUint32(badCookie[4:8], 0)

		// When
		handled := manager.HandlePacket(badCookie)

		// Then
		if handled {
			t.Fatal("bad STUN magic cookie was accepted")
		}
	})

	t.Run("rejects delivery after manager close", func(t *testing.T) {
		// Given
		manager := newPendingSTUNManagerForTest(transactionID)
		manager.Close()

		// When
		handled := manager.HandlePacket(valid.Raw)

		// Then
		if handled {
			t.Fatal("closed manager accepted stale STUN response")
		}
		manager.mu.Lock()
		pending := len(manager.pending)
		manager.mu.Unlock()
		if pending != 0 {
			t.Fatalf("pending transactions = %d, want 0", pending)
		}
	})
}

func newPendingSTUNManagerForTest(transactionID [stun.TransactionIDSize]byte) *SuperSTUNManager {
	manager := NewSuperSTUNManager(&Device{})
	manager.addPendingForTest(transactionID)
	return manager
}
