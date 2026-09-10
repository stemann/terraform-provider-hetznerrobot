package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// listenLocal opens a loopback listener that is closed when the test ends.
func listenLocal(t *testing.T) net.Listener {
	t.Helper()

	//exhaustruct:ignore
	config := net.ListenConfig{}

	listener, err := config.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	t.Cleanup(func() { _ = listener.Close() })

	return listener
}

// startHostKeyServer serves SSH handshakes on 127.0.0.1 with a freshly
// generated ed25519 host key, closing the first refuseFirst connections
// without one. It returns the listen address and the host key served.
//
//nolint:ireturn // ssh.PublicKey is the upstream interface, as in hostkeys.go.
func startHostKeyServer(t *testing.T, refuseFirst int64) (string, ssh.PublicKey) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating host key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}

	listener := listenLocal(t)

	//exhaustruct:ignore
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)

	var accepted atomic.Int64

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			if accepted.Add(1) <= refuseFirst {
				_ = conn.Close()

				continue
			}

			// The client aborts as soon as it has the host key, so the
			// handshake is expected to fail here.
			go func() {
				defer conn.Close()

				_, _, _, _ = ssh.NewServerConn(conn, cfg)
			}()
		}
	}()

	return listener.Addr().String(), signer.PublicKey()
}

func TestScanHostKeys(t *testing.T) {
	t.Parallel()

	addr, want := startHostKeyServer(t, 0)

	keys, err := scanHostKeys(context.Background(), addr)
	if err != nil {
		t.Fatalf("scanHostKeys: %v", err)
	}

	// Six of the seven probes ask for an algorithm this server cannot serve.
	if len(keys) != 1 {
		t.Fatalf("captured %d key types, want 1: %v", len(keys), keys)
	}

	got, ok := keys[ssh.KeyAlgoED25519]
	if !ok {
		t.Fatalf("no %s key captured: %v", ssh.KeyAlgoED25519, keys)
	}

	if string(got.Marshal()) != string(want.Marshal()) {
		t.Errorf("captured key does not match the key served")
	}
}

func TestScanHostKeysReportsEveryProbeFailure(t *testing.T) {
	t.Parallel()

	// A server that closes every connection: no probe can capture a key.
	addr, _ := startHostKeyServer(t, int64(len(hostKeyAlgos)))

	_, err := scanHostKeys(context.Background(), addr)
	if err == nil {
		t.Fatal("scanHostKeys succeeded against a server that refuses every connection")
	}

	if !strings.Contains(err.Error(), "no host keys captured from "+addr) {
		t.Errorf("error does not name the host: %v", err)
	}

	for _, algo := range hostKeyAlgos {
		if !strings.Contains(err.Error(), algo) {
			t.Errorf("error drops the %s probe failure: %v", algo, err)
		}
	}
}

func TestScanHostKeyStopsAtDeadline(t *testing.T) {
	t.Parallel()

	// A listener that accepts and then says nothing: without a deadline on the
	// connection, ssh.NewClientConn would wait for a banner forever.
	listener := listenLocal(t)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}

		t.Cleanup(func() { _ = conn.Close() })
	}()

	const timeout = 200 * time.Millisecond

	start := time.Now()

	_, err := scanHostKey(
		context.Background(),
		listener.Addr().String(),
		ssh.KeyAlgoED25519,
		timeout,
	)
	if err == nil {
		t.Fatal("scanHostKey succeeded against a silent server")
	}

	if elapsed := time.Since(start); elapsed > 5*timeout {
		t.Errorf("scanHostKey took %v, want it to give up around %v", elapsed, timeout)
	}
}

func TestScanHostKeysWithinRetries(t *testing.T) {
	t.Parallel()

	// Every probe of the first round is refused, as when rescue init restarts
	// sshd right after the port comes up. The second round succeeds.
	addr, _ := startHostKeyServer(t, int64(len(hostKeyAlgos)))

	keys, err := scanHostKeysWithin(
		context.Background(),
		addr,
		5*time.Second,
		10*time.Millisecond,
	)
	if err != nil {
		t.Fatalf("scanHostKeysWithin did not retry a failed round: %v", err)
	}

	if _, ok := keys[ssh.KeyAlgoED25519]; !ok {
		t.Errorf("no %s key captured on retry: %v", ssh.KeyAlgoED25519, keys)
	}
}

func TestScanHostKeysWithinGivesUpAtBudget(t *testing.T) {
	t.Parallel()

	listener := listenLocal(t)
	addr := listener.Addr().String()

	err := listener.Close()
	if err != nil {
		t.Fatalf("closing listener: %v", err)
	}

	start := time.Now()

	_, err = scanHostKeysWithin(
		context.Background(),
		addr,
		100*time.Millisecond,
		10*time.Millisecond,
	)
	if err == nil {
		t.Fatal("scanHostKeysWithin succeeded against a closed port")
	}

	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("scanHostKeysWithin ran for %v, want it bounded by the budget", elapsed)
	}
}

func TestScanHostKeysWithinHonorsContext(t *testing.T) {
	t.Parallel()

	listener := listenLocal(t)
	addr := listener.Addr().String()

	err := listener.Close()
	if err != nil {
		t.Fatalf("closing listener: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = scanHostKeysWithin(ctx, addr, time.Minute, time.Second)
	if err == nil {
		t.Fatal("scanHostKeysWithin ignored a cancelled context")
	}
}

func TestHostKeyAttributes(t *testing.T) {
	t.Parallel()

	addr, want := startHostKeyServer(t, 0)

	keys, err := scanHostKeys(context.Background(), addr)
	if err != nil {
		t.Fatalf("scanHostKeys: %v", err)
	}

	fingerprints, hostKeys := hostKeyAttributes(keys)

	keyType := want.Type()
	if got := fingerprints[keyType]; got != ssh.FingerprintLegacyMD5(want) {
		t.Errorf("fingerprint = %q, want %q", got, ssh.FingerprintLegacyMD5(want))
	}

	wantKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(want)))
	if got := hostKeys[keyType]; got != wantKey {
		t.Errorf("host key = %q, want %q", got, wantKey)
	}
}
