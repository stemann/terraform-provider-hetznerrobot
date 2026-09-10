package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/crypto/ssh"
)

const (
	hostKeyScanTimeout  = 10 * time.Second
	hostKeyScanBudget   = 2 * time.Minute
	hostKeyScanInterval = 10 * time.Second
)

// errHostKeyCaptured aborts the SSH handshake once the host key is captured.
var errHostKeyCaptured = errors.New("host key captured")

// hostKeyAlgos covers the host-key signature algorithms a current sshd advertises.
// Multiple entries may resolve to the same underlying key (e.g. RSA + rsa-sha2-*);
// scanHostKeys deduplicates by key type (key.Type()), so each type is
// captured once from the first algorithm that succeeds.
//
//nolint:gochecknoglobals // package-level constant list; not a mutable global.
var hostKeyAlgos = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512,
	ssh.KeyAlgoRSASHA256,
	ssh.KeyAlgoRSA,
}

// scanHostKey dials addr offering only the given host-key algorithm and returns
// the captured key. The handshake is aborted before authentication; we never
// authenticate to the rescue system from the provider.
//
//nolint:ireturn // ssh.PublicKey is the upstream interface; returning a concrete type would lose info.
func scanHostKey(
	ctx context.Context,
	addr, algo string,
	timeout time.Duration,
) (ssh.PublicKey, error) {
	var captured ssh.PublicKey

	//exhaustruct:ignore
	cfg := &ssh.ClientConfig{
		User:              "root",
		HostKeyAlgorithms: []string{algo},
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			captured = k

			return errHostKeyCaptured
		},
		Timeout: timeout,
	}

	//exhaustruct:ignore
	dialer := net.Dialer{Timeout: timeout}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	// ClientConfig.Timeout covers the dial only, and ssh.NewClientConn neither
	// takes a context nor sets a deadline, so a peer that accepts the connection
	// and then stalls before its banner would block here indefinitely.
	err = conn.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		return nil, fmt.Errorf("set deadline for %s: %w", addr, err)
	}

	_, _, _, _ = ssh.NewClientConn(conn, addr, cfg) //nolint:dogsled // we only want the host key.

	if captured == nil {
		return nil, fmt.Errorf("no host key for %s on %s", algo, addr)
	}

	return captured, nil
}

// scanHostKeys probes addr once per known host-key algorithm and returns the
// captured keys by key type. Per-algorithm failures are kept rather than
// dropped: a server that has no key of that type and a connection the peer
// reset look the same to a single probe, so the errors are what tell the two
// apart once every probe has run.
func scanHostKeys(ctx context.Context, addr string) (map[string]ssh.PublicKey, error) {
	keys := make(map[string]ssh.PublicKey, len(hostKeyAlgos))

	var errs []error

	for _, algo := range hostKeyAlgos {
		key, err := scanHostKey(ctx, addr, algo, hostKeyScanTimeout)
		if err != nil {
			errs = append(errs, err)

			continue
		}

		if _, dup := keys[key.Type()]; !dup {
			keys[key.Type()] = key
		}
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no host keys captured from %s: %w", addr, errors.Join(errs...))
	}

	return keys, nil
}

// scanHostKeysWithin retries a scan that captured nothing until budget is
// spent: the rescue system restarts sshd shortly after it first accepts on
// port 22, so an entire round of probes can fail on a reset connection a
// second after the port came up.
func scanHostKeysWithin(
	ctx context.Context,
	addr string,
	budget, interval time.Duration,
) (map[string]ssh.PublicKey, error) {
	deadline := time.Now().Add(budget)

	for {
		keys, err := scanHostKeys(ctx, addr)
		if err == nil {
			return keys, nil
		}

		if !time.Now().Before(deadline) {
			return nil, err
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("scanning %s: %w", addr, ctx.Err())
		case <-time.After(interval):
		}
	}
}

// hostKeyAttributes renders captured keys as the two computed attributes: MD5
// fingerprints and authorized_keys-formatted keys, both keyed by SSH key type
// (e.g. "ssh-ed25519", "ssh-rsa"). The fingerprints are computed here, since
// the Hetzner API reports none for the rescue system.
func hostKeyAttributes(keys map[string]ssh.PublicKey) (map[string]string, map[string]string) {
	fingerprints := make(map[string]string, len(keys))
	hostKeys := make(map[string]string, len(keys))

	for keyType, key := range keys {
		fingerprints[keyType] = ssh.FingerprintLegacyMD5(key)
		hostKeys[keyType] = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	}

	return fingerprints, hostKeys
}

// captureRescueHostKeys scans host:22 for each known host-key algorithm and
// stores what it captured on the resource. The keys are trusted on first use:
// the Hetzner API reports no fingerprints for the rescue system, so there is
// nothing to verify them against.
func captureRescueHostKeys(
	ctx context.Context,
	d *schema.ResourceData,
	host string,
) error {
	addr := net.JoinHostPort(host, "22")

	keys, err := scanHostKeysWithin(ctx, addr, hostKeyScanBudget, hostKeyScanInterval)
	if err != nil {
		return err
	}

	fingerprints, hostKeys := hostKeyAttributes(keys)

	err = d.Set("host_key_fingerprints", fingerprints)
	if err != nil {
		return fmt.Errorf("error setting host_key_fingerprints attribute: %w", err)
	}

	err = d.Set("host_keys", hostKeys)
	if err != nil {
		return fmt.Errorf("error setting host_keys attribute: %w", err)
	}

	return nil
}
