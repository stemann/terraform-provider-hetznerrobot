package server

import (
	"context"
	"crypto/md5" //nolint:gosec // Hetzner Robot returns MD5 fingerprints; used only to compare.
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/crypto/ssh"
)

const hostKeyScanTimeout = 10 * time.Second

// errHostKeyCaptured aborts the SSH handshake once the host key is captured.
var errHostKeyCaptured = errors.New("host key captured")

// hostKeyAlgos covers the host-key signature algorithms a current sshd advertises.
// Multiple entries may resolve to the same underlying key (e.g. RSA + rsa-sha2-*);
// scanAndVerifyHostKeys deduplicates by marshaled key bytes.
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

func md5Fingerprint(key ssh.PublicKey) string {
	sum := md5.Sum(key.Marshal()) //nolint:gosec // see file-level comment.

	parts := make([]string, len(sum))

	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02x", b)
	}

	return strings.Join(parts, ":")
}

func sha256Fingerprint(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())

	return "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
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

	_, _, _, _ = ssh.NewClientConn(conn, addr, cfg) //nolint:dogsled // we only want the host key.

	if captured == nil {
		return nil, fmt.Errorf("no host key for %s on %s", algo, addr)
	}

	return captured, nil
}

// scanAndVerifyHostKeys probes host:22 for each known host-key algorithm and
// verifies every captured key against the API-supplied fingerprints. It returns
// two maps keyed by SSH key type (e.g. "ssh-ed25519", "ssh-rsa"): the verified
// MD5 fingerprints and the authorized_keys-formatted public keys, ready to be
// passed to a Terraform connection block as host_key. A captured key whose
// fingerprint is not in the API list aborts the call as a possible MITM.
func scanAndVerifyHostKeys(
	ctx context.Context,
	host string,
	expected []string,
) (map[string]string, map[string]string, error) {
	if len(expected) == 0 {
		return nil, nil, errors.New("no expected fingerprints from API; refusing to trust scan")
	}

	allowed := make(map[string]struct{}, len(expected))
	for _, fp := range expected {
		allowed[strings.ToLower(strings.TrimSpace(fp))] = struct{}{}
	}

	addr := net.JoinHostPort(host, "22")
	fingerprints := map[string]string{}
	hostKeys := map[string]string{}

	for _, algo := range hostKeyAlgos {
		key, err := scanHostKey(ctx, addr, algo, hostKeyScanTimeout)
		if err != nil {
			continue
		}

		keyType := key.Type()
		if _, dup := hostKeys[keyType]; dup {
			continue
		}

		md5fp := md5Fingerprint(key)
		sha256fp := sha256Fingerprint(key)
		_, mdMatch := allowed[strings.ToLower(md5fp)]
		_, shaMatch := allowed[strings.ToLower(sha256fp)]

		if !mdMatch && !shaMatch {
			return nil, nil, fmt.Errorf(
				"host key for %s (%s) not in API fingerprint list — possible MITM (md5=%s sha256=%s)",
				host,
				keyType,
				md5fp,
				sha256fp,
			)
		}

		fingerprints[keyType] = md5fp
		hostKeys[keyType] = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	}

	if len(hostKeys) == 0 {
		return nil, nil, fmt.Errorf("no host keys captured from %s", host)
	}

	return fingerprints, hostKeys, nil
}

// captureRescueHostKeys scans the rescue system, verifies its keys against
// the API fingerprints, and stores the result on the resource.
func captureRescueHostKeys(
	ctx context.Context,
	d *schema.ResourceData,
	host string,
	expected []string,
) error {
	fingerprints, hostKeys, err := scanAndVerifyHostKeys(ctx, host, expected)
	if err != nil {
		return err
	}

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
