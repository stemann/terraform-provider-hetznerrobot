package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// RDNS represents a single PTR record returned by /rdns endpoints.
type RDNS struct {
	IP  string `json:"ip"`
	PTR string `json:"ptr"`
}

// ErrRDNSNotFound is returned when no PTR exists for an IP.
var ErrRDNSNotFound = errors.New("rdns entry not found")

// FetchRDNS returns the PTR record for a single IP, or ErrRDNSNotFound if none.
func (c *HetznerRobotClient) FetchRDNS(ctx context.Context, ip string) (RDNS, error) {
	resp, err := c.DoRequest(ctx, "GET", "/rdns/"+ip, nil, "")
	if err != nil {
		return RDNS{}, fmt.Errorf("FetchRDNS request error: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return RDNS{}, ErrRDNSNotFound
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)

		return RDNS{}, fmt.Errorf("FetchRDNS %s: status %d, body %s", ip, resp.StatusCode, body)
	}

	var result struct {
		RDNS RDNS `json:"rdns"`
	}

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return RDNS{}, fmt.Errorf("FetchRDNS decode error: %w", err)
	}

	return result.RDNS, nil
}

// SetRDNS upserts the PTR record for an IP via PUT /rdns/{ip}.
func (c *HetznerRobotClient) SetRDNS(ctx context.Context, ip, ptr string) error {
	data := url.Values{}
	data.Set("ptr", ptr)

	resp, err := c.DoRequest(
		ctx,
		"PUT",
		"/rdns/"+ip,
		strings.NewReader(data.Encode()),
		"application/x-www-form-urlencoded",
	)
	if err != nil {
		return fmt.Errorf("SetRDNS request error: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)

		return fmt.Errorf("SetRDNS %s: status %d, body %s", ip, resp.StatusCode, body)
	}

	return nil
}

// DeleteRDNS removes the PTR record for an IP. A 404 is treated as success.
func (c *HetznerRobotClient) DeleteRDNS(ctx context.Context, ip string) error {
	resp, err := c.DoRequest(ctx, "DELETE", "/rdns/"+ip, nil, "")
	if err != nil {
		return fmt.Errorf("DeleteRDNS request error: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
		return nil
	}

	body, _ := io.ReadAll(resp.Body)

	return fmt.Errorf("DeleteRDNS %s: status %d, body %s", ip, resp.StatusCode, body)
}
