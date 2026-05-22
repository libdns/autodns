package sdk_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/libdns/autodns"
	"github.com/libdns/autodns/sdk"
	"github.com/libdns/libdns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration(t *testing.T) {

	username := getIfSet(t, "AUTODNS_USERNAME")
	password := getIfSet(t, "AUTODNS_PASSWORD")
	zone := getIfSet(t, "TEST_ZONE")

	s := &sdk.SDK{
		Username: username,
		Password: password,
	}

	if c := os.Getenv("AUTODNS_CONTEXT"); c != "" {
		s.Context = c
	}
	if ep := os.Getenv("AUTODNS_ENDPOINT"); ep != "" {
		s.Endpoint = ep
	}
	s.HttpClient = &http.Client{Timeout: 30 * time.Second}

	provider := autodns.NewWithSDK(s)

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	probe := &libdns.TXT{
		Name: fmt.Sprintf("autodns-integration-test-%d", time.Now().Unix()),
		Text: "record via TestIntegration",
		TTL:  300 * time.Second,
	}

	t.Log("=== add ===")
	added, err := provider.AppendRecords(ctx, zone, []libdns.Record{probe})
	require.NoError(t, err, "AppendRecords: %v", err)
	assert.Len(t, added, 1)

	printRecords(t, "added", added)

	t.Log("=== list ===")
	records, err := provider.GetRecords(ctx, zone)
	require.NoError(t, err, "GetRecords: %v", err)
	assert.Greater(t, len(records), 0)

	printRecords(t, zone, records)

	t.Log("=== remove ===")
	removed, err := provider.DeleteRecords(ctx, zone, []libdns.Record{probe})
	require.NoError(t, err, "DeleteRecords: %v", err)
	assert.Len(t, removed, 1)

	printRecords(t, "removed", removed)
}

func getIfSet(t *testing.T, key string) string {
	t.Helper()

	val, exist := os.LookupEnv(key)
	if !exist {
		t.Skipf("Missing %s in environment", key)
	}

	return val
}

func printRecords(t *testing.T, label string, records []libdns.Record) {
	t.Helper()

	t.Logf("%s — %d record(s)\n", label, len(records))
	for _, r := range records {
		rr := r.RR()
		t.Logf("  %q\t%-6s ttl=%-8s %s\n", rr.Name, rr.Type, rr.TTL, rr.Data)
	}
}
