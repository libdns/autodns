package autodns_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/libdns/autodns"
	"github.com/stretchr/testify/assert"
)

func TestProvider(t *testing.T) {
	if os.Getenv("AUTODNS_USERNAME") == "" || os.Getenv("AUTODNS_PASSWORD") == "" {
		t.SkipNow()
	}

	provider := autodns.NewWithDefaults(os.Getenv("AUTODNS_USERNAME"), os.Getenv("AUTODNS_PASSWORD"))

	t.Run("GetRecords", func(t *testing.T) {
		if os.Getenv("TEST_ZONE") == "" {
			t.Skip()
		}

		records, err := provider.GetRecords(context.TODO(), os.Getenv("TEST_ZONE"))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}

		if len(records) == 0 {
			t.Fatalf("expected at least one record: %#v", records)
		}
	})

}

func TestGetRecords(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.String() == "/zone/_search" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(mockSearchResponse)
			return
		}

		if r.Method == http.MethodGet && r.URL.String() == "/zone/example.org/a.ns14.net" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(mockZoneResponse)
			return
		}

		t.Logf("%s %s", r.Method, r.URL.String())
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintln(w, "Hello, client")
	}))
	defer ts.Close()

	provicer := autodns.Provider{
		Username: "doesn't-matter",
		Password: "doesn't matter",
		Context:  "23",
		Endpoint: ts.URL,
	}

	records, err := provicer.GetRecords(context.TODO(), "example.org")
	assert.NoError(t, err)
	assert.NotEmpty(t, records)
}
