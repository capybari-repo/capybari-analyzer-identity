package identity

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/capybari-repo/capybari-core/facts"
	"github.com/capybari-repo/capybari-core/finding"
)

var now = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// registry serves an RDAP bootstrap and one domain record.
func registry(t *testing.T, registered, expires string) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/bootstrap":
			w.Write([]byte(`{"services":[[["com","uk"],["` + srv.URL + `/rdap/"]]]}`))
		case strings.HasPrefix(r.URL.Path, "/rdap/domain/"):
			w.Write([]byte(`{"events":[{"eventAction":"registration","eventDate":"` + registered + `"},{"eventAction":"expiration","eventDate":"` + expires + `"}],
"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Registrar"]]]}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func dns(records map[string][]string) func(context.Context, string) ([]string, error) {
	return func(_ context.Context, name string) ([]string, error) {
		if r, ok := records[name]; ok {
			return r, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
}

func byCat(fs []finding.Finding) map[string]finding.Finding {
	m := map[string]finding.Finding{}
	for _, f := range fs {
		m[f.Category] = f
	}
	return m
}

func TestEstablishedShop(t *testing.T) {
	srv := registry(t, "2015-03-01T00:00:00Z", "2027-03-01T00:00:00Z")
	a := &Analyzer{Bootstrap: srv.URL + "/bootstrap", LookupTXT: dns(map[string][]string{
		"tallyroom.co.uk":        {"v=spf1 include:_spf.google.com ~all"},
		"_dmarc.tallyroom.co.uk": {"v=DMARC1; p=reject"},
	})}
	ws := &facts.WebSnapshot{FinalURL: "https://www.tallyroom.co.uk/", Body: `<html><head><title>Tallyroom — café rotas</title></head><body>Hi</body></html>`}
	fs, id, _, err := a.assess(context.Background(), ws, &facts.Commerce{Sells: true}, srv.Client(), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 || id.Domain != "tallyroom.co.uk" || id.Registered.Year() != 2015 || id.Registrar != "Example Registrar" || !id.BrandMatches || !id.DNSChecked {
		t.Fatalf("established shop: %+v %+v", fs, id)
	}
}

func TestNewSpoofableMismatchedShop(t *testing.T) {
	srv := registry(t, "2025-12-10T00:00:00Z", "2026-01-15T00:00:00Z")
	a := &Analyzer{Bootstrap: srv.URL + "/bootstrap", LookupTXT: dns(map[string][]string{"_dmarc.bestdeals-outlet.com": {"v=DMARC1; p=none"}})}
	ws := &facts.WebSnapshot{FinalURL: "https://bestdeals-outlet.com/", Body: `<html><head><title>Nike Official Store | Sale</title><meta property="og:site_name" content="Nike"></head><body>Big sale</body></html>`}
	fs, _, _, _ := a.assess(context.Background(), ws, &facts.Commerce{Sells: true}, srv.Client(), now)
	got := byCat(fs)
	if f := got["domain-new"]; f.Severity != finding.Medium || !strings.Contains(f.Title, "22 days ago") {
		t.Fatalf("new domain selling: %+v", got)
	}
	if _, ok := got["domain-expiring"]; !ok {
		t.Fatalf("expiring domain: %+v", got)
	}
	if f := got["email-spoofable"]; !strings.Contains(f.Title, "no SPF record, DMARC policy is p=none") {
		t.Fatalf("spoofable email: %+v", got)
	}
	if f := got["brand-mismatch"]; !strings.Contains(f.Title, `"Nike"`) {
		t.Fatalf("brand mismatch: %+v", got)
	}
}

func TestSubdomainProductName(t *testing.T) {
	a := &Analyzer{}
	ws := &facts.WebSnapshot{FinalURL: "https://news.livegrid.live/", Body: `<title>News Briefing</title>`}
	_, id, _, _ := a.assess(context.Background(), ws, nil, nil, now)
	if !id.BrandMatches {
		t.Fatalf("a subdomain product may carry the subdomain's name: %+v", id)
	}
}

func TestOfflineAndIPs(t *testing.T) {
	a := &Analyzer{}
	ws := &facts.WebSnapshot{FinalURL: "http://127.0.0.1:8080/", Body: `<title>Whatever</title>`}
	fs, id, limits, _ := a.assess(context.Background(), ws, nil, nil, now)
	if len(fs) != 0 || id.BrandEvaluated || len(limits) == 0 {
		t.Fatalf("an IP address has no domain to check: %+v %+v %v", fs, id, limits)
	}
}
