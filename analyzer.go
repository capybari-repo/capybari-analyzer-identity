// Package identity implements Domain & Identity: how established a
// website's domain is, whether its email can be spoofed, and whether the
// site's name matches its domain. Only the domain name leaves the scan.
package identity

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/capybari-repo/capybari-core/analyzer"
	"github.com/capybari-repo/capybari-core/facts"
	"github.com/capybari-repo/capybari-core/finding"
	"github.com/capybari-repo/capybari-core/webtext"
)

//go:embed capability.yaml
var capabilityYAML []byte

var capability = analyzer.MustParseCapability(capabilityYAML)

// Thresholds.
const (
	newDomain      = 90 * 24 * time.Hour
	expiringWithin = 30 * 24 * time.Hour
)

// Analyzer implements the capability.
type Analyzer struct {
	// Bootstrap overrides IANA's RDAP bootstrap URL (tests).
	Bootstrap string
	// LookupTXT overrides DNS TXT lookups (tests).
	LookupTXT func(ctx context.Context, name string) ([]string, error)
}

// New returns the capability.
func New() *Analyzer { return &Analyzer{} }

// Capability implements analyzer.Analyzer.
func (*Analyzer) Capability() analyzer.Capability { return capability }

// Applies declines when no page was fetched.
func (*Analyzer) Applies(in *analyzer.Input) (bool, string) {
	var ws facts.WebSnapshot
	if ok, _ := in.Evidence.Get(facts.KeyWebSnapshot, &ws); !ok || ws.FinalURL == "" {
		return false, "no page was fetched"
	}
	return true, ""
}

var (
	reTitle    = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reSiteName = regexp.MustCompile(`(?i)<meta[^>]+property=["']og:site_name["'][^>]+content=["']([^"']+)|<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:site_name`)
	reAppName  = regexp.MustCompile(`(?i)<meta[^>]+name=["']application-name["'][^>]+content=["']([^"']+)`)
	reNonAlnum = regexp.MustCompile(`[^a-z0-9]+`)
	reSep      = regexp.MustCompile(`\s+[|–—:·-]\s+|\s*[|–—·]\s*`)
)

func norm(s string) string { return reNonAlnum.ReplaceAllString(strings.ToLower(s), "") }

// Analyze implements analyzer.Analyzer.
func (a *Analyzer) Analyze(ctx context.Context, in *analyzer.Input) (*analyzer.Result, error) {
	var ws facts.WebSnapshot
	if _, err := in.Evidence.Get(facts.KeyWebSnapshot, &ws); err != nil {
		return nil, err
	}
	var com facts.Commerce
	hasCommerce, _ := in.Evidence.Get(facts.KeyCommerce, &com)
	now := time.Now().UTC()
	if in.Now != nil {
		now = in.Now().UTC()
	}
	var c *facts.Commerce
	if hasCommerce {
		c = &com
	}
	fs, id, limits, err := a.assess(ctx, &ws, c, in.HTTP, now)
	if err != nil {
		return nil, err
	}
	return &analyzer.Result{
		Findings:    fs,
		Summary:     summary(id),
		Evidence:    map[string]any{facts.KeyIdentity: id},
		Limitations: limits,
	}, nil
}

// assess does the work of Analyze; com is nil when commerce did not run and
// client is nil offline.
func (a *Analyzer) assess(ctx context.Context, ws *facts.WebSnapshot, com *facts.Commerce, client *http.Client, now time.Time) ([]finding.Finding, *facts.Identity, []string, error) {
	hasCommerce := com != nil
	if com == nil {
		com = &facts.Commerce{}
	}
	u, err := url.Parse(ws.FinalURL)
	if err != nil {
		return nil, nil, nil, err
	}
	host := strings.ToLower(u.Hostname())
	id := &facts.Identity{Domain: host}
	var limits []string
	isIP := net.ParseIP(host) != nil
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil && !isIP {
		id.Domain = d
	}
	sells := hasCommerce && com.Sells

	// Registration: RDAP, via IANA's bootstrap list for the TLD.
	online := client != nil && !isIP && strings.Contains(id.Domain, ".")
	if online {
		if err := a.rdap(ctx, client, id); err != nil {
			limits = append(limits, "Domain registration not checked: "+err.Error())
		}
		a.email(ctx, id)
	} else {
		limits = append(limits, "Offline or not a public domain: registration and email protection were not checked.")
	}

	// Brand: the name in the title, og:site_name or application-name.
	label := norm(strings.TrimSuffix(id.Domain, "."+suffixOf(id.Domain)))
	// A product on a subdomain (news.example.com) may carry the subdomain's
	// name rather than the domain's.
	labels := []string{label}
	if sub := strings.TrimSuffix(strings.TrimSuffix(host, id.Domain), "."); sub != "" && sub != "www" {
		for _, l := range strings.Split(sub, ".") {
			if l = norm(l); len(l) >= 3 && l != "www" && l != "app" {
				labels = append(labels, l)
			}
		}
	}
	var names []string
	if m := reSiteName.FindStringSubmatch(ws.Body); m != nil {
		names = append(names, m[1]+m[2])
	}
	if m := reAppName.FindStringSubmatch(ws.Body); m != nil {
		names = append(names, m[1])
	}
	if m := reTitle.FindStringSubmatch(ws.Body); m != nil {
		title := strings.TrimSpace(webtext.Visible(m[1]))
		names = append(names, reSep.Split(title, -1)...)
	}
	if len(names) > 0 && len(label) >= 3 && !isIP {
		id.BrandEvaluated = true
		id.Brand = strings.TrimSpace(names[0])
		text := norm(webtext.Visible(ws.Body))
	match:
		for _, n := range names {
			nn := norm(n)
			if nn == "" {
				continue
			}
			for _, l := range labels {
				if strings.Contains(nn, l) || len(nn) >= 4 && strings.Contains(l, nn) {
					id.BrandMatches, id.Brand = true, strings.TrimSpace(n)
					break match
				}
			}
		}
		if !id.BrandMatches && strings.Contains(text, label) {
			id.BrandMatches = true // the domain name appears on the page itself
		}
	}

	var fs []finding.Finding
	add := func(f finding.Finding) {
		f.Dimension = finding.DimTrust
		if f.Impact == nil {
			f.Impact = &finding.Impact{Buyer: finding.BuyerSupportCost}
		}
		fs = append(fs, f)
	}
	if !id.Registered.IsZero() && now.Sub(id.Registered) < newDomain {
		sev := finding.Low
		if sells {
			sev = finding.Medium
		}
		add(finding.Finding{
			Category: "domain-new", Severity: sev, Confidence: finding.ConfidenceHigh,
			Title:       fmt.Sprintf("Domain registered %d days ago", int(now.Sub(id.Registered).Hours()/24)),
			Description: fmt.Sprintf("%s was registered on %s. Brand-new domains are normal for new products, but also typical of short-lived shops and look-alike sites; check who is behind it before paying.", id.Domain, id.Registered.Format("2 Jan 2006")),
			Evidence:    []finding.Evidence{{Location: finding.Location{URL: ws.FinalURL}, Detail: "RDAP registration " + id.Registered.Format("2006-01-02")}},
		})
	}
	if !id.Expires.IsZero() && id.Expires.After(now) && id.Expires.Sub(now) < expiringWithin {
		add(finding.Finding{
			Category: "domain-expiring", Severity: finding.Low, Confidence: finding.ConfidenceHigh,
			Title:       "Domain expires on " + id.Expires.Format("2 Jan 2006"),
			Description: "The domain registration runs out within 30 days. If it is not renewed, the site and its email stop working.",
			Evidence:    []finding.Evidence{{Location: finding.Location{URL: ws.FinalURL}, Detail: "RDAP expiration " + id.Expires.Format("2006-01-02")}},
			Remediation: &finding.Remediation{Summary: "Renew the domain and enable auto-renewal."},
		})
	}
	usesEmail := sells || hasCommerce && strings.Contains(strings.ToLower(com.Contact), "@"+id.Domain)
	if id.DNSChecked && usesEmail && (id.SPF == "" || !strongDMARC(id.DMARC)) {
		var missing []string
		if id.SPF == "" {
			missing = append(missing, "no SPF record")
		}
		switch {
		case id.DMARC == "":
			missing = append(missing, "no DMARC record")
		case !strongDMARC(id.DMARC):
			missing = append(missing, "DMARC policy is p=none (monitor only)")
		}
		add(finding.Finding{
			Category: "email-spoofable", Severity: finding.Low, Confidence: finding.ConfidenceHigh,
			Title:       "Email from " + id.Domain + " can be spoofed (" + strings.Join(missing, ", ") + ")",
			Description: "Without SPF and an enforcing DMARC policy, anyone can send email that appears to come from this domain, so customers can receive convincing phishing in its name.",
			Evidence:    []finding.Evidence{{Location: finding.Location{URL: "dns:" + id.Domain}, Detail: fmt.Sprintf("SPF: %q; DMARC: %q", id.SPF, id.DMARC)}},
			Remediation: &finding.Remediation{Summary: "Publish an SPF record and a DMARC record with p=quarantine or p=reject."},
		})
	}
	if id.BrandEvaluated && !id.BrandMatches {
		add(finding.Finding{
			Category: "brand-mismatch", Severity: finding.Low, Confidence: finding.ConfidenceLow,
			Title:       fmt.Sprintf("Site calls itself %q, which does not match its domain %s", truncate(id.Brand, 40), id.Domain),
			Description: "Neither the page title nor its site name mentions the domain name, and the domain name does not appear on the page. That can be a rebrand, but it is also typical of copied templates and look-alike sites.",
			Evidence:    []finding.Evidence{{Location: finding.Location{URL: ws.FinalURL}, Detail: "title/site name: " + strings.Join(names, " | ")}},
			Remediation: &finding.Remediation{Summary: "Use the product's name consistently in the title, og:site_name and on the page."},
		})
	}

	return fs, id, limits, nil
}

func suffixOf(domain string) string {
	s, _ := publicsuffix.PublicSuffix(domain)
	return s
}

func strongDMARC(rec string) bool {
	r := strings.ToLower(strings.ReplaceAll(rec, " ", ""))
	return strings.Contains(r, "p=quarantine") || strings.Contains(r, "p=reject")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// rdap looks up the domain's registration with its registry's RDAP server.
func (a *Analyzer) rdap(ctx context.Context, c *http.Client, id *facts.Identity) error {
	boot := a.Bootstrap
	if boot == "" {
		boot = "https://data.iana.org/rdap/dns.json"
	}
	var bs struct {
		Services [][][]string `json:"services"`
	}
	if err := getJSON(ctx, c, boot, &bs); err != nil {
		return err
	}
	tld := id.Domain[strings.LastIndex(id.Domain, ".")+1:]
	var base string
	for _, s := range bs.Services {
		if len(s) < 2 || len(s[1]) == 0 {
			continue
		}
		for _, t := range s[0] {
			if strings.EqualFold(t, tld) {
				base = s[1][0]
			}
		}
	}
	if base == "" {
		return fmt.Errorf("no RDAP service for .%s", tld)
	}
	if !strings.HasPrefix(base, "https://") && !strings.HasPrefix(base, "http://127.0.0.1") {
		return fmt.Errorf("RDAP service for .%s is not HTTPS", tld)
	}
	var r struct {
		Events []struct {
			Action string    `json:"eventAction"`
			Date   time.Time `json:"eventDate"`
		} `json:"events"`
		Entities []struct {
			Roles []string `json:"roles"`
			Vcard []any    `json:"vcardArray"`
		} `json:"entities"`
	}
	if err := getJSON(ctx, c, strings.TrimSuffix(base, "/")+"/domain/"+id.Domain, &r); err != nil {
		return err
	}
	for _, e := range r.Events {
		switch e.Action {
		case "registration":
			id.Registered = e.Date.UTC()
		case "expiration":
			id.Expires = e.Date.UTC()
		}
	}
	for _, e := range r.Entities {
		for _, role := range e.Roles {
			if role == "registrar" {
				id.Registrar = vcardName(e.Vcard)
			}
		}
	}
	return nil
}

// vcardName extracts the "fn" value from a jCard array.
func vcardName(v []any) string {
	if len(v) < 2 {
		return ""
	}
	props, _ := v[1].([]any)
	for _, p := range props {
		if f, ok := p.([]any); ok && len(f) >= 4 && f[0] == "fn" {
			s, _ := f[3].(string)
			return s
		}
	}
	return ""
}

func getJSON(ctx context.Context, c *http.Client, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, req.URL.Host)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
}

// email reads the domain's SPF and DMARC records.
func (a *Analyzer) email(ctx context.Context, id *facts.Identity) {
	lookup := a.LookupTXT
	if lookup == nil {
		lookup = net.DefaultResolver.LookupTXT
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	txt, err := lookup(ctx, id.Domain)
	if err != nil && !isNotFound(err) {
		return
	}
	for _, t := range txt {
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			id.SPF = t
		}
	}
	dm, err := lookup(ctx, "_dmarc."+id.Domain)
	if err != nil && !isNotFound(err) {
		return
	}
	for _, t := range dm {
		if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
			id.DMARC = t
		}
	}
	id.DNSChecked = true
}

func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

func summary(id *facts.Identity) string {
	var parts []string
	if !id.Registered.IsZero() {
		reg := "registered " + id.Registered.Format("2006-01-02")
		if id.Registrar != "" {
			reg += " via " + id.Registrar
		}
		parts = append(parts, id.Domain+" "+reg)
	} else {
		parts = append(parts, id.Domain+": registration not known")
	}
	if id.DNSChecked {
		spf, dmarc := "no SPF", "no DMARC"
		if id.SPF != "" {
			spf = "SPF"
		}
		if id.DMARC != "" {
			dmarc = "DMARC " + map[bool]string{true: "enforcing", false: "monitor-only"}[strongDMARC(id.DMARC)]
		}
		parts = append(parts, spf+", "+dmarc)
	}
	if id.BrandEvaluated {
		parts = append(parts, fmt.Sprintf("name %q %s the domain", id.Brand, map[bool]string{true: "matches", false: "does not match"}[id.BrandMatches]))
	}
	return strings.Join(parts, "; ")
}
