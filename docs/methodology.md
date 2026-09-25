# Methodology: Domain & Identity (experimental)

## Requests

1. `GET https://data.iana.org/rdap/dns.json`: IANA's list of RDAP servers per top-level domain.
2. `GET <registry RDAP server>/domain/<domain>`, HTTPS only. The `registration` and `expiration` events and the registrar's name are read.
3. DNS TXT lookups for `<domain>` (SPF, `v=spf1`) and `_dmarc.<domain>` (DMARC, `v=DMARC1`) through the system resolver, with a 5 s timeout.

The domain is the registrable domain (public suffix + 1), so `shop.example.co.uk` is looked up as `example.co.uk`. IP addresses and offline scans skip all three.

## Findings

| Rule | Trigger | Severity | Confidence | Buyer impact |
|---|---|---|---|---|
| `domain-new` | registered < 6 months ago | low; medium if it sells (from `commerce`); high if it sells and is < 30 days old | high | support cost |
| `domain-expiring` | expiry within 30 days | low | high | support cost |
| `email-spoofable` | sells, or publishes an email address at the domain, **and** no SPF record or DMARC missing / `p=none` | low | high | support cost |
| `brand-mismatch` | no title/site-name part contains the domain or subdomain label (or vice versa, for names of 4+ characters), and the domain label does not appear in the page text | low | low | support cost |

Positives in the verdict: a domain registered over a year ago; SPF with DMARC `p=quarantine` or `p=reject`.

## Limitations

Some registries hide or omit registration dates in RDAP. A new domain is normal for a new product; the finding says so. Brand checks cannot see rebrands. Look-alike (template twin) detection against other sites is not done.
