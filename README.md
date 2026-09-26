# capybari-analyzer-identity (experimental)

**Capybari Source Intelligence: Domain & Identity: who is behind this website?**

| Signal | Source |
|---|---|
| Domain registration and expiry dates, registrar | **RDAP**, the public registration-data service: IANA's bootstrap list (`data.iana.org`) names the registry's RDAP server for the TLD |
| Email spoofing protection | **SPF** and **DMARC** TXT records in public DNS |
| Name consistency | the page title, `og:site_name` and `application-name` compared with the domain (and subdomain) name |

| Finding | When | For buyers |
|---|---|---|
| `domain-new` | registered less than 6 months ago: "Domain only about 3 months old" (medium if the site sells; high if it sells and is under 30 days) | support cost |
| `domain-expiring` | expires within 30 days | support cost |
| `email-spoofable` | the site sells or publishes an address at its domain, and has no SPF or no enforcing DMARC (`p=quarantine`/`p=reject`): "Email in Indraft's name can be faked" | support cost |
| `brand-inconsistent` | the page title and og:site_name name the product differently | support cost |
| `brand-mismatch` | the name the site gives itself matches neither its domain nor anything on the page | support cost |

Only the domain name leaves the scan. It feeds the **Trust** question of the verdict.

| | |
|---|---|
| Requires | `web-snapshot` (optional `commerce`) |
| Provides | `identity` evidence |
| Network | optional: `data.iana.org` and the registry's RDAP server; two DNS TXT lookups |

Methodology: [docs/methodology.md](docs/methodology.md). License: Apache-2.0.
