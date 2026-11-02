<div align="center">

```
 ██████ ██    ██ ███████     ███████ ███████ ███████ ██████
██      ██    ██ ██          ██      ██      ██      ██   ██
██      ██    ██ █████       █████   █████   █████   ██   ██
██       ██  ██  ██          ██      ██      ██      ██   ██
 ██████   ████   ███████     ██      ███████ ███████ ██████
```

### **[cve.zerocrew.in](https://cve.zerocrew.in)**

**Arm your agents with knowledge of vulnerabilities — and the exploits that exist for them.**

[![live](https://img.shields.io/badge/live-cve.zerocrew.in-d2694f?style=flat-square)](https://cve.zerocrew.in)
[![mcp](https://img.shields.io/badge/MCP-6_tools-5a9c98?style=flat-square)](https://cve.zerocrew.in/mcp)
[![sources](https://img.shields.io/badge/registers-5_merged-6e6d6a?style=flat-square)](#sources)
[![licence](https://img.shields.io/badge/licence-noncommercial-9c5f12?style=flat-square)](#licence)
[![no key](https://img.shields.io/badge/API_key-not_required-5f9b7e?style=flat-square)](#mcp)

</div>

---

A model knows vulnerabilities up to its training cut-off and nothing after it,
which makes it a junior analyst reciting last year's news. Point an agent at
this endpoint and it gets what a good operator actually carries in their head:
what landed overnight, whether anyone has written working code for it, where
that code is, and which of the things you ship it lands on.

```bash
claude mcp add --transport http cvefeed https://cve.zerocrew.in/mcp
```

No account. No API key. Any MCP client works.

## What makes it different from a CVE list

Most feeds stop at "here is a CVE with a CVSS score". A score does not tell you
whether someone can run an attack this afternoon.

- **Exploit intelligence on every record** — whether exploitation has been
  *observed in the wild*, *weaponized* into a Metasploit module, archived as a
  *public exploit*, or published as *proof-of-concept* code, plus whether a
  Nuclei template means it is scanned for at internet scale. Sort by that and
  a 7.5 with a ready-made module correctly outranks a 9.8 nobody has written
  anything for.
- **A dependency check that knows versions** — paste a lockfile and every
  package is resolved at its exact installed version through OSV.dev, then
  ordered by whether exploit code exists. Unlike `npm audit`, the answer is a
  worklist of four rather than a wall of forty. See [Dependency check](#dependency-check).
- **Search by the names software actually has** — package coordinates, vendors
  and products are kept as structured data, so `litellm` matches the package
  rather than the word. A name nobody has asked about before is fetched from
  the registers once and kept. See [Search](#search).
- **A facet for the AI and agent stack** — inference servers, agent
  frameworks, MCP servers, vector stores, MLOps. Young code shipping fast, and
  the surface least picked over. See [The AI stack](#the-ai-stack).
- **Community proofs of concept**, reviewed before publication. See
  [Community proofs of concept](#community-proofs-of-concept).

Runs with no build step. It will run with no database at all, holding the feed
in memory with a JSON snapshot on disk — but it is [built around MongoDB](#storage),
and that is what makes the corpus accumulate instead of forgetting.

## Sources

| Source | What it adds | Auth |
| --- | --- | --- |
| [NVD](https://nvd.nist.gov/) | The CVE baseline: descriptions, CVSS v3/v4, CWEs, references | Optional key |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Confirmed in-the-wild exploitation, remediation due dates, ransomware use | None |
| [CISA Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories) | ICS, medical device and alert advisories | None |
| [GitHub Security Advisories](https://github.com/advisories) | Package/ecosystem detail, EPSS, fast publication | Optional token |
| [EUVD (ENISA)](https://euvd.enisa.europa.eu/) | EU vulnerability database, EPSS, independent scoring | None |

Any CVE identifier can be searched, including ones older than the feed window:
if it is not in the window, the sources are queried directly and the replies are
merged the same way. See [Search](#search).

Records describing the same vulnerability are **merged by CVE ID**: the highest
CVSS wins, EPSS and CWEs are unioned, every source keeps its own permalink, and
exploitation status is carried over from KEV. CISA advisories also enrich the
CVEs they reference.

## Quick start

```bash
npm install
cp .env.example .env   # optional - every setting has a sane default
npm start
```

Open <http://localhost:3000>.

The first boot fetches all five feeds (roughly 20–30 seconds, mostly NVD) and
warms the cache in the background, so the dashboard is responsive immediately
and fully populated shortly after.

## Search

Three stages, cheapest and most precise first, stopping at the first that
matches anything:

1. **Exact name** — the term *is* a package, vendor or product name. Package
   coordinates from GitHub Advisories, vendors and products from KEV and EUVD
   are kept as structured data rather than flattened into prose, so `litellm`
   matches the package and not the word. One indexed equality.
2. **Words** — a MongoDB text index over titles, descriptions, vendors and
   products.
3. **Substring** — a scan, for a term inside a word: `log4j` inside
   *Log4Shell*.

An exact match wins outright, which is the point — but it *hides* the text
matches, so the dashboard says so and offers `&match=words` to search
everything. On `microsoft` that is the difference between 94 records
attributed to Microsoft and 244 that merely mention the word.

A **typeahead** suggests real names as you type, from the curated AI-stack
taxonomy (which works even with the database down) merged with the corpus
vocabulary, rebuilt a few times a day rather than queried per keystroke.

### When the corpus has never heard of it

The feed accumulates forward from the day it started storing, so for most
software the last CVE predates the corpus entirely — and "no results" for a
product name reads as "nothing is wrong with it", which is the worst way for a
vulnerability feed to be wrong.

So a name query that returns little or nothing is looked up against the
registers once, kept, and answered properly from then on:

```bash
curl 'localhost:3000/api/feed?q=defectdojo'   # 4 records, oldest from 2023
```

Cached for twelve hours including the misses, and rate-limited through a
shared token bucket, so a spray of distinct terms cannot drain the upstream
budget. A **CVE identifier** resolves the same way, from every register in
parallel, so Log4Shell comes back as readily as something published this
morning.

```bash
curl 'localhost:3000/api/feed?q=CVE-2021-44228'
curl 'localhost:3000/api/cve/CVE-2021-44228'
```

Looked-up records are marked `outsideWindow`: they stay out of the browsable
listing, which is meant to be *current* disclosures, but they are found by
search, which is meant to be everything known.

## Dependency check

[`/dependencies`](https://cve.zerocrew.in/dependencies), `POST /api/dependencies/check`,
or `check_dependencies` over MCP.

Free-text search cannot answer "is my dependency vulnerable", and it is worth
being plain about why: it has no ecosystem (npm `zip` and crates.io `zip` are
unrelated software), no version awareness (4.17.21 is fine where 4.17.15 is
not), and no way to ask about ninety packages at once.

So this resolves **coordinates** through [OSV.dev](https://osv.dev) — the
database the ecosystems themselves publish into — then adds the thing OSV does
not have and `npm audit` cannot tell you: whether an exploit actually exists.

```bash
curl -X POST localhost:3000/api/dependencies/check \
  -H 'Content-Type: application/json' \
  --data "{\"manifest\": $(jq -Rs . < package-lock.json)}"
```

Reads `package.json`, `package-lock.json`, `yarn.lock`, `requirements.txt`,
`poetry.lock`, `Pipfile.lock`, `go.mod`, `Cargo.lock`, `Gemfile.lock` and
`composer.lock`. A lockfile is much better than a manifest — a manifest states
ranges, which have to be coerced to their floor, and findings from one are
flagged approximate.

The answer leads with `patchFirst`: what to upgrade, to what version, and why.
Both halves are cached in MongoDB, so re-checking the same lockfile in CI is
nearly free.

## Storage

**MongoDB is the architecture, not an add-on.** It is what makes the corpus
accumulate instead of ageing out of a rolling window, what lets a CVE fetched
once stay fetched, and what keeps a cheap shared host from holding the data at
all. The app still runs without it, degraded and honest about it.

The live instance runs on **MongoDB Atlas M0** — the free tier — which is the
point: none of this needs a cluster you pay for.

**Without `MONGODB_URI`** everything is in the process: the feed is an array,
the exploit index is an object, and requests filter and count by scanning them.
Simple, no infrastructure, and the footprint grows with the data.

**With `MONGODB_URI`** the records and the exploit signals live in the
database, which does the filtering, sorting, paging and counting. The host
keeps a page of results and nothing else.

| | In memory | On MongoDB |
| --- | --- | --- |
| Resident memory, at rest | 82 MB | **84 MB** (75 MB warm) |
| Disk | 11.8 MB | **8 KB** |
| Data held on the host | 22.9 MB | ~0 |
| Grows as records accumulate | yes | no |

The memory saving is smaller than it looks and worth being precise about: the
driver and its TLS cost roughly 20 MB, which almost cancels the 23 MB of data
it removes. Pool size and compression make no difference — 1 socket or 5, zlib
or none, it measures the same. **The real win is that nothing scales with the
data**, and that a database makes the feed stop forgetting: records accumulate
instead of ageing out of a seven-day window, so a CVE keeps its page after it
drops out of the fetch.

### Web workers only read; cron refreshes

A refresh downloads five registers and parses ~27 MB of exploit catalogues.
Measured, it peaks at **475 MB** — and V8 does not hand that memory back
afterwards, so a web worker that refreshes once stays that size for the rest of
its life.

So with a database configured, **web workers never refresh**. They serve
records straight from Atlas and read a ~3 KB summary of the last refresh from
the `meta` collection. Refreshing belongs to `scripts/refresh.js`, a
short-lived process that takes the peak and then exits, returning the memory
with it.

| | before | read-only worker |
| --- | --- | --- |
| Cold boot | 173 MB | **84 MB** |
| Under sustained load | spikes to 270 MB+ on refresh | plateaus ~130–150 MB |
| Refresh peak | inside a worker, permanently | in a process that exits |

This means **a cron job is required**. Without one the data stops updating —
and `/healthz` says so rather than staying quietly green:

```json
"refresh": { "mode": "external", "stale": true,
             "problem": "The last refresh is older than expected; check the cron job." }
```

`feedAgeSeconds` is measured from when the data was generated, not from when a
worker last looked — otherwise a dead cron job would read as fresh forever.

Set `WEB_REFRESH=true` to let workers refresh themselves again, for hosts with
no cron. Expect the memory to follow.

#### Setting up cron on Hostinger

**1. Give cron the environment.** Variables set in the Node.js app panel are
injected into the web app only — cron never sees them. The refresh script reads
a `.env` file from the app directory, so create one there (it is gitignored,
and `chmod 600` it):

```bash
MONGODB_URI=mongodb+srv://...
MONGODB_DB=cvefeed
NVD_API_KEY=...
GITHUB_TOKEN=...
```

Without `MONGODB_URI` the refresh runs but writes nowhere the workers can see,
and `/healthz` flags the feed as stale within the hour.

**2. Find Node.** Over SSH, in the app directory:

```bash
ls -d /opt/alt/alt-nodejs*/root/usr/bin/node
```

Use the one matching the version selected in the Node.js app panel.

**3. Add two jobs** in hPanel → Advanced → Cron Jobs, substituting your paths:

```bash
*/30 * * * * cd /home/USER/domains/cve.zerocrew.in/APP_DIR && /opt/alt/alt-nodejs24/root/usr/bin/node scripts/refresh.js >> refresh.log 2>&1
17 */12 * * * cd /home/USER/domains/cve.zerocrew.in/APP_DIR && /opt/alt/alt-nodejs24/root/usr/bin/node scripts/refresh.js --exploits >> refresh.log 2>&1
```

Every 30 minutes for the feed is plenty for a CVE feed and halves the cost of
every 20. The exploit catalogues change slowly, so twice a day — offset to
minute 17 so the two never run at once and stack their peaks.

**4. Check it took.** After the first run, `/healthz` should show
`"refresh": {"mode": "external", "stale": false}` and a small `feedAgeSeconds`.
`refresh.log` holds each run's per-source results and peak memory.

### What goes where

| Collection | Holds | Written by | Expires |
| --- | --- | --- | --- |
| `cves` | One merged record per vulnerability, with `firstSeen`, `lastSeen` and the names it can be found by | each refresh and each lookup | never |
| `exploit_signals` | One per CVE that has any, with links | the exploit refresh | 60 days |
| `pocs` | Community submissions, held for review before publication | visitors | 60 days |
| `osv_queries` | What OSV said about one package coordinate | dependency sweeps | 6 hours |
| `osv_vulns` | One OSV advisory, trimmed to what a sweep reports | dependency sweeps | 14 days |

Everything that can grow without bound has a TTL index, so Atlas expires it
rather than the free tier filling up.

Indexes are created on first use and **fail loudly**: each one is created
individually, a failure is logged and surfaced in `/healthz`, and the text
index is checked against the spec in the source and reported if it has drifted
— never silently recreated, because dropping it would make every `$text` query
error until it was rebuilt.

`/healthz` and `feed_status` both report how much of the corpus is searchable
by name. That number climbs as records are re-ingested rather than being
complete on day one, and saying so is the difference between "not vulnerable"
and "not enriched yet".

## Community proofs of concept

Every CVE page takes a community proof of concept. It is contribution
infrastructure for *published* vulnerabilities — think Exploit-DB, not a
marketplace — and it is built to be safe to run in public:

- **Text only.** No file uploads; there is nothing to host or scan. The body is
  validated as plain text (binary pastes rejected) and always rendered escaped,
  inside `<pre>`, as data.
- **Reviewed before it appears.** A submission is stored `pending` and is never
  shown publicly until a moderator approves it (`POC_AUTO_APPROVE` exists for a
  trusted private instance and defaults off). Approve via the token-protected
  `GET /api/pocs/pending` and `POST /api/pocs/:id/approve`.
- **Gated.** A CAPTCHA (Cloudflare Turnstile when configured, a built-in signed
  challenge otherwise), a honeypot field, a per-IP hourly cap, and the global
  rate limiter all stand in front of it.
- **Validated hard.** Published-CVE id required, length bounds, http(s)-only
  references, six mandatory legal acknowledgements, and a chosen licence.
- **Private contact stays private.** A contact is kept for the moderator and is
  never returned by the public API or shown on the page.
- **De-duplicated and serialised** in Atlas (`pocs` collection), one document
  per submission, fingerprinted so the same PoC cannot be stored twice.

Legitimate ways to be *paid* for vulnerability research — bug bounty platforms,
vendor programs, competitions — are at [`/earn`](src/pages/earn.js), framed with
the legal boundary stated plainly: **this platform does not buy, sell, or broker
exploits.** The submission and use terms are at [`/terms`](src/pages/legal.js).

## Rate limiting

Two kinds, for two problems.

**Per-IP limits** on the public surface, so one caller cannot flood the API,
the MCP endpoint or the database. Each returns `429` with `Retry-After` once a
client exceeds its window; static assets and `/healthz` are exempt. Defaults
are generous (`API_RATE_MAX` 120/min, `MCP_RATE_MAX` 60/min, `PAGE_RATE_MAX`
240/min) and every one is tunable, or set to `0` to disable.

**A shared budget for the upstream lookup fan-out.** Resolving a CVE outside
the window calls four registers at once, and one of those calls spends from
GitHub's anonymous **60-requests-an-hour-per-IP** budget — which belongs to the
whole host, not just this app. A spray of distinct CVE ids could drain it and
break the feed's own GitHub refresh. A token bucket (`LOOKUP_BURST` 15, then
`LOOKUP_REFILL_PER_SEC` 0.2) caps the fan-out; a declined lookup reads as "not
found", and is deliberately not cached so it retries once the bucket refills.

This is in-process, so it resets on restart and does not coordinate across
workers — right for casual abuse and crawler politeness. A determined attacker
is a job for the edge (Cloudflare in front of the domain).

### Looked-up CVEs are cached in the database

The feed only fetches a recent window, so a search for an older CVE resolves it
live from the registers. With MongoDB configured, that resolved record is
**written to the store** (flagged `outsideWindow`, so it stays out of the
browsable window and the counts, but is found by id). The next request for it
is one database read instead of a four-source fan-out — so each old CVE is
searched upstream at most once, ever, rather than re-fetched every six hours and
on every redeploy. Measured: a cold lookup ~2.4s, the same lookup afterwards
~35ms.

## Exploit availability

CISA KEV answers "is this being exploited?" and EPSS answers "is it likely to
be?". Between them sits the question that usually decides what gets patched
this afternoon: **can someone run an exploit today?**

| Signal | Source | Means |
| --- | --- | --- |
| In the wild | CISA KEV, VulnCheck KEV | Exploitation has been observed |
| Metasploit | Metasploit Framework | A module exists, so it is point-and-click |
| Exploit-DB | Exploit-DB | An exploit is archived and downloadable |
| Public PoC | PoC-in-GitHub | Proof-of-concept code is published |
| Scanned for | Nuclei templates | A detection template exists, so the internet is scanned for it at scale |

Each signal carries **links to the exploit itself** — the Metasploit module on
Rapid7, the Exploit-DB entry, the Nuclei template on GitHub. Public PoC
repositories are fetched per CVE when you open a record, sorted by stars, since
resolving eleven thousand of them up front to populate an index nobody reads
would be absurd.

Filter with `exploit=poc,metasploit,...`, or `maturity=` for a minimum rung of
the ladder (`observed`, `weaponized`, `public-exploit`, `proof-of-concept`),
which also returns everything above it. `sort=exploitability` leads with
whatever is most reachable.

In a typical week this roughly doubles the records carrying actionable exploit
intelligence — not from Exploit-DB, which archives older vulnerabilities and
barely intersects a rolling window, but from public PoCs, which appear within
days of disclosure.

**Absence is not a negative.** A source that is unreachable removes its signal
and nothing else, and the dashboard says so rather than letting "nothing found"
read as "nothing exists". `npm run test:exploits` covers that contract: total
network failure, a single source 500ing, a changed file format, a hung
download, and the claim that a missing source never becomes a `false`.

The downloads total roughly 27MB, so they cache far longer than the feed
(`EXPLOIT_TTL_HOURS`, default 12) and run under a budget
(`EXPLOIT_BUDGET_SECONDS`, default 25) after which the feed is served without
them; they attach on the next refresh. Set `GITHUB_TOKEN` in production —
unauthenticated GitHub allows 60 requests an hour per IP, shared with every
other site on a shared host. `VULNCHECK_TOKEN` is optional and free, and adds a
considerably wider view of observed exploitation than CISA's.

## The AI stack

Vulnerabilities in the software agents are built on get their own facet:
inference servers, agent frameworks, MCP servers, vector stores, MLOps
platforms, model runtimes and chat interfaces. Pick a category, or use **Only**
to narrow the whole feed to the stack.

This is not a keyword search. Grepping descriptions for "ray", "dify" or
"agent" returns array, modify and user agent, so [`src/stack.js`](src/stack.js)
matches structured fields first - exact package names from GitHub advisories
(`vllm`, `@modelcontextprotocol/sdk`), then vendors from KEV and EUVD - and
falls back to word-bounded prose only for records that carry neither. Names too
ambiguous to stand alone need a qualifier: `ray serve`, never a bare `ray`.

A typical week turns up a few dozen, four of them already on CISA's
known-exploited list. Adding a project is one entry in the `SUBJECTS` table.

## Pages

The dashboard is a client-side app, which means a crawler, a link preview and
`curl` all see an empty shell. These pages are rendered on the server and are
complete without JavaScript:

| Path | What it is |
| --- | --- |
| `/cve/:id` | One page per vulnerability, merging what every source says, with `TechArticle` and `BreadcrumbList` structured data |
| `/ai-stack` | The AI-stack overview and its categories |
| `/ai-stack/:category` | One page per category, listing what is currently disclosed |
| `/exploited` | Everything CISA has confirmed is being exploited |
| `/mcp` | The page for agents — served here when a browser asks for HTML, the protocol when an MCP client does |
| `/robots.txt`, `/sitemap.xml` | Generated from the live feed |

Unknown paths return a real 404. Serving the dashboard for every address would
answer 200 for anything on the domain, which is an unbounded supply of
near-duplicate pages for a crawler to find.

Set `SITE_URL` in production: canonical URLs, sitemap entries and Open Graph
tags need an absolute origin, and behind a TLS-terminating proxy the request's
own scheme is `http`.

## MCP

`POST /mcp` speaks the Model Context Protocol over Streamable HTTP, so an agent
can query the feed as a tool instead of scraping the page. No key, no account.

| Tool | Does |
| --- | --- |
| `check_dependencies` | **Paste a lockfile.** Resolves every package at its exact version and orders the findings by whether exploit code exists |
| `search_cves` | Filter by package or vendor name, free text, severity, CVSS, EPSS, exploitation, exploit maturity, AI-stack category or recency. Paginated |
| `get_cve` | One vulnerability in full by CVE, GHSA, EUVD or advisory ID, with community PoCs. Anything unseen is fetched live and kept |
| `get_exploits` | The exploit picture for one CVE on its own: maturity, evidence, and links to the Metasploit module, Exploit-DB entry, Nuclei template and PoC repos by stars |
| `list_exploited` | What CISA confirms is being exploited right now, optionally scoped to the AI stack |
| `feed_status` | What is stored, which registers answered, whether the database or the degraded fallback is serving, and how much of the corpus is searchable by name |

```bash
claude mcp add --transport http cvefeed https://cve.zerocrew.in/mcp
```

Ask it things like *"are any of our dependencies exploitable?"*, *"what landed
overnight that changes my plan?"* or *"can CVE-2021-44228 actually be
exploited, and with what?"*

Two decisions worth knowing about.

**Responses are shaped for agents, not for completeness.** Twenty records cost
~1,800 tokens rather than the ~12,100 the equivalent REST payload would, an 85%
saving, because tools return a trimmed record. `detail: true` opts back into
descriptions, CVSS vectors, CWEs, KEV guidance and reference URLs.

**Advisory text is labelled untrusted, and reference URLs are not fetched.**
CVE descriptions are third-party prose and references point at arbitrary pages,
so every tool result carries a notice telling the agent to treat the content as
data rather than instructions. A vulnerability feed is a poor thing to turn into
an injection path.

The protocol is implemented directly rather than through the official SDK, which
pulls seventeen transitive dependencies including a second major version of
Express. `npm run test:mcp` checks conformance against the real SDK client, as a
dev dependency that never ships.

**Exploit material is for authorised testing only.** Point this at systems you
own or have written permission to test.

`GET /llms.txt` describes all of this in prose, for agents handed only a domain.

## Dashboard

- **Triage-first ordering** — actively exploited vulnerabilities, then CVSS, then recency
- **Filters** for severity, source, AI-stack category, time window, exploited-only, and free-text search across IDs, vendors, products, CWEs and descriptions
- **Shareable URLs** — every filter is reflected in the query string
- **Source health** pills in the header show which feeds responded, with counts and latency
- **Expandable rows** with the CVSS vector, EPSS likelihood, KEV required action, references and per-source links
- **Copy what you came for** — the identifier, the CVSS vector, any reference URL, a permalink, or the whole advisory as Markdown for a ticket
- Light/dark themes, keyboard search (`/`), and a responsive layout

## Configuration

Everything is optional. See [`.env.example`](.env.example) for the full list.

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `3000` | Listen port. Hostinger sets this for you. |
| `SOURCES` | all five | Comma-separated subset, e.g. `nvd,kev`. |
| `CACHE_TTL_MINUTES` | `20` | How long a fetch is reused. |
| `STALE_WHILE_REVALIDATE_MINUTES` | `360` | How far past the TTL a snapshot is still served instantly while it refreshes behind the request; `0` blocks on every expiry instead. |
| `REFRESH_INTERVAL_MINUTES` | `20` | Background refresh cadence; `0` disables it. |
| `NVD_DAYS` | `7` | Publication window pulled from NVD (1–120). |
| `NVD_MAX_PAGES` | `2` | 500 CVEs per page. Raise for a deeper feed. |
| `KEV_DAYS` | `90` | Drop KEV-only entries older than this; `0` keeps the full catalog. |
| `NVD_API_KEY` | — | [Free key](https://nvd.nist.gov/developers/request-an-api-key); raises the limit from 5 to 50 req/30s. |
| `GITHUB_TOKEN` | — | Raises the advisories limit to 5000 req/hour. |
| `MONGODB_URI` | — | Move records and exploit signals off the host. Unset keeps everything in memory. |
| `MONGODB_DB` | `cvefeed` | Database name. |
| `MONGODB_POOL_SIZE` | `5` | The driver defaults to 100 sockets. |
| `CACHE_MAX_ENTRIES` | `500` | Cap on per-CVE cache entries, in memory and on disk. |
| `DISK_CACHE` | `true` | Keep a JSON snapshot in `.cache/` so restarts are instant. |
| `REFRESH_TOKEN` | — | Enables `POST /api/refresh`. Unset = endpoint disabled. |

### Why a database is optional

Every record is derived from an upstream feed, so the feeds *are* the source of
truth and nothing stored here is irreplaceable. That is why the app runs with
no database at all: drop the cache, or drop the collections, and the next
refresh rebuilds them. No migrations, nothing to back up.

A database earns its place for two reasons rather than durability. It keeps the
data off a host you are paying for by the megabyte, and it lets the feed
accumulate instead of forgetting whatever aged out of the fetch window. If
neither matters to you, leave `MONGODB_URI` unset and the app behaves exactly
as it always did.

## API

All endpoints return JSON.

| Endpoint | Description |
| --- | --- |
| `GET /api/feed` | Merged, filtered, paginated feed with stats and source health |
| `GET /api/stats` | Summary counts only |
| `GET /api/sources` | Configured sources and their metadata |
| `GET /api/stack` | The AI-stack categories the feed classifies against |
| `GET /api/exploit-sources` | What each exploit signal means, and whether its source is answering |
| `GET /api/cve/:id` | One record by CVE, GHSA, EUVD or advisory ID, falling back to a direct source lookup |
| `GET /api/cve/:id/pocs` | Approved community proofs of concept for a CVE |
| `POST /api/cve/:id/pocs` | Submit a PoC (text, CAPTCHA-gated, held for review) |
| `GET /api/pocs/pending`, `POST /api/pocs/:id/{approve,reject}` | Moderation (token-protected) |
| `POST /api/refresh` | Force a refetch (requires `REFRESH_TOKEN`) |
| `GET /healthz` | Liveness, cache age, and the TTL/grace thresholds that give that age its meaning |
| `POST /mcp` | Model Context Protocol endpoint ([see above](#mcp)) |
| `GET /llms.txt` | Prose description of the service for agents |

`GET /api/feed` accepts `q`, `severity` (`critical,high,medium,low,none`),
`source`, `kind` (`cve` / `advisory`), `stack`, `exploit`, `maturity`,
`exploited=1`, `minScore`, `days`, `sort` (`priority`, `newest`, `updated`,
`score`, `epss`, `severity`, `exploitability`), `page` and `limit` (max 100).

An unrecognised `exploit` value returns nothing rather than everything: in a
security tool a typo should look wrong, not look like no filter.

`stack` takes `any` for everything classified, or a comma-separated list of
`inference`, `agents`, `mcp`, `retrieval`, `mlops`, `runtime`, `apps`. Each
classified record carries a `stack` object with its categories and the projects
matched, and `stats` gains `byStack`, `inStack` and `stackExploited`.

```bash
# Actively exploited criticals from the last week
curl 'localhost:3000/api/feed?exploited=1&severity=critical&days=7&limit=5'

# Anything in the AI stack that is already being exploited
curl 'localhost:3000/api/feed?stack=any&exploited=1'

# Not yet catalogued by CISA, but exploit code is public
curl 'localhost:3000/api/feed?maturity=proof-of-concept&exploited=0'

# MCP servers and agent frameworks only
curl 'localhost:3000/api/feed?stack=mcp,agents'
```

## Deployment

See **[DEPLOY-HOSTINGER.md](DEPLOY-HOSTINGER.md)** for step-by-step Hostinger
instructions (shared/cloud Node.js hosting and VPS).

Short version for Hostinger Node.js hosting: upload the repo, set
**Application startup file** to `app.js`, run Install Dependencies, then Start.
Nothing else to configure.

## Updating a deployment

The **data** looks after itself. A background timer refreshes every
`REFRESH_INTERVAL_MINUTES`. A request that arrives once the TTL has expired is
answered from the last snapshot straight away, in milliseconds, and the refetch
runs behind it — so nobody waits on upstream. The page notices, says which
snapshot it is showing, and picks up the new data on its own a few seconds
later.

That only holds while the snapshot is worth showing. Past
`CACHE_TTL_MINUTES + STALE_WHILE_REVALIDATE_MINUTES` — six hours and twenty
minutes by default — the request blocks and waits for a real fetch rather than
quietly serving day-old vulnerability data. Set
`STALE_WHILE_REVALIDATE_MINUTES=0` to always block on expiry.

This matters most on shared hosting, where the app is suspended when idle and
the timer stops with it. The first visitor back still gets an instant page from
the snapshot on disk; the fetch they trigger (~25s cold) happens out of their
way. The cron entry in [DEPLOY-HOSTINGER.md](DEPLOY-HOSTINGER.md) running
`npm run warm` every 20 minutes keeps the data inside its TTL on top of that, so
the snapshot being served is never more than a few minutes behind.

Stale data is always flagged: an amber banner while a refresh is in flight, and
a different one naming the failure if upstream could not be reached at all.

The **code** needs a restart to take effect:

```bash
git pull && npm install --omit=dev && rm -rf .cache && pm2 reload cvefeed
```

On Hostinger Node.js hosting that is Git → Pull, then **Restart** on the Node.js
page. The restart is what re-stamps the asset URLs; without it browsers keep
cached CSS/JS. Clearing `.cache` matters only when an update changes how records
are parsed or merged.

## Notes

- The dashboard is read-only and anonymous; it stores nothing about visitors.
- Severity follows the merged CVSS score. Freshly published CVEs are often
  **Unscored** until NVD finishes analysis — that is expected, not an error.
- Always confirm against the upstream advisory before acting on a record.

## Licence

**[PolyForm Noncommercial 1.0.0](LICENSE)** — source-available, not open
source.

You may read it, run it, self-host it, study it, modify it and share it, for
any **noncommercial** purpose. Personal use, research, study, hobby projects,
charities, schools, universities, public research and safety bodies, and
government all qualify. What you may not do is sell it, offer it as a paid
service, or use it to run a business.

Want to use it commercially? Open an issue and ask.

Earlier releases were published under GPL-3.0-or-later. That grant cannot be
withdrawn — anyone who received those versions keeps their rights to them.
This licence governs this version onward.

### The data is not ours to licence

The vulnerability data this fetches stays under its own sources' terms: NVD and
CISA KEV are US government works in the public domain, GitHub Advisories are
CC-BY-4.0, EUVD is published under ENISA's terms, and OSV records carry the
licences of the databases they come from. Community proofs of concept are
published under the licence each author chose at submission.
