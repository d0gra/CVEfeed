# CVE Feed

A live vulnerability dashboard that aggregates CVE data from five trusted public
sources. **No build step, no API keys required.** It runs with no database at
all, holding the feed in memory with a JSON snapshot on disk — or, pointed at a
MongoDB instance, [keeps almost nothing on the host](#storage).

Vulnerabilities in the AI and agent stack - inference servers, agent
frameworks, MCP servers, vector stores - get [a facet of their own](#the-ai-stack),
and the whole feed is [consumable by agents over MCP](#mcp).

Built to drop onto Hostinger's Node.js hosting with `npm install` + `npm start`.

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

Free-text search (`cisco`, `CWE-190`, a package name) filters the current
window. A **CVE identifier** is treated differently: if it is not in the window,
`NVD`, `CISA KEV`, `GitHub` and `EUVD` are each asked for that one CVE in
parallel and the answers are merged by the same rules the feed uses, so
Log4Shell resolves as readily as something published this morning.

```bash
curl 'localhost:3000/api/feed?q=CVE-2021-44228'
curl 'localhost:3000/api/cve/CVE-2021-44228'
```

Looked-up records are marked `outsideWindow` and labelled in the UI. They are
cached for six hours, since an old CVE rarely changes. The KEV catalog is
already held in full, so exploitation status, ransomware use and the federal
remediation deadline come back for any CVE at no extra request.

Full-text search across every CVE ever published is deliberately *not*
supported: that needs an index, which means the database this app avoids.

## Storage

The app runs two ways, and the difference is where the data sits.

**Without `MONGODB_URI`** everything is in the process: the feed is an array,
the exploit index is an object, and requests filter and count by scanning them.
Simple, no infrastructure, and the footprint grows with the data.

**With `MONGODB_URI`** the records and the exploit signals live in the
database, which does the filtering, sorting, paging and counting. The host
keeps a page of results and nothing else.

| | In memory | On MongoDB |
| --- | --- | --- |
| Resident memory, at rest | 82 MB | **50 MB** |
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

### Keep refreshes out of the web process

Fetching and merging peaks far above anything serving costs — around 120 MB for
the feed and 270 MB while parsing the exploit catalogues. Running that inside
the web process sizes the process for its worst minute. Set
`REFRESH_INTERVAL_MINUTES=0` and let cron own it:

```bash
*/20 * * * * cd /path/to/cvefeed && npm run refresh      # the feed
17 */12 * * * cd /path/to/cvefeed && npm run refresh:all # and exploit signals
```

That at-rest 50 MB assumes this. With in-process refreshing it is roughly 120 MB.

### What goes where

| Collection | Holds | Written by |
| --- | --- | --- |
| `cves` | One document per merged record, with `firstSeen` and `lastSeen` | each refresh |
| `exploit_signals` | One per CVE that has any, with links, expiring after 60 days | the exploit refresh |

Free-text search uses a MongoDB text index, which matches words rather than
substrings — a deliberate difference from the in-memory scan, which could not
survive a growing collection.

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
| `search_cves` | Filter by text, severity, CVSS, exploitation, AI-stack category or recency |
| `get_cve` | One vulnerability by CVE, GHSA, EUVD or advisory ID, with the direct-source fallback |
| `list_exploited` | What CISA has confirmed is being exploited, optionally scoped to the AI stack |
| `feed_status` | Source health, data age and the available categories |

```bash
claude mcp add --transport http cvefeed https://yourdomain.com/mcp
```

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
| `POST /api/refresh` | Force a refetch (requires `REFRESH_TOKEN`) |
| `GET /healthz` | Liveness, cache age, and the TTL/grace thresholds that give that age its meaning |
| `POST /mcp` | Model Context Protocol endpoint ([see above](#mcp)) |
| `GET /llms.txt` | Prose description of the service for agents |

`GET /api/feed` accepts `q`, `severity` (`critical,high,medium,low,none`),
`source`, `kind` (`cve` / `advisory`), `stack`, `exploit`, `maturity`,
`exploited=1`, `minScore`, `days`, `sort` (`priority`, `newest`, `updated`,
`score`, `epss`, `severity`, `exploitability`), `page` and `limit` (max 500).

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

## License

GNU General Public License v3.0 or later - see [LICENSE](LICENSE).

That covers this code. The vulnerability data it fetches stays under its own
sources' terms: NVD and CISA KEV are US government works in the public domain,
GitHub Advisories are CC-BY-4.0, and EUVD is published under ENISA's terms.
