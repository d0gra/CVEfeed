# CVE Feed

A live vulnerability dashboard that aggregates CVE data from five trusted public
sources. **No database, no build step, no API keys required** — it fetches
directly from the upstream feeds and keeps a short-lived cache in memory plus a
small JSON snapshot on disk.

Built to drop onto Hostinger's Node.js hosting with `npm install` + `npm start`.

## Sources

| Source | What it adds | Auth |
| --- | --- | --- |
| [NVD](https://nvd.nist.gov/) | The CVE baseline: descriptions, CVSS v3/v4, CWEs, references | Optional key |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Confirmed in-the-wild exploitation, remediation due dates, ransomware use | None |
| [CISA Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories) | ICS, medical device and alert advisories | None |
| [GitHub Security Advisories](https://github.com/advisories) | Package/ecosystem detail, EPSS, fast publication | Optional token |
| [EUVD (ENISA)](https://euvd.enisa.europa.eu/) | EU vulnerability database, EPSS, independent scoring | None |

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

## Dashboard

- **Triage-first ordering** — actively exploited vulnerabilities, then CVSS, then recency
- **Filters** for severity, source, time window, exploited-only, and free-text search across IDs, vendors, products, CWEs and descriptions
- **Shareable URLs** — every filter is reflected in the query string
- **Source health** pills in the header show which feeds responded, with counts and latency
- **Expandable rows** with the CVSS vector, EPSS likelihood, KEV required action, references and per-source links
- Light/dark themes, keyboard search (`/`), and a responsive layout

## Configuration

Everything is optional. See [`.env.example`](.env.example) for the full list.

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `3000` | Listen port. Hostinger sets this for you. |
| `SOURCES` | all five | Comma-separated subset, e.g. `nvd,kev`. |
| `CACHE_TTL_MINUTES` | `20` | How long a fetch is reused. |
| `REFRESH_INTERVAL_MINUTES` | `20` | Background refresh cadence; `0` disables it. |
| `NVD_DAYS` | `7` | Publication window pulled from NVD (1–120). |
| `NVD_MAX_PAGES` | `2` | 500 CVEs per page. Raise for a deeper feed. |
| `KEV_DAYS` | `90` | Drop KEV-only entries older than this; `0` keeps the full catalog. |
| `NVD_API_KEY` | — | [Free key](https://nvd.nist.gov/developers/request-an-api-key); raises the limit from 5 to 50 req/30s. |
| `GITHUB_TOKEN` | — | Raises the advisories limit to 5000 req/hour. |
| `DISK_CACHE` | `true` | Keep a JSON snapshot in `.cache/` so restarts are instant. |
| `REFRESH_TOKEN` | — | Enables `POST /api/refresh`. Unset = endpoint disabled. |

### Why no database?

Every record is derived from an upstream feed, so the feeds *are* the source of
truth. The app holds the merged result in memory and mirrors it to a single JSON
file. That means no migrations, no credentials, and nothing to provision — and
if an upstream feed goes down, the last good snapshot keeps serving with a
visible "stale" banner.

## API

All endpoints return JSON.

| Endpoint | Description |
| --- | --- |
| `GET /api/feed` | Merged, filtered, paginated feed with stats and source health |
| `GET /api/stats` | Summary counts only |
| `GET /api/sources` | Configured sources and their metadata |
| `GET /api/cve/:id` | One record by CVE, GHSA, EUVD or advisory ID |
| `POST /api/refresh` | Force a refetch (requires `REFRESH_TOKEN`) |
| `GET /healthz` | Liveness and cache age |

`GET /api/feed` accepts `q`, `severity` (`critical,high,medium,low,none`),
`source`, `kind` (`cve` / `advisory`), `exploited=1`, `minScore`, `days`,
`sort` (`priority`, `newest`, `updated`, `score`, `epss`, `severity`), `page`
and `limit` (max 500).

```bash
# Actively exploited criticals from the last week
curl 'localhost:3000/api/feed?exploited=1&severity=critical&days=7&limit=5'
```

## Deployment

See **[DEPLOY-HOSTINGER.md](DEPLOY-HOSTINGER.md)** for step-by-step Hostinger
instructions (shared/cloud Node.js hosting and VPS).

Short version for Hostinger Node.js hosting: upload the repo, set
**Application startup file** to `app.js`, run Install Dependencies, then Start.
Nothing else to configure.

## Notes

- The dashboard is read-only and anonymous; it stores nothing about visitors.
- Severity follows the merged CVSS score. Freshly published CVEs are often
  **Unscored** until NVD finishes analysis — that is expected, not an error.
- Always confirm against the upstream advisory before acting on a record.

## License

MIT
