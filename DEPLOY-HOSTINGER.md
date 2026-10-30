# Deploying on Hostinger

The app is deliberately boring to deploy: plain Node.js, no build step, no
database, no environment variables required. Pick the path that matches your
plan.

---

## Option A — Hostinger Node.js hosting (Premium / Business / Cloud)

This is the easiest route. Hostinger runs the app behind Passenger, so you only
point it at the entry file.

### 1. Get the code onto the server

**Via Git (recommended)** — in hPanel: **Website → Git**, add your repository
URL and branch, and deploy into a directory such as `cvefeed`.

**Or via File Manager / FTP** — upload the project, but **do not upload
`node_modules`**; Hostinger installs it for you.

### 2. Create the Node.js app

In hPanel go to **Advanced → Node.js** and click **Create application**:

| Field | Value |
| --- | --- |
| Node.js version | **22.x** (or any 18.17+) |
| Application mode | **Production** |
| Application root | the folder you deployed into, e.g. `cvefeed` |
| Application URL | your domain or subdomain |
| **Application startup file** | **`app.js`** |

`app.js` sits at the project root precisely because Passenger looks for it
there by default.

### 3. Install dependencies

On the same Node.js page click **Install Dependencies** (it runs `npm install`
against `package.json`). Wait for it to finish.

### 4. Start it

Click **Start** (or **Restart**). Open your domain — the dashboard loads
immediately and fills in as the feeds arrive, which takes 20–30 seconds on the
very first boot.

### 5. Optional: environment variables

Still on the Node.js page, use **Environment variables** to add any of these.
All are optional.

| Variable | Why you might set it |
| --- | --- |
| `NVD_API_KEY` | A [free NVD key](https://nvd.nist.gov/developers/request-an-api-key) raises the rate limit from 5 to 50 requests / 30s, making refreshes faster and more reliable on a busy shared IP. |
| `GITHUB_TOKEN` | Any read-only PAT raises the GitHub advisories limit to 5000 req/hour. |
| `NVD_MAX_PAGES` | Raise to `4`–`6` for a deeper feed if your plan has the CPU budget. |
| `CACHE_TTL_MINUTES` | Increase to `60` to be gentler on upstream feeds and your CPU quota. |
| `STALE_WHILE_REVALIDATE_MINUTES` | Default `360`. How long an idle app may answer from its last snapshot while refreshing behind the request, so the first visitor back never waits. |

Do **not** set `PORT` — Hostinger assigns it, and the app reads it
automatically.

> **Shared-hosting tip:** these plans suspend idle apps. The app re-warms itself
> on the next request from its disk snapshot, so the dashboard still appears
> instantly. For an always-warm feed, add a cron job (**Advanced → Cron Jobs**)
> running every 20 minutes:
>
> ```bash
> cd ~/domains/yourdomain.com/public_html/cvefeed && /opt/alt/alt-nodejs22/root/usr/bin/node scripts/warm-cache.js
> ```
>
> Adjust the path to match your Node version and app root.

---

## Option B — Hostinger VPS

You get a full OS, so run it under PM2 behind Nginx.

```bash
# 1. Node 22
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs nginx git

# 2. App
sudo mkdir -p /var/www && cd /var/www
sudo git clone <your-repo-url> cvefeed && cd cvefeed
sudo npm install --omit=dev

# 3. Keep it running
sudo npm install -g pm2
pm2 start ecosystem.config.cjs
pm2 save && pm2 startup     # run the command it prints
```

Reverse proxy — `/etc/nginx/sites-available/cvefeed`:

```nginx
server {
    listen 80;
    server_name yourdomain.com;

    location / {
        proxy_pass         http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/cvefeed /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# HTTPS
sudo apt-get install -y certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com
```

### Docker on a VPS

```bash
docker compose up -d --build
```

The compose file persists `.cache` in a named volume and passes `NVD_API_KEY` /
`GITHUB_TOKEN` through from your shell or a `.env` file.

---

## Verifying a deployment

```bash
curl https://yourdomain.com/healthz
curl 'https://yourdomain.com/api/feed?limit=1' | head -c 400
```

`/healthz` reports cache age and the configured sources. The dashboard header
also shows a pill per source with its record count, so a feed that is failing is
visible at a glance.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| 503 / "Application failed to start" | Startup file is not `app.js`, or dependencies were never installed. Fix both on the Node.js page and Restart. |
| Dashboard loads but shows no records | The first fetch is still running. Wait ~30s and refresh; the header pills show progress. |
| NVD pill shows "offline" | NVD rate-limited the shared IP (HTTP 403/429). Set `NVD_API_KEY`, or raise `CACHE_TTL_MINUTES`. Other sources keep working. |
| A "stale snapshot" banner | An upstream refresh failed and the last good data is being served. Usually transient. |
| High CPU on a shared plan | Lower `NVD_MAX_PAGES` to `1` and raise `CACHE_TTL_MINUTES` to `60`. |
| Changes not visible after a Git pull | Click **Restart** on the Node.js page; Passenger caches the running process. |
