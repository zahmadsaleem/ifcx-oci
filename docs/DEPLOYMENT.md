# Cloud test deployment

Run one Subsoil server behind an HTTPS ingress or load balancer, with persistent
storage for its accounts and files. Route the whole hostname to container port
5000 over a private HTTP connection. The ingress handles TLS, so clients use
HTTPS even though the private connection uses HTTP.

Configure DNS and a valid certificate for `registry.example.com`. If another
application connects to Subsoil, register its exact HTTPS callback URL, including
the path and any trailing slash.

## Start the registry

Build the image with `docker build -t subsoil:dev .`. Provision accounts with the
existing CLI by running the same distroless image as a one-off job. Its entrypoint
is the binary; no shell or admin API is needed. These examples use Docker, with
the same `/data` volume and UID/GID **65532:65532** for every job and server:

```sh
docker volume create subsoil-data
docker run --rm -it --user 65532:65532 -v subsoil-data:/data subsoil:dev \
  user add --data /data writer
docker run --rm --user 65532:65532 -v subsoil-data:/data subsoil:dev \
  user grant --data /data writer project/model:pull,push

# Publish only to the local ingress; in a cloud service, use a private backend.
docker run -d --name subsoil-registry --restart unless-stopped --stop-timeout 60 \
  --user 65532:65532 -p 127.0.0.1:5000:5000 -v subsoil-data:/data subsoil:dev \
  serve --data /data --listen 0.0.0.0:5000 \
  --public-url https://registry.example.com \
  --oauth-client-id model-client \
  --oauth-redirect-uri https://app.example.com/oauth/callback
```

For a noninteractive cloud job, use `user add --password-stdin` and pipe a password
from your secret manager into its standard input. Passwords require at least 12
characters. `user add --grant project/model:pull,push` also provisions grants in
one job; `user grant` can add permissions later against the same mounted volume.

For repository wildcards, tag restrictions, and expiring shares, use the JSON
policy model described in [AUTHORIZATION.md](AUTHORIZATION.md). Imported policies
are bound to the deployment's public registry host.

New persistent disks must be empty and writable by UID 65532; initialize ownership
through the platform's volume setup. Do not mount a root-owned disk over `/data`
without arranging that ownership.

## Storage and replacement

Persist **all of `/data`**, including `registry.json`, `auth.sqlite` (accounts,
policies, browser sessions and shares), `signing.key`, `blobs/` and `repositories/` (including
uploads). Keep this volume when replacing the container, and supply the same
public URL and OAuth registration to its replacement. Back up the whole directory
with the server stopped or using a consistent volume snapshot. The Docker smoke
check below verifies that accounts, grants, remembered sessions, existing bearer
tokens and pushed artifacts survive replacement on the same volume.

The store uses format `subsoil-registry/2`. Start with a fresh directory when
using a different experimental store format.

## Application login

The public URL is an origin without credentials, path, query or fragment. It
controls authorization links, password-form Origin checks and the OCI Bearer
realm. Host and forwarded headers do not select it. HTTPS public URLs require
HTTPS callbacks; callbacks are matched exactly. HTTP is supported only with a
loopback public URL for local development. Non-loopback listeners require an
explicit public URL.

For browser applications, fetch `/oauth/config` and use Authorization Code with
PKCE S256 and request `subsoil:session`. Exchange the approved session root at
`/token` for concrete repository tokens before making artifact requests. The
password page is on the registry's public origin.

Proxy the application's `/oauth/token` and `/oauth/revoke` routes to the registry
routes of the same name. Preserve the browser's `Origin` (the registered callback's origin),
`Cookie`, form body, response status and `Set-Cookie`; do not replace Origin with
the private backend address or enable arbitrary cross-origin proxy requests.
Remembered login uses a rotating `HttpOnly; Secure; SameSite=Strict` cookie scoped
to `/oauth/`; keep those application routes under that path and serve them over
HTTPS. The proxy makes the cookie belong to the application, so refresh works
without third-party cookies. Keep access tokens in memory; remembered refresh
credentials are omitted from JSON. Consent cookies on the HTTPS registry are
also Secure even though the private hop uses HTTP.

## Direct browser access with CORS

CORS is disabled by default. Add `--cors-origin https://app.example.com` to the
`serve` command to let that application call the registry directly; repeat the
option for more trusted origins. Each entry must be an exact HTTPS origin (or
loopback HTTP for development), without credentials, a path, query or fragment.
Wildcards and `null` origins are rejected. OAuth callback registration remains
separate and still requires the exact callback URL.

Allowed origins receive CORS headers on `/v2`, `/v2/…`, `/token`, `/oauth/config`,
`/oauth/token`, `/oauth/revoke` and `/shares` routes, including error responses and unauthenticated
OPTIONS preflights. GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS are allowed,
with Authorization, Accept, Content-Type, Content-Range and Range request headers.
The browser can read WWW-Authenticate, Location, Link, Range, Content-Range,
Retry-After, Docker-Content-Digest, Docker-Distribution-API-Version,
Docker-Upload-UUID and the subsoil-registry publication headers. Responses vary by
Origin and the preflight method/headers. The registry password/consent page and
health probes do not receive CORS access; sign-in still opens the registry's page.
CORS does not replace bearer-token authorization or grant repository permissions.

Direct browser clients can use PKCE with a memory-only session. Credentialed
requests are permitted for allowlisted origins, but refresh cookies retain
`HttpOnly; SameSite=Strict` (and Secure on HTTPS): CORS does not make a cookie
available across unrelated sites. Keep the application token/revoke proxy above
for reliable remembered login across sites. This option does not change cookie
policy or bypass browser restrictions on HTTPS pages accessing local HTTP servers.

## Health and shutdown

Use unauthenticated `GET /healthz` for liveness and `GET /readyz` for readiness.
They return empty bodies: 200 when healthy, or 503 when database/storage readiness
fails. Readiness checks a database write transaction and temporary file I/O in
the data and artifact directories. Configure a modest probe interval such as 10
seconds. On SIGTERM or Ctrl+C the server stops accepting connections and drains
active requests; allow enough shutdown time for uploads (the example allows 60
seconds).

## Deployment limits

Browser password login and OCI/CLI `/token` login share an in-memory limit of
5 failed attempts per account per minute. Successful password verification does
not consume this account budget or clear earlier failures. In-flight attempts
reserve account slots so parallel failures cannot bypass the limit. A separate
global limit counts all attempts, including successes, at 60 per minute to bound
password-verification work. These limits are keyed by account, never untrusted
forwarded IP headers, following [OWASP's account-based failed-login guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#login-throttling).
Throttled attempts return 429 with `Retry-After`. Restart clears these budgets;
apply ingress request limits too for an internet-facing test service.

Share TTL is capped by `--share-max-age <seconds>` (default 2592000, or 30 days),
with at most 128 active shares per creator. Tags are immutable; publishing changed
content requires a new tag. Overwrite and published deletion are not supported.

Keep replica count at **one**, including during replacement (use a recreate
strategy). Pending OAuth requests and authorization codes are in memory and are
lost on restart; users can restart sign-in. Storage mutations use a server-local
lock and assume one server, so a shared volume does not make replicas safe.
One-off account jobs use SQLite transactions; they are not additional servers.
Use the CLI for account administration. There is no account administration API
for password resets, disabling accounts, or revoking sessions administratively.

## Verify the deployment

Verify the image and a real TLS ingress/application proxy locally:

```sh
cargo test --locked --test deployment --test oauth_sessions --test showcase
docker build -t subsoil:cloud-test .
python3 tests/cloud_smoke.py subsoil:cloud-test
```

The smoke check requires Docker, Python 3 and `openssl`, trusts its temporary
localhost certificate, and removes its test containers and volume. Against your
deployed hostname, use the [login, push and pull examples](../README.md#share-your-own-model-locally)
with `registry.example.com` and omit `--plain-http`.
