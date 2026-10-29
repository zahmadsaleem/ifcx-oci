# Cloud test deployment

Run **one replica** behind an HTTPS cloud ingress/load balancer. Route the whole
registry hostname to container port 5000 over a private HTTP connection; expose
only HTTPS to clients. The registry does not terminate TLS itself. Configure DNS
and a valid certificate for `registry.example.com`, and register the application's
exact HTTPS callback URL, including its path and trailing slash if present.

## Start the registry

Build the image with `docker build -t ifcx-oci:dev .`. Provision accounts with the
existing CLI by running the same distroless image as a one-off job. Its entrypoint
is the binary; no shell or admin API is needed. These examples use Docker, with
the same `/data` volume and UID/GID **65532:65532** for every job and server:

```sh
docker volume create ifcx-oci-data
docker run --rm -it --user 65532:65532 -v ifcx-oci-data:/data ifcx-oci:dev \
  user add --data /data writer
docker run --rm --user 65532:65532 -v ifcx-oci-data:/data ifcx-oci:dev \
  user grant --data /data writer project/model:pull,push

# Publish only to the local ingress; in a cloud service, use a private backend.
docker run -d --name ifcx-registry --restart unless-stopped --stop-timeout 60 \
  --user 65532:65532 -p 127.0.0.1:5000:5000 -v ifcx-oci-data:/data ifcx-oci:dev \
  serve --data /data --listen 0.0.0.0:5000 \
  --public-url https://registry.example.com \
  --oauth-client-id model-client \
  --oauth-redirect-uri https://app.example.com/oauth/callback
```

For a noninteractive cloud job, use `user add --password-stdin` and pipe a password
from your secret manager into its standard input. Passwords require at least 12
characters. `user add --grant project/model:pull,push` also provisions grants in
one job; `user grant` can add permissions later against the same mounted volume.
New persistent disks must be empty and writable by UID 65532; initialize ownership
through the platform's volume setup. Do not mount a root-owned disk over `/data`
without arranging that ownership.

## Storage and replacement

Persist **all of `/data`**, including `registry.json`, `auth.sqlite` (accounts,
grants and browser sessions), `signing.key`, `blobs/` and `repositories/` (including
uploads). Keep this volume when replacing the container, and supply the same
public URL and OAuth registration to its replacement. Back up the whole directory
with the server stopped or using a consistent volume snapshot. The Docker smoke
check below verifies that accounts, grants, remembered sessions, existing bearer
tokens and pushed artifacts survive replacement on the same volume.

## Application login

The public URL is an origin without credentials, path, query or fragment. It
controls authorization links, password-form Origin checks and the OCI Bearer
realm. Host and forwarded headers do not select it. HTTPS public URLs require
HTTPS callbacks; callbacks are matched exactly. HTTP is supported only with a
loopback public URL for local development. Non-loopback listeners require an
explicit public URL.

For browser applications, fetch `/oauth/config` and use Authorization Code with
PKCE S256. The password page is on the registry's public origin. Proxy the
application's `/oauth/token` and `/oauth/revoke` routes to the registry routes of
the same name. Preserve the browser's `Origin` (the registered callback's origin),
`Cookie`, form body, response status and `Set-Cookie`; do not replace Origin with
the private backend address or enable arbitrary cross-origin proxy requests.
Remembered login uses a rotating `HttpOnly; Secure; SameSite=Strict` cookie scoped
to `/oauth/`; keep those application routes under that path and serve them over
HTTPS. The proxy makes the cookie belong to the application, so refresh works
without third-party cookies. Keep access tokens in memory; remembered refresh
credentials are omitted from JSON. Consent cookies on the HTTPS registry are
also Secure even though the private hop uses HTTP.

## Health and shutdown

Use unauthenticated `GET /healthz` for liveness and `GET /readyz` for readiness.
They return empty bodies: 200 when healthy, or 503 when database/storage readiness
fails. Readiness checks a database write transaction and temporary file I/O in
the data and artifact directories. Configure a modest probe interval such as 10
seconds. On SIGTERM or Ctrl+C the server stops accepting connections and drains
active requests; allow enough shutdown time for uploads (the example allows 60
seconds).

## Deployment limits

Both browser password login and OCI/CLI `/token` login share an in-memory budget
of 5 attempts per account and 60 total attempts per minute, including successes.
Throttled attempts return 429 with `Retry-After`. Restart clears this budget;
apply ingress request limits too for an internet-facing test service.

Keep replica count at **one**, including during replacement (use a recreate
strategy). Pending OAuth requests and authorization codes are in memory and are
lost on restart; users can restart sign-in. Storage mutations use a server-local
lock and assume one server, so a shared volume does not make replicas safe.
One-off account jobs use SQLite transactions; they are not additional servers.
Password reset, account disabling and administrative session revocation are
follow-up CLI work.

## Verify the deployment

Verify the image and a real TLS ingress/application proxy locally:

```sh
cargo test --locked --test deployment --test oauth_sessions --test showcase
docker build -t ifcx-oci:cloud-test .
python3 tests/cloud_smoke.py ifcx-oci:cloud-test
```

The smoke check requires Docker, Python 3 and `openssl`, trusts its temporary
localhost certificate, and removes its test containers and volume. Against your
deployed hostname, use the [login, push and pull examples](README.md#share-your-own-model-locally)
with `registry.example.com` and omit `--plain-http`.
