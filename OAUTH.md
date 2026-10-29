# Browser login contract

Applications delegate sign-in and consent to the registry. Only the registry's
browser page collects the existing local account credentials. Applications use
OAuth 2.0 Authorization Code with PKCE S256 and never receive a password.
The existing CLI and independent OCI clients keep their local account login.
The S256 exchange follows [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636).

## Registration and discovery

Start the registry with `--oauth-client-id CLIENT` and one
`--oauth-redirect-uri URL` per permitted application callback. The client ID is
chosen by the operator to match their application, with no client secret. Redirect
URIs are matched exactly, must use HTTPS or loopback HTTP, and cannot contain
credentials, query parameters or fragments. No redirect is enabled by default.
For local development, register the application's actual origin and callback
path, for example `http://localhost:3000/oauth/callback`.
One public client is configured per registry process; additional applications
need separate registration support. There is no built-in application identity.

`GET /oauth/config` returns:

```json
{
  "client_id": "model-client",
  "authorization_endpoint": "http://127.0.0.1:5000/oauth/authorize",
  "token_endpoint": "/oauth/token",
  "revocation_endpoint": "/oauth/revoke",
  "refresh_cookie_name": "ifcx_oci_refresh",
  "session_max_age": 28800,
  "remembered_session_max_age": 2592000,
  "redirect_uris": ["http://localhost:3000/oauth/callback"],
  "code_challenge_methods_supported": ["S256"]
}
```

The authorization endpoint is the registry's own browser origin. The token
endpoint is relative so an application's fixed registry proxy can forward it
without CORS. Proxy `/oauth/config` and `/oauth/token`; keep the application's
registered callback local. Never proxy the credential page under the application
origin.

## Authorization

Open `authorization_endpoint` with `response_type=code`, the configured `client_id`,
the exact `redirect_uri`, a fresh unpredictable `state`, `code_challenge`,
`code_challenge_method=S256`, and space-separated `scope` values. Supported
scopes are `registry:catalog:read` and `repository:NAME:pull,push` (either action
can be requested alone).

The registry validates the request before showing its sign-in/consent form.
Approval returns `redirect_uri?code=OPAQUE_CODE&state=ORIGINAL_STATE`.
Denial returns `error=access_denied&state=ORIGINAL_STATE`. Invalid client or
redirect URIs are rejected locally without redirecting. Authorization forms
expire in five minutes and are bound to a browser cookie. Codes expire in one
minute and can be redeemed once, only by the same client, redirect URI and PKCE
verifier.

The application validates the exact callback origin/path, one state and code, no
fragment, and provider errors. Keep the verifier/state only in the initiating
tab's memory. In browsers with COOP isolation, a same-origin BroadcastChannel
callback can relay the result without relying on the popup's opener reference.
Attach the callback listener before navigating the popup; enforce a five-minute
timeout. Cancellation/sign-out must prevent late replies from restoring a
session.

## Token and session

POST form data to `/oauth/token`: `grant_type=authorization_code`,
the configured `client_id`, `redirect_uri`, `code`, and the corresponding
`code_verifier`. Responses contain `token`, `access_token` (same JWT),
`token_type=Bearer`, `expires_in=900`, `subject` (local account name), and
`access` (the existing exact repository/action grants, plus catalog access when
requested). Requested permissions are intersected with current local grants.
Token responses are not cacheable. Access tokens last at most 15 minutes, and
tab-only sessions have an absolute eight-hour lifetime. Remembered sessions last
30 days across tabs, reloads and browser restarts. Renewal never extends
that deadline or increases the permissions approved at sign-in.

The registry sign-in page offers an unchecked **Remember me for 30 days** option.
Without it, token replies include an opaque `refresh_token` for application
memory only. With it, the refresh token is set only in an HttpOnly,
SameSite=Strict cookie with a 30-day maximum age; it is not exposed in JSON.
Both modes return `remember_me`, `session_expires_at` (Unix seconds) and
`session_expires_in` (remaining seconds). The exact cookie name is
`ifcx_oci_refresh`, with `Path=/oauth/` and `Secure` when the registered application
callback uses HTTPS. It has no Domain attribute. The cookie belongs to the
application's browser origin through its fixed proxy. Only one registry is
connected per application origin.

Renew using POST form data to `/oauth/token`: `grant_type=refresh_token`,
`client_id` and, for memory mode, `refresh_token`. Cookie mode omits that field,
uses browser `credentials: include`, and requires an `Origin` matching the
registered callback origin. Every successful refresh rotates the opaque token.
Replaying a consumed token revokes its whole session, including issued access
tokens. Serialize refresh across tabs with Web Locks, and coalesce concurrent
refresh requests within a tab. Store no refresh tokens in localStorage.
This follows the rotation and replay-detection model in
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2).

Refresh permissions are the intersection of the original approved grants and
current account grants. Added grants require a new sign-in. Removed grants
take effect on data requests and renewal. Refresh-token hashes and sessions
persist in the existing private SQLite store, so server restart does not require
sign-in while the session remains valid.

POST `/oauth/revoke` with `client_id` and `token` for memory mode, or the cookie
for remembered mode. Cookie requests require the same Origin validation.
Revocation clears the cookie and immediately invalidates the session's access
and refresh tokens. Unknown tokens return success. On sign-out, clear local
state immediately, cancel pending login/refresh work and revoke the server
session. Late responses must not restore a signed-out session.

Use `Authorization: Bearer JWT` for `/v2/`. Keep access tokens in memory. Refresh
before expiry or on one 401, retry a data request at most once, and return to
sign-in when the session expires or renewal is rejected. Do not retry writes
after an ambiguous network failure.

For a fixed application proxy, forward cookies and Set-Cookie only on the exact
`/oauth/token` and `/oauth/revoke` routes; `/oauth/config` remains credential-free.
Keep the application's callback local and the credential page on the registry
origin. The registry does not enable cross-origin token requests.

## Existing clients

`/token` remains the OCI Basic-to-scoped-Bearer endpoint for the existing CLI and
ORAS. Browser code must use the new OAuth endpoints exclusively. This is a local
registry authorization server using existing accounts, with no external
identity-provider credentials or configuration.
