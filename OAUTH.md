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
Token responses are not cacheable. There is no refresh token.

Use `Authorization: Bearer JWT` for existing `/v2/` operations. Keep the token in
tab memory, retain the 15-minute expiry, and clear it on sign-out or a 401.
Sign-out is local session disposal; already issued JWTs expire normally.
Applications decide when closing a view should preserve or discard their token.

## Existing clients

`/token` remains the OCI Basic-to-scoped-Bearer endpoint for the existing CLI and
ORAS. Browser code must use the new OAuth endpoints exclusively. This is a local
registry authorization server using existing accounts, with no external
identity-provider credentials or configuration.
