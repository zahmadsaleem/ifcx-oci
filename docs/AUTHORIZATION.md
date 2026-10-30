# Access and sharing

An account determines which files a person or application can use. The file
browser calls these collections **folders** and their saved editions **versions**.
The command line and API use the OCI terms **repositories**, **artifacts**, and
**tags**. This guide uses those terms when describing the API and its policies.

Each account has a JSON policy defining what it may read or publish. Browser
sessions and share links inherit limits from that policy. OCI clients receive
tokens for specific repositories, and the server checks their effective
permissions on every request.

## Repository names and artifact identity

A repository is a collection of artifact versions, identified by a name such as
`hospital-a/models/architecture`. The registry gives no special meaning to any
component: `hospital-a` can be a project, organization, or another naming
convention chosen by its owner. A policy can cover several such namespaces.

Repositories can contain models, drawings, reports, or other artifact profiles.
The manifest's `artifactType` and its descriptors' media types describe the
content. Applications decide which profiles they can interpret. The server
accepts the OCI image-manifest envelope for arbitrary artifacts; OCI indexes and
referrers are outside its supported API. The experimental viewer opens supported
IFC source artifacts.

Within a repository, a tag names a published version and a digest identifies its
exact manifest bytes. Tags are immutable, so publishing changed content requires
a new tag. A digest reference identifies the same content regardless of its tags.

## JSON grant policies

Account policies and share requests use the same grant objects. A policy document
binds those grants to one registry host and optional port:

```json
{
  "version": 1,
  "registry": "registry.example.com",
  "grants": [
    {
      "repositories": ["hospital-a/**", "bridge-b/**"],
      "tags": ["issued"],
      "actions": ["pull"]
    },
    {
      "repositories": ["hospital-a/models/*"],
      "tags": ["review-*"],
      "actions": ["pull", "push"]
    }
  ]
}
```

The first rule allows reading the `issued` version in repositories below either
namespace. The second allows reading and publishing `review-*` versions in direct
children of `hospital-a/models`.

A rule must match the repository, any tag restriction, and the requested action.
Entries within a list are alternatives; matching rules add their permissions
together. Requests without a matching allow rule are denied. There are no
explicit deny rules, and the only supported actions are `pull` and `push`.

Repository selectors contain names, not complete OCI references. Write a tag in
`tags`, rather than appending `:issued` to a repository selector.

| Repository selector | Matches |
| --- | --- |
| `hospital-a/models/architecture` | That exact repository |
| `hospital-a/models/*` | Direct children of `hospital-a/models` |
| `hospital-a/*/*` | Exactly two components below `hospital-a` |
| `hospital-a/**` | Descendants at any depth, excluding `hospital-a` itself |
| `hospital-a/**/*` | Descendants at any depth, excluding `hospital-a` itself |
| `**` | Every repository |

`*` matches within one component. A standalone `**` matches recursively across
components; a trailing `/**` requires a descendant. Patterns remain anchored to
the complete name, so `hospital-a/**` does not match `hospital-ab/model`.

Tags support `*` within a tag: `["issued"]` selects one exact tag and
`["review-*"]` selects matching version names. Omitting `tags` allows the whole
repository, including untagged manifests. `"tags": ["*"]` allows named versions
only. Empty selector or action lists are invalid; an empty top-level `grants`
list removes all account permissions. Unknown fields and unsupported policy
versions are rejected.

## Enforcement and publication

Repository tokens carry ordinary OCI repository/action scopes. Tag restrictions,
approval limits, and share restrictions remain in the registry's policy layer;
a token's repository scope alone does not override them.

The registry applies those restrictions to tag reads, manifest reads by digest,
and the blobs described by authorized manifests. Knowing a hidden artifact's
digest does not grant access to it. Catalog and tag discovery expose only
published content visible under the caller's policy.

Uploads are bound to their account session or share authorization. A restricted
writer can publish only to an allowed tag and must upload any referenced bytes
it cannot already read. This prevents publishing a hidden blob under a readable
tag merely by knowing its digest. Tag-restricted readers gain access to staged
content only through an authorized published manifest.

Publication enforces immutability atomically:

- A new tag may point to a new or existing manifest digest.
- Repeating the same tag and digest returns HTTP 201 and preserves the original
  publication record.
- A different digest at an existing tag returns HTTP 409 `DENIED`.

Overwriting tags and deleting published content are not supported.

## Account sessions and repository tokens

Browser sign-in approves an account policy once, then obtains repository tokens
as the application needs them:

1. Fetch `GET /oauth/config` and use the advertised Authorization Code flow with
   PKCE S256. Request `subsoil:session` and open the registry's own sign-in page.
2. At consent, the registry captures the account's current rules. The resulting
   session root credential has catalog access and returns those rules in the
   token response's `permissions` field.
3. Exchange that root for a token naming the concrete repository and actions.
4. Send the repository token with artifact requests. Keep the root for token
   exchange, catalog discovery, and share management.

The configuration advertises `session_scope: "subsoil:session"` and
`scoped_token_endpoint: "/token"`. An exchange looks like:

```http
GET /token?scope=repository:hospital-a/models/architecture:pull,push
Authorization: Bearer <session-root>
```

The response contains the intersection of requested and permitted actions, using
standard OCI scopes. Repository access tokens expire within 15 minutes and
cannot mint further tokens. Their expiry is also bounded by the absolute
session or share deadline.

A session's effective permissions are bounded by both the consent-time policy
and the account's current policy. Adding a rule or action requires another
login and approval. Removing permission affects existing tokens too. An approved
wildcard already includes future repositories matching that pattern.

Tab sessions have an absolute eight-hour lifetime. Remembered sessions have a
30-day lifetime and use a rotating `HttpOnly; SameSite=Strict` refresh cookie,
with `Secure` on HTTPS. Refresh does not extend the original deadline or widen
the approval. Applications keep access tokens in memory. Callback registration,
cookie forwarding, and CORS configuration are covered in
[DEPLOYMENT.md](DEPLOYMENT.md#application-login).

Ordinary ORAS login, push, pull, and copy retain the standard Basic/Bearer
challenge flow. `registry:catalog:read` grants listing only. The optional
`subsoil:catalog:grants` extension additionally bundles concrete repository grants
within the caller's approval and current account policy. It omits repository
names outside that approval and does not expand wildcard rules into access.

Repository and tag listings accept Distribution pagination parameters `n` (1–1000)
and `last`, with a `Link` header for the next page. The optional Subsoil `q`
parameter filters names by a case-insensitive substring before paging. Listing
and search results include only authorized content. Tag requests without `n`
retain the unpaged response.

## Opening files in external applications

Registered applications appear under **Open with…** when they support the
selected version's profile. Profile registration determines compatibility;
account and share policies determine access. The
[development guide](DEVELOPMENT.md#register-applications-that-open-files)
describes operator configuration and the `open-artifact/1` contract.

Choose **Open with…** to view files or **Edit with…** to edit them, then select
an application. A single compatible application opens directly. The launcher
uses a fifteen-minute lifetime and derives save access in the source folder
from the account or share policy. The receiving application owns Save As,
destination choices, and version names; the registry checks each publication
against the granted permissions.

A launch pins the selected source manifest by digest. Viewing grants access to
that manifest and its described files. Editing can also request permission to
publish new versions to a chosen repository and tag pattern. Source reads and
destination writes are separate rules: publication permission leaves other
versions unreadable and preserves tag immutability. Opening a published result
uses another authorized launch or an ordinary application connection.

Account holders sign in and explicitly approve the limited application access.
The read-only file browser can prepare an edit request; the fresh approval checks
the account's current publication permissions. Share recipients approve on the
registry's page using browser proof established when they selected the
application. This requires the redeemed share root and stays within all of its
existing permissions. A snapshot share opens its selected content for viewing;
publishing requires a live share that already permits the destination.

The application receives a request ID in its launch URL and starts Authorization
Code with PKCE S256. The request ID alone grants no access. The single-use code
is bound to the application, exact callback, and PKCE challenge. Access and
refresh tokens arrive through the token response and stay in application memory.
Launch sessions use rotating refresh tokens without remembered-login cookies.

The chosen lifetime is between one second and eight hours, bounded further by
the originating session or share's absolute deadline. Refresh preserves that
deadline and the original permission ceiling. Removing account permissions or
revoking a share affects issued launch tokens too. Signing out of the launched
application revokes its own session through `/oauth/revoke`. Each registered
application also has a separate remembered-login cookie for ordinary account
connections; `/oauth/config?client_id=<id>` advertises its cookie name.

## Expiring shares

A share delegates a subset of an approved account policy to anyone holding its
secret. It has its own identity, absolute expiry, and revocation record. Creating
one requires an approved account session root; repository tokens and share
guests cannot administer shares.

The creator chooses how the share relates to repository content:

| Binding | Content access | Actions |
| --- | --- | --- |
| `snapshot` (default) | Authorized manifest digests present at creation and their content | `pull` only |
| `live` | Current and future content matching its grants | `pull`, `push`, or both |

Snapshot shares pin content, so later artifacts do not become readable through
them. Live publishing is an explicit delegation and still requires new version
tags because publication remains immutable.

### Create and manage a share

Send the shared grant shape with a required TTL in seconds:

```http
POST /shares
Authorization: Bearer <account-session-root>
Content-Type: application/json
```

```json
{
  "version": 1,
  "registry": "registry.example.com",
  "grants": [
    {
      "repositories": ["hospital-a/models/architecture"],
      "tags": ["issued"],
      "actions": ["pull"]
    }
  ],
  "binding": "snapshot",
  "ttl": 86400
}
```

The registry checks the requested grants against both the creator's approved
and current permissions. Delegation supports identical patterns, concrete
narrowing, and literal namespace subtrees. Ambiguous glob containment is
rejected. A snapshot must match existing authorized content.

The response includes share metadata, its one-time secret, and a URL such as
`https://registry.example.com/share#secret=<secret>`. Store or deliver that link
securely: it is a credential. The registry persists only the secret's hash.

| Endpoint | Purpose |
| --- | --- |
| `POST /shares` | Create a share and return its secret once |
| `GET /shares` | List the creator's share metadata without secrets |
| `POST /shares/{id}/revoke` | Immediately revoke an owned share |

These endpoints require an account session root in the Authorization header;
they do not use browser cookies. The default maximum lifetime is 30 days and
can be configured with `serve --share-max-age <seconds>`. Each account may have
at most 128 active shares.

### Redeem and use a share

A recipient sends the secret in a POST body:

```http
POST /shares/redeem
Content-Type: application/json
```

```json
{"secret": "<share-secret>"}
```

Redemption returns a short-lived share root credential with `authorization_type`
set to `"share"`, its grant policy in `permissions`, and the absolute expiry.
Exchange that root at `/token` for concrete repository tokens using the same flow as an
account session. Redemption can renew the root only until the share expires;
it never extends the share's lifetime.

The registry landing page removes the URL fragment before redemption. The
experimental viewer also accepts the link in its registry address field, clears
that input before redemption, and keeps credentials only in tab memory. Its
share controls support creation and revocation. Viewer connections remain
limited to the configured loopback registry.

For ORAS, redeem the share and exchange its root first, then pass the repository
token with `--header 'Authorization: Bearer <repository-token>'`. Access tokens
belong in headers and share secrets in POST bodies, never query strings.

### Expiry, revocation, and identity

Signing out of the creator's account does not revoke an issued share. A guest's
sign-out disconnects that client locally. Explicit revocation or absolute expiry
ends share access, including access through tokens already issued for it.
Current account restrictions continue to bound the share throughout its life.
Share state and revocation survive server restart.

Publications made through a share identify the publisher as `share:<id>` and
record its creator separately. Authorized manifest responses expose
`subsoil-registry-publisher`, `subsoil-registry-pushed-at`, `subsoil-registry-share-id`, and
`subsoil-registry-created-by`. Publication records remain separate from immutable
manifest bytes. Session and share token responses advertise the publisher and
timestamp header names in the optional `publication_headers` object, with
`publisher` and `pushed_at` keys. Clients can read those names without depending
on the backend's product identity. These metadata fields are extensions to the
token response, rather than standard OCI provenance.

## Provisioning and deployment

Manage accounts through the CLI, using the same JSON policy model as the API:

```sh
subsoil user add --data /var/lib/subsoil alice
subsoil user grants set --data /var/lib/subsoil alice grants.json
subsoil user grants list --data /var/lib/subsoil alice
subsoil user grants remove --data /var/lib/subsoil alice 12
```

`set` atomically replaces an account's grants. Importing a policy binds the store
to its registry host and optional port; startup rejects a different public
origin. `user add --grant project/model:pull,push` and `user grant` are shortcuts
for exact repository-wide rules.

Shares can also be provisioned locally with the same policy document:

```sh
subsoil share create --data /var/lib/subsoil alice \
  --grants share.json --ttl 86400 --public-url https://registry.example.com
subsoil share list --data /var/lib/subsoil alice
subsoil share revoke --data /var/lib/subsoil alice <share-id>
```

Local creation defaults to snapshot binding; use `--binding live` explicitly
for live content or publishing. Operators must apply the deployment's lifetime
limit when using the local `--share-max-age` option.

Run one server instance per data directory and persist the entire store,
including signing keys, policies, sessions, shares, and artifacts. The storage
format is `subsoil-registry/2`; other experimental formats require a fresh
store. See [DEPLOYMENT.md](DEPLOYMENT.md) for TLS, exact CORS origins, callback
registration, login throttling, and persistent-volume setup.

Authorization uses [OWASP's deny-by-default and every-request checks](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).
Token issuance uses the Distribution [requested/granted scope intersection](https://distribution.github.io/distribution/spec/auth/token/).
The richer policy remains a registry extension; OCI repository scope syntax
and ordinary client behavior remain standard.
