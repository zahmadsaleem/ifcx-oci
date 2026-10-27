# Developing ifcx-oci

The [README](README.md) covers the purpose and everyday binary commands. This
guide covers building, testing, implementation details and local integration
work. Run commands from the repository root.

## Build and development environment

Nix pins the Rust toolchain, native dependencies and showcase tools through
`flake.lock`. Enable its `nix-command` and `flakes` features before using the
commands below. You can also enable them for a single command, for example:

```sh
nix --extra-experimental-features 'nix-command flakes' build
```

Build the executable and make its binary name available in the current terminal:

```sh
nix build
export PATH="$PWD/result/bin:$PATH"
ifcx-oci --help
```

The executable is at `result/bin/ifcx-oci`. It runs directly, but a Nix-built
executable still needs its platform runtime dependencies from the Nix closure.
Copying the executable alone is not a complete portable installation.

Enter the development environment to use Cargo, rustc, rustfmt, Clippy,
pkg-config, ORAS and jq:

```sh
nix develop
cargo build --locked --release
./target/release/ifcx-oci --help
```

The flake declares macOS and Linux packages for ARM64 and x86-64. The current
showcase has been exercised on macOS ARM64; the other targets have not been
verified here.

`Cargo.lock` pins the Rust dependency graph. The IFClite core, processing and
export crates are pinned to revision
`9d154898de31fe91eb46f0200f2b3634c8c592f1`. IFClite is an MPL-2.0 dependency;
its source and license are in the [pinned repository](https://github.com/LTplus-AG/ifc-lite/tree/9d154898de31fe91eb46f0200f2b3634c8c592f1/rust).
The Nix package source filter includes Cargo and license files, `src/` and
`tests/`, keeping local stores and model inputs outside the package source.

## Checks

Inside `nix develop`:

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

The tests cover actual IFC extraction and geometry, source-schema metadata,
determinism, corrupt payloads, unsafe paths and invalid references. Registry
tests cover uploads, missing blobs, repository membership, persistence,
authenticated transfers and permission denials. Authentication checks include
password hashing, token scope, signature, issuer, audience and expiry.

`nix build` runs the library tests in the build sandbox. Networked integration
tests run through Cargo or the explicit showcase, rather than inside that
sandbox. `nix flake check --no-build` evaluates the flake outputs for the current
system without rebuilding the executable.

For a documentation-only change, compare examples with the relevant binary
`--help`, check links and run `git diff --check`. A full build and showcase are
not needed unless behavior or tooling changes.

## Local showcase and fixtures

The complete Nix showcase supplies the pinned ORAS client automatically:

```sh
nix run .#demo -- --output build/showcase-oras
```

The binary can also run the showcase directly. Without `--oras`, it exercises
the Rust client; supplying an ORAS executable adds independent-client checks:

```sh
ifcx-oci demo --output build/showcase-rust
ifcx-oci demo --output build/showcase-independent --oras /absolute/path/to/oras
```

Each output directory must be new. The generated IFC4 fixture in `src/demo.rs`
contains two placed walls, a shared type, typed properties including zero,
false and null, and a quantity. Conversion uses IFClite's real extraction and
tessellation. The demo starts two registries with independent persistent stores,
users, grants and signing keys, then performs these checks:

1. Obtain repository/action-scoped JWTs through OCI Bearer discovery.
2. Push, copy across registries, pull by digest and verify the derived release.
3. Confirm reader pull access and deny reader push and cross-repository access.
4. Reject expired and invalid tokens.
5. When requested, use ORAS for authenticated push, registry-to-registry copy
   and pull, verify the received files, read an ORAS-produced artifact with the
   Rust client, and deny an ORAS reader push.

The report is written to `<output>/demo-report.json` with actual outcomes and
manifest digests. It does not contain passwords or JWTs. Servers stop when the
demo finishes; stores and received files remain. The ORAS credential directory
is temporary and removed when its check finishes.

To include ORAS in the Cargo integration test, provide its absolute path:

```sh
IFCX_TEST_ORAS=/absolute/path/to/oras cargo test --locked --test showcase
```

Keep private IFC inputs local. Conversion and tests do not publish them. Source
`.ifc` and `.ifczip` files, `build/`, authentication files and registry stores are
excluded by `.gitignore`. The producer includes the source IFC in an artifact
only when `convert --include-source` is requested.

## Implementation

One Rust executable exposes both server and client entry points. The registry
stores opaque manifests and blobs; it does not interpret model semantics. The
converter owns the experimental AEC payload contract. The implementation-neutral
architecture diagram is in the README.

| Area | Source | Responsibility |
| --- | --- | --- |
| CLI | `src/main.rs` | Server, user management, login, conversion, verification and transfer commands |
| IFC adapter and release | `src/release.rs` | IFClite extraction, Parquet/GLB output, index and verification |
| Registry | `src/registry.rs` | OCI HTTP endpoints and persistent content storage |
| Client | `src/client.rs` | Bearer login, manifests, blobs, push, pull and copy |
| Identity and access | `src/auth.rs` | SQLite identities/grants, Argon2id and scoped JWTs |
| Showcase | `src/demo.rs`, `tests/showcase.rs` | Generated fixture, real transfers and interoperability checks |

## Release contract

The profile is `urn:ifcx-oci:profile:0.2`, with artifact type
`application/vnd.ifcx-oci.model.v0.2`. It is experimental and not buildingSMART
approved. An OCI manifest directly describes `index.json` and every required
payload, so a standard artifact client can copy the release without interpreting
IFC-specific dependencies.

| Payload | Meaning |
| --- | --- |
| `data/entities.parquet` | Source STEP IDs, IFC classes, ordered forward attributes, selected root metadata and type assignments |
| `data/types.parquet` | Shared types assigned by `IfcRelDefinesByType`; a subset of entity rows |
| `data/properties.parquet` | Property-set IDs, names, value kinds, optional IFC datatype tags, values and candidate lists |
| `data/quantities.parquet` | Quantity-set IDs, quantity names, kinds and numeric values |
| `data/relations.parquet` | References from relationship records, with source attribute index and nested value path |
| `data/representations.parquet` | IFC entity-to-GLB scene-node bindings |
| `geometry/model.glb` | Tessellated geometry with the complete glTF scene transforms; omitted when no render geometry is produced |
| `schema/profile.json` | Source IFC schema, exact table fields, adapter revision and interpretation/preservation rules |
| `index.json` | Source IFC schema, file media types, sizes, SHA-256 digests, row counts and geometry coverage |

Entity IDs combine a caller-supplied model ID with the source STEP ID. They are
model-scoped references and may change when an authoring tool renumbers the
source. The `attributes` column is a JSON array in source attribute order,
interpreted using the recorded `sourceSchema`. Inputs must declare a supported
IFC schema in their header. References, integers, enums, typed values, binary
literals and derived values have explicit tags. Null remains distinct from a
derived attribute; references use source-relative STEP IDs within the model.

Properties retain the adapter's extracted value kind and optional IFC datatype.
Analytical values remain in source units. GLB uses metres and Y-up, and consumers
must apply the full scene/node transform hierarchy. The index reports source
products declared to have geometry that did not receive a scene binding.

Verification checks hashes and sizes, source-schema metadata, built-in table
schemas, row counts, table references and IFC-to-GLB bindings. It does not prove
authorship, engineering correctness or complete IFC semantic validity. The
profile is derived analytical/rendering data, without a lossless STEP round trip.
Review missing or unsupported geometry for the intended use.

## Authentication and authorization

SQLite stores Argon2id password hashes, users and exact repository/action grants.
The token endpoint authenticates credentials and intersects requested scopes
with the user's stored grants. It issues HS256 JWTs lasting 900 seconds. Each
registry has its own persisted identity and randomly generated 32-byte signing
key; no separate authentication service is required.

Clients discover `WWW-Authenticate: Bearer`, request a token from `/token`, and
send it on subsequent requests. Login output shows the granted access without
printing the JWT. The Rust client caches tokens, but not passwords, in
`build/client-auth.json` by default. Use `--auth-file` to separate client
identities. Login again after expiry or to request additional scopes.

Every data request validates signature, issuer, audience, expiry, issue time and
the existence of the subject. Repository access requires the action in both the
token and current SQLite grants. There are no wildcard or implicit
cross-repository grants. Invalid credentials or tokens receive an authentication
failure; a valid token without the required repository/action is denied.

Passwords must be at least 12 characters. Interactive prompts do not echo input;
`--password-stdin` is available on `user add` and `login` for automation. On Unix,
the registry directory is mode `0700`, and the database, signing key and client
auth file are mode `0600`. Protect the store and client credentials accordingly.

Additional access can be granted explicitly:

```sh
ifcx-oci user grant --data build/company-a writer project/reports:pull,push
```

The client must then log in requesting that scope to obtain a token containing
it. Multiple `--scope` arguments can request access to several repositories.

## Copy between two registries

After setting up Company A as in the README, create and start Company B in
another terminal. Enter a password for its writer account when prompted:

```sh
ifcx-oci user add --data build/company-b writer \
  --grant deliveries/model:pull,push
ifcx-oci serve --data build/company-b --listen 127.0.0.1:5001
```

With both servers running, log in to each using the writer password configured
for that server. These examples keep both tokens in one selected auth file:

```sh
ifcx-oci --plain-http --auth-file build/writer-auth.json \
  login 127.0.0.1:5000 --username writer --scope project/model:pull,push
ifcx-oci --plain-http --auth-file build/writer-auth.json \
  login 127.0.0.1:5001 --username writer --scope deliveries/model:pull,push
```

Replace `DIGEST` with the complete `sha256:...` value printed when the release
was pushed to Company A:

```sh
ifcx-oci --plain-http --auth-file build/writer-auth.json \
  copy 127.0.0.1:5000/project/model@DIGEST \
       127.0.0.1:5001/deliveries/model:issued
ifcx-oci --plain-http --auth-file build/writer-auth.json \
  pull 127.0.0.1:5001/deliveries/model@DIGEST --output build/received-copy
```

Copy preserves the manifest bytes and digest. The destination can use its own
repository and tag. This is an explicit copy, not ongoing synchronization. Tags
may move; retain digests in decision records, and define retention and backups
when continued availability matters.

## Registry API and current limits

The server implements authorized `/v2/_catalog` discovery, the `/v2/` check,
chunked and monolithic blob uploads,
blob GET/HEAD, OCI image-manifest PUT/GET/HEAD, tags listing, upload cancellation
and the Bearer token flow. It preserves exact manifest bytes, validates referenced
blob availability and size, and checks upload digests before publishing content.
Blob membership is explicit per repository.

The server binds only to loopback. The Rust client permits local HTTP with
`--plain-http` and refuses plain HTTP for remote hosts. The showcase buffers
blobs and has a 512 MiB per-blob limit. Conversion processes one IFC input in
memory and emits one file per table and one GLB scene when geometry is available.

This implementation does not claim full OCI conformance. Image indexes,
referrers, garbage collection, high availability and production TLS deployment
are outside the current server API. Use an appropriately operated OCI registry
service for those requirements. Model interpretation, IDS validation, editing
and merging belong to the applications that consume the agreed profile.

## Working on the project

Keep changes focused on the relevant module and run checks appropriate to the
behavior changed. Update the README when the user workflow changes, and this
guide when build, security or payload contracts change.

## References

- [OCI artifact manifests](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md#guidelines-for-artifact-usage)
- [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md)
- [Registry Bearer authentication and scoped access](https://distribution.github.io/distribution/spec/auth/token/)
- [ORAS](https://oras.land/docs/)
- [Pinned IFClite Rust source](https://github.com/LTplus-AG/ifc-lite/tree/9d154898de31fe91eb46f0200f2b3634c8c592f1/rust)


## Model discovery and publication records

`GET /v2/_catalog?n=100&last=project/model` implements the [Distribution catalog
API](https://distribution.github.io/distribution/spec/api/#listing-repositories)
shape and `Link` pagination. Catalog listing is not a required OCI Distribution
endpoint. It lists only published repositories for which the
JWT carries an exact `pull` grant that is still present in SQLite. Tags use
`GET /v2/<repository>/tags/list`; manifest reads retain the same pull checks.
Unauthenticated catalog requests return 401; a token without discovery access
returns 403. No catalog or manifest metadata exposes another account's models.

The local browser requests the explicit token scope `registry:catalog:read` at
`/token` using Basic credentials. This local auth extension issues a catalog
read capability plus the account's current exact repository/action grants in
the ordinary `access` array. It never grants wildcard repositories or actions.
Repository-scoped OCI clients keep the existing token flow. The token response
also includes the authenticated `subject`. Passwords are not needed to select
another already-authorized model during the session.

Successful manifest publication records the authenticated JWT subject and
server epoch time in separate files under the repository's `publications/`
directory. `GET` and `HEAD /v2/<repository>/manifests/<reference>` return optional
`IFCX-Registry-Publisher` and `IFCX-Registry-Pushed-At` headers. These headers are
this registry's extension, not standard OCI manifest fields. A tag describes
its latest publication; a digest describes the first observed publication of
those exact bytes here. Records survive restart and do not alter submitted
manifest bytes or digests. Older publications without records omit the headers;
clients must show that attribution/time was not recorded.

Manifest `org.opencontainers.image.title`, `.authors` and `.created` annotations
are declared package metadata. They do not establish an authenticated pusher or
registry upload time. Browser publications include those standard annotations,
while the normal UI attributes publication using the registry's separate
records. Copies to another registry have their own observed publication record.
