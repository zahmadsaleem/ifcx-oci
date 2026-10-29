# Development

## Build

```sh
nix develop
cargo build --locked --release
./target/release/ifcx-oci --help
```

```sh
nix build
./result/bin/ifcx-oci --help
```

## Checks

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
IFCX_TEST_ORAS="$(command -v oras)" cargo test --locked --test showcase
nix flake check --no-build
git diff --check
```

## Connect a browser application

```sh
cargo run --locked -- user add --data build/registry writer \
  --grant project/model:pull,push
cargo run --locked -- serve --data build/registry --listen 127.0.0.1:5000 \
  --oauth-client-id model-client \
  --oauth-redirect-uri http://localhost:3000/oauth/callback
```

## Demo

```sh
nix run .#demo -- --output build/showcase
```

## Docker

```sh
docker build -t ifcx-oci:dev .
docker run --rm ifcx-oci:dev --help
docker volume create ifcx-oci-data
docker run --rm -it -v ifcx-oci-data:/data ifcx-oci:dev \
  user add --data /data writer --grant project/model:pull,push

docker run --rm -p 127.0.0.1:5000:5000 -v ifcx-oci-data:/data ifcx-oci:dev \
  serve --data /data --listen 0.0.0.0:5000 --public-url http://localhost:5000 \
  --oauth-client-id model-client \
  --oauth-redirect-uri http://localhost:3000/oauth/callback
```

Open the development registry as `http://localhost:5000`. For an HTTPS cloud
ingress, persistent storage and one-off provisioning jobs, see the
[deployment example](README.md#single-instance-cloud-test-deployment).
