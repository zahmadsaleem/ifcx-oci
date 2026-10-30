<h1><picture><source media="(prefers-color-scheme: dark)" srcset="assets/brand/subsoil-logo-chalk.svg"><img src="assets/brand/subsoil-logo.svg" alt="Subsoil" width="280"></picture></h1>

Subsoil gives your team a shared place for project files and their versions.
Find what you need, see who added it, and share a link with someone who has access.
Your organization chooses where the files are kept and which people and apps can
use them.

## Find your files

Open the Subsoil address your team gave you and sign in with your account. The
Files page shows the folders you can access. Search for a folder, choose a
version, and look through its files. **Added by**, **Added**, and **Size** help
you recognize the version you need.

The file browser is for viewing. It does not change the files stored there.
Your sign-in lasts up to eight hours in that browser tab. If a folder is missing,
ask your project team to check your access.

## Share a version

Choose **Copy link** on a version's page to send its address to a teammate.
They will need their own access to open it. Copying a link does not change who
can use the files.

Your team can also send an expiring share link. Its page shows the files shared
with you and when the link stops working. Ask the sender for a new link if it has
expired, or for help choosing an app to open a model.

Each named version stays fixed. Changed files are added as a new version, so a
link to an issued version continues to identify the same content. People who
connect other software can find storage information and an exact integration
reference under **Technical details**.

## Try Subsoil on your computer

The following examples use the `subsoil` command. Follow the
[development guide](docs/DEVELOPMENT.md) to build it, then run commands from the
repository root.

```sh
subsoil demo --output build/showcase
```

The demo makes a small example model and shares it between two local stores. It
checks that the files arrive intact and that a person with viewing access cannot
add files or open another collection. The stores stop when it finishes. Their
data and a report remain in `build/showcase`; use a new output folder for each run.

## Share your own model locally

Create an account and start a local server. Choose a password of at least 12
characters when prompted.

```sh
subsoil user add --data build/company-a writer \
  --grant project/model:pull,push
subsoil serve --data build/company-a --listen 127.0.0.1:5000
```

Open `http://127.0.0.1:5000/explore` to browse the files. Keep the server running
and use a second terminal for the remaining commands.

```sh
subsoil --plain-http login 127.0.0.1:5000 \
  --username writer --scope project/model:pull,push
subsoil convert /path/to/model.ifc --output build/release --model-id design
subsoil verify build/release
subsoil --plain-http push build/release 127.0.0.1:5000/project/model:issued
```

Replace `/path/to/model.ifc` with your model's path. In these commands,
`project/model` is the folder name and `issued` is the version name. The command
line and API call these a **repository** and a **tag**. `pull` allows receiving
files; `push` allows adding them. `--plain-http` enables this local connection.

Publishing prints a content fingerprint beginning with `sha256:`. Copy the
whole value in place of `DIGEST` to receive that exact version:

```sh
subsoil --plain-http pull 127.0.0.1:5000/project/model@DIGEST \
  --output build/received
```

Receiving also checks the files. Both conversion and receiving require a new
output folder. Add changed content under a new version name.

An account that only needs to receive files uses a `pull` grant:

```sh
subsoil user add --data build/company-a reader --grant project/model:pull
subsoil --plain-http login 127.0.0.1:5000 \
  --username reader --scope project/model:pull
```

Command-line sign-in expires after 15 minutes; run `login` again when needed.
After signing in to two stores, use `subsoil copy SOURCE DESTINATION` to copy a
version between them.

## Set up a team or connect an app

The [deployment guide](docs/DEPLOYMENT.md) explains shared hosting, accounts, and
persistent storage. [Access and sharing](docs/AUTHORIZATION.md) covers account rules,
browser sign-in, and expiring links. The [development guide](docs/DEVELOPMENT.md)
explains the file format and application connection.

Subsoil's model conversion is experimental and is not buildingSMART approved.
It does not preserve every authoring detail needed to recreate the original IFC
file. Include the source file with `convert --include-source` when you want it
in the shared version. Verification checks file integrity and internal links;
your team still decides whether a model is suitable for its project.

The [brand guide](docs/BRANDING.md) covers the logo and interface language.
You can also [read the project pitch](https://madsolame.com/subsoil/).

Licensed under the [Apache License 2.0](LICENSE).
