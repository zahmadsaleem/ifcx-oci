# Subsoil branding

Subsoil's Common Ground identity gives project files a familiar, shared home.
Its calm colours and clear language help people find their work and understand
what they can do with it.
The logo is a square soil section with four layers: dotted topsoil, dash-only
subsoil, a dense middle layer with alternating dots and dashes at 45°, and angular
bedrock. The three separators and the outer border share a 1.8-unit stroke.

## Master artwork

- [Symbol](../assets/brand/subsoil-symbol.svg): the shared geometry and textures.
- [Wordmark](../assets/brand/subsoil-wordmark.svg): outlined lettering.
- [Primary logo](../assets/brand/subsoil-logo.svg): the full-colour horizontal signature.
- [Forest logo](../assets/brand/subsoil-logo-forest.svg) and
  [chalk logo](../assets/brand/subsoil-logo-chalk.svg): single-colour treatments.
- [App icon](../assets/brand/subsoil-app-icon.svg).

Use the full-colour signature on light surfaces and the chalk signature on dark
surfaces. Preserve the square, proportions, texture positions and layer borders.
All sizes use the same artwork. Keep at least 8 units of clear space around the
visible 80-unit square on its 96-unit canvas. Use the horizontal signature at
144px wide or larger.

The sign-in, file browser and sharing screens use `/brand/logo.svg` and
the favicon uses `/brand/symbol.svg`. These assets are embedded in the binary.

## Regenerate exports

Edit the master symbol or outlined wordmark, then regenerate the signatures,
single-colour treatments and app icon:

```sh
python3 tools/build_brand.py
python3 tools/build_brand.py --check
```

Commit the regenerated SVGs with the masters. The generator uses Python's
standard library and does not require fonts to be installed.

## Writing for users

Write for someone looking for files in a shared project space. Say **files**,
**folders**, **versions**, and **links**. Use familiar actions such as **Show
files**, **Added by**, and **Copy link**. Describe Subsoil as a shared place for
project files, and start with what the person wants to find or do.

Explain access through everyday tasks: viewing files, adding a version, or
sharing with a teammate. When an app asks for access, describe what it can do
and whether that includes new folders. A copied browser link does not give
someone permission to open its files.

Storage formats, content IDs, and integration references belong under
**Technical details**. Keep those values accurate for support teams while using
plain labels in the main view. Errors should give a useful next step, such as
signing in again or asking the person who shared the files for help.

For example: **Your files, in one place.** Find your project files, choose the
version you need, and share it with your team.
