#!/usr/bin/env python3
"""Copy the complete approved deck; never regenerate it from an older narrative."""
import argparse
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil

APPROVED_SOURCE = Path(
    "/Users/saleem/.codex/visualizations/2026/10/27/"
    "01a17ef3-7361-7152-b405-dbbf903f3156/aec-common-ground"
)
DESTINATION = Path(__file__).resolve().parent
REQUIRED_ADDITIONS = {
    "An IFCX release, carried as an OCI artifact.",
    "Changes deserve their own artifacts.",
    "Agree on the contract. Let tools evolve.",
    "One small agreement. Two independent tools.",
}


class Deck(HTMLParser):
    def __init__(self):
        super().__init__()
        self.titles = []
        self.notes = 0
        self.articles = 0

    def handle_starttag(self, tag, attributes):
        attributes = dict(attributes)
        if tag == "section" and "slide" in attributes.get("class", "").split():
            self.titles.append(attributes.get("data-title", ""))
        if tag == "aside" and attributes.get("class") == "speaker-note":
            self.notes += 1
        if tag == "article" and attributes.get("id", "").startswith("note-"):
            self.articles += 1


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def synchronize(source):
    source = source.resolve()
    if source == DESTINATION or DESTINATION.is_relative_to(source):
        raise ValueError("Choose the separate approved source bundle.")
    deck = Deck()
    deck.feed((source / "index.html").read_text())
    notes = Deck()
    notes.feed((source / "speaker-notes.html").read_text())
    verification = json.loads((source / "verification.json").read_text())
    sources = json.loads((source / "sources.json").read_text())
    count = len(deck.titles)
    if count < 15 or not REQUIRED_ADDITIONS.issubset(deck.titles):
        raise ValueError("The source is missing approved slide additions; nothing copied.")
    if deck.titles[-1] != "Could OCI become common ground?":
        raise ValueError("The approved final invitation must remain last.")
    if deck.notes != count or notes.articles != count:
        raise ValueError("Every source slide needs embedded and standalone notes.")
    if verification.get("slides") != count or sources.get("presented_slides") != count:
        raise ValueError("Source verification and slide counts disagree.")
    files = sorted(path for path in source.rglob("*") if path.is_file())
    if any(path.is_symlink() for path in files):
        raise ValueError("Source assets must be ordinary files.")
    before = {str(path.relative_to(source)): digest(path) for path in files}
    changed = not (DESTINATION / "index.html").exists() or digest(DESTINATION / "index.html") != before["index.html"]
    if changed:
        # These are generated previews of the old slide order, never source assets.
        for image in (DESTINATION / "previews").glob("slide-[0-9][0-9].png"):
            image.unlink()
        (DESTINATION / "preview.png").unlink(missing_ok=True)
        (DESTINATION / "project-verification.json").unlink(missing_ok=True)
    for path in files:
        relative = path.relative_to(source)
        target = DESTINATION / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists() or digest(target) != before[str(relative)]:
            shutil.copyfile(path, target)
    after = {str(path.relative_to(source)): digest(path) for path in files}
    if before != after:
        raise RuntimeError("The source changed during synchronization; inspect before retrying.")
    copied = {name: digest(DESTINATION / name) for name in before}
    if copied != before:
        raise RuntimeError("A copied source asset does not match.")
    # One preview entry always opens the current canonical HTML, even when the
    # simple local HTTP server/browser still caches an earlier deck response.
    (DESTINATION / "preview.html").write_text('''<!doctype html>
<html lang="en"><meta charset="utf-8"><title>Pitch preview</title>
<script>
const deck = new URL('index.html', location.href);
deck.searchParams.set('preview', String(Date.now()));
deck.hash = location.hash;
location.replace(deck);
</script>
<noscript><a href="index.html">Open the pitch</a></noscript></html>
''')
    preview_files = list((DESTINATION / "previews").glob("slide-[0-9][0-9].png"))
    report = {
        "source": str(source), "destination": str(DESTINATION),
        "slideCount": count, "slideTitles": deck.titles,
        "embeddedNotes": deck.notes, "standaloneNotes": notes.articles,
        "sourceUnchanged": True, "allSourceFilesMatch": True,
        "sourceFiles": before,
        "previewRefreshRequired": changed or not (DESTINATION / "preview.png").exists() or len(preview_files) != count,
    }
    (DESTINATION / "sync-verification.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "sourceFiles"}, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=APPROVED_SOURCE)
    synchronize(parser.parse_args().source)
