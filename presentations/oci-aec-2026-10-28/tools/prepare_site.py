#!/usr/bin/env python3
"""Validate the complete pitch and export only its public static resources."""
import argparse
import hashlib
import html
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import shutil
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
TITLES = (
    "IFClite × Open CDE",
    "Why IFClite feels approachable.",
    "Every new connection takes work.",
    "Integrate once to a common agreement.",
    "Each company owns its reservoir.",
    "Many focused apps. One shared release.",
    "Compatible connections. Independent owners.",
    "Start with the IFC file we already have.",
    "An IFCX release, carried as an OCI artifact.",
    "One interface. Many ways to run it.",
    "Know exactly which release you received.",
    "Changes deserve their own artifacts.",
    "Agree on the contract. Let tools evolve.",
    "One small agreement. Two independent tools.",
    "The delivery path has a prototype.",
    "Could OCI become common ground?",
)
PUBLIC_FILES = (
    "index.html", "speaker-notes.html", "preview.html", "sources.json",
    "oci-ifcx-manifest.example.json", "ifcx-profile-config.example.json",
    "previews/overview.png",
    *(f"previews/slide-{number:02}.png" for number in range(1, len(TITLES) + 1)),
)
TOOL_FILES = (
    "tools/prepare_site.py", "tools/sync.py", "tools/serve.py",
    "tools/verification.json",
)
RETIRED_FILES = (
    "oci-ifcx-slide.json", "navigation-check.js", "preview.png",
    "project-verification.json", "sync-verification.json", "verification.json",
    "sync.py", "serve.py",
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def retired_files(root):
    return [p for p in root.glob("new-slide-*") if p.is_file()] + [
        root / name for name in RETIRED_FILES if (root / name).exists()
    ]


class References(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.ids = []

    def handle_starttag(self, tag, attributes):
        for key, value in attributes:
            if key == "id":
                self.ids.append(value)
            if key in ("href", "src") and value:
                self.links.append(value)


def text_content(markup):
    return " ".join(html.unescape(re.sub(r"<[^>]+>", "", markup)).split())


def validate_bundle(root):
    root = root.resolve()
    stale = retired_files(root)
    if stale:
        raise ValueError(f"Retired drafting files remain: {[p.name for p in stale]}")
    for name in PUBLIC_FILES:
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"Missing public file or unsupported link: {name}")
    index = (root / "index.html").read_text()
    notes = (root / "speaker-notes.html").read_text()
    sections = re.findall(r'<section class="slide\b.*?</section>', index, re.S)
    articles = re.findall(r'<article\b.*?</article>', notes, re.S)
    titles = [html.unescape(re.search(r'data-title="([^"]+)"', s)[1]) for s in sections]
    if tuple(titles) != TITLES or len(articles) != len(TITLES):
        raise ValueError(f"The complete {len(TITLES)}-slide order and Notes are required.")
    for number, (section, article) in enumerate(zip(sections, articles), 1):
        assert f'id="slide-{number}"' in section
        assert f'id="note-{number}"' in article
        assert '<span>Ahmad Saleem Z · AnkerDB</span>' in section
        assert '<span>IFCLite x Open CDE Proposal</span>' in section
        assert "28 OCT 2026" not in section and "ECOSYSTEM PROPOSAL" not in section
        embedded = re.search(r'<aside class="speaker-note" hidden>(.*?)</aside>', section, re.S)[1]
        standalone = article.split("</h2>", 1)[1].split("<small>", 1)[0]
        assert text_content(embedded) == text_content(standalone)
        assert len(text_content(embedded)) > 100
        assert text_content(re.search(r"<h2>(.*?)</h2>", article, re.S)[1]) == TITLES[number - 1]
    assert "<title>Pitch</title>" in index and " · Pitch`" in index
    assert "<title>Notes · Pitch</title>" in notes and "<h1>Notes</h1>" in notes
    assert 'id="deck-label"' not in index and "AEC / COMMON GROUND" not in index
    assert 'href="speaker-notes.html"' in index and 'href="index.html"' in notes
    assert 'An invitation to collaborate' in sections[-1]
    assert 'Invite tool builders and AEC teams to explore OCI' in sections[-1]
    assert 'Independent AEC tools · Shared model delivery' in notes
    links = set()
    for name in ("index.html", "speaker-notes.html", "preview.html"):
        markup = (root / name).read_text()
        assert not re.search(r"/Users/|file://|https?://(?:localhost|127\.0\.0\.1)", markup)
        references = References()
        references.feed(markup)
        assert len(references.ids) == len(set(references.ids)), f"Duplicate IDs in {name}"
        for target in references.links:
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            local = unquote(parsed.path)
            assert not local.startswith("/") and ".." not in Path(local).parts
            assert local in PUBLIC_FILES, f"Unpublished relative resource: {target}"
            links.add(local)
    for name in ("sources.json", "oci-ifcx-manifest.example.json", "ifcx-profile-config.example.json"):
        json.loads((root / name).read_text())
    sources = json.loads((root / "sources.json").read_text())
    assert sources["presented_slides"] == len(TITLES)
    assert sources["audience"] == "AEC tool builders and teams"
    assert "verified_person" not in sources
    for name in PUBLIC_FILES:
        if name.endswith(".png"):
            assert (root / name).read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    return {
        "slides": len(TITLES), "notes": len(TITLES), "slideTitles": titles,
        "presenter": "Ahmad Saleem Z",
        "footer": "IFCLite x Open CDE Proposal", "notesMatch": True,
        "relativeLinksResolve": sorted(links), "legacyDraftFiles": 0,
        "publicFiles": {name: digest(root / name) for name in PUBLIC_FILES},
    }


def export_site(root, output):
    report = validate_bundle(root)
    output = output.resolve()
    if output == root.resolve() or root.resolve().is_relative_to(output):
        raise ValueError("Choose a separate export directory.")
    if output.exists() and any(output.iterdir()):
        raise ValueError("The export directory must be empty.")
    output.mkdir(parents=True, exist_ok=True)
    for name in PUBLIC_FILES:
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / name, target)
    (output / ".nojekyll").write_text("")
    actual = {str(p.relative_to(output)) for p in output.rglob("*") if p.is_file()}
    assert actual == set(PUBLIC_FILES) | {".nojekyll"}
    assert all(digest(output / name) == value for name, value in report["publicFiles"].items())
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Export the public Pages artifact to an empty directory.")
    parser.add_argument("--report", type=Path, help="Save portable validation metadata.")
    args = parser.parse_args()
    result = export_site(ROOT, args.output) if args.output else validate_bundle(ROOT)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key != "publicFiles"}, ensure_ascii=False))
