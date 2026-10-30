#!/usr/bin/env python3
"""Build every logo treatment from the approved symbol and outlined wordmark."""

import argparse
from copy import deepcopy
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets" / "brand"
NS = "http://www.w3.org/2000/svg"
ET.register_namespace("", NS)


def element(tag, **attributes):
    return ET.Element(f"{{{NS}}}{tag}", attributes)


def artwork(svg):
    return [deepcopy(child) for child in svg if child.tag != f"{{{NS}}}title"]


def document(title, viewbox, colour="#224F43"):
    svg = element("svg", viewBox=viewbox, color=colour, role="img")
    svg.set("aria-labelledby", "title")
    label = ET.SubElement(svg, f"{{{NS}}}title", {"id": "title"})
    label.text = title
    return svg


def monochrome(source, colour):
    svg = deepcopy(source)
    svg.set("color", colour)
    for child in list(svg):
        if child.tag == f"{{{NS}}}path" and child.get("fill"):
            svg.remove(child)
    for node in svg.iter():
        for attribute in ("fill", "stroke"):
            if node.get(attribute) and node.get(attribute) != "none":
                node.set(attribute, "currentColor")
    return svg


def signature(symbol, wordmark, colour="#224F43"):
    _, _, width, height = map(float, wordmark.get("viewBox").split())
    # The wordmark master includes an 8-unit margin on each side.
    scale = 44 / (height - 16)
    total_width = 84 + (width - 16) * scale
    svg = document("Subsoil", f"0 0 {total_width:.4f} 64", colour)
    mark = ET.SubElement(svg, f"{{{NS}}}g", {"transform": "scale(.6666667)"})
    mark.extend(artwork(symbol))
    letters = ET.SubElement(
        svg,
        f"{{{NS}}}g",
        {"transform": f"translate(84 10) scale({scale:.6f})"},
    )
    letters.extend(artwork(wordmark))
    return svg


def build():
    symbol = ET.parse(ASSETS / "subsoil-symbol.svg").getroot()
    wordmark = ET.parse(ASSETS / "subsoil-wordmark.svg").getroot()
    outputs = {"subsoil-logo.svg": signature(symbol, wordmark)}
    for name, colour in (("forest", "#224F43"), ("chalk", "#FFFDF8"), ("black", "#000000")):
        mono = monochrome(symbol, colour)
        outputs[f"subsoil-symbol-{name}.svg"] = mono
        outputs[f"subsoil-logo-{name}.svg"] = signature(mono, wordmark, colour)
    icon = document("Subsoil", "0 0 64 64")
    icon.append(element("rect", width="64", height="64", rx="10", fill="#FFFDF8"))
    mark = ET.SubElement(icon, f"{{{NS}}}g", {"transform": "scale(.6666667)"})
    mark.extend(artwork(symbol))
    outputs["subsoil-app-icon.svg"] = icon
    return {
        name: (ET.tostring(svg, encoding="unicode") + "\n").encode()
        for name, svg in outputs.items()
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Check that committed exports match the masters")
    args = parser.parse_args()
    stale = []
    for name, data in build().items():
        path = ASSETS / name
        if args.check:
            if not path.exists() or path.read_bytes() != data:
                stale.append(name)
        else:
            path.write_bytes(data)
    if stale:
        print("Regenerate brand assets: " + ", ".join(stale), file=sys.stderr)
        return 1
    print("Brand exports match the approved masters." if args.check else "Generated brand exports.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
