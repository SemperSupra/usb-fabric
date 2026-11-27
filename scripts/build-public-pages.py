#!/usr/bin/env python3
"""Materialize the deliberately small, public documentation allowlist."""
from html.parser import HTMLParser
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_LINKS = {"https://github.com/SemperSupra/usb-fabric", "https://github.com/SemperSupra/usb-fabric/releases"}

class SiteCheck(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = False
        self.links = set()

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "iframe", "object", "embed", "form", "base", "link", "img", "video", "audio", "source"}:
            raise ValueError(f"unexpected active or external content: {tag}")
        if tag == "title":
            self.title = True
        for key, value in attrs:
            if key.startswith("on") or key in {"src", "srcset", "action", "style", "http-equiv"}:
                raise ValueError(f"unexpected attribute: {key}")
            if key == "href":
                if tag != "a" or value not in ALLOWED_LINKS:
                    raise ValueError("link outside the public allowlist")
                self.links.add(value)

def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: python3 -I scripts/build-public-pages.py NEW_OUTPUT_DIRECTORY")
    src = ROOT / "site"
    if src.is_symlink() or not src.is_dir():
        raise ValueError("site must be a regular directory")
    if sorted(p.name for p in src.iterdir()) != ["index.html"]:
        raise ValueError("site contains files outside the allowlist")
    page = src / "index.html"
    if page.is_symlink() or not page.is_file() or page.stat().st_size > 65536:
        raise ValueError("unexpected page type or size")
    data = page.read_bytes()
    document = data.decode("utf-8")
    if "Pre-release documentation." not in document or "No production release" not in document:
        raise ValueError("missing explicit pre-release status")
    check = SiteCheck()
    check.feed(document)
    check.close()
    if not check.title or check.links != ALLOWED_LINKS:
        raise ValueError("missing title or approved links")
    out = Path(sys.argv[1])
    out.mkdir(parents=False, exist_ok=False)
    (out / "index.html").write_bytes(data)
    print("PASS: public documentation materialized; no product artifacts")

if __name__ == "__main__":
    main()
