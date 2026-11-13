"""Rewrite README.md for PyPI: relative links and images become absolute GitHub URLs at one tag.

    python scripts/pypi_readme.py v0.6.0a2

PyPI renders the README outside the repository, so relative links (docs/..., examples/..., LICENSE) would be
broken there; images become raw.githubusercontent.com URLs. PyPI does not render Mermaid, so the diagram becomes
a link to it on GitHub. In-page links (#accuracy, ...) are kept: PyPI's renderer gives headings matching ids. The
release workflow runs this before building; the README in the repository is not changed by a commit. Standard
library only.
"""
import os
import re
import sys

REPO = "mohamedmoatazsec/mintmap"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def absolute(text: str, ref: str) -> str:
    blob = f"https://github.com/{REPO}/blob/{ref}/"
    raw = f"https://raw.githubusercontent.com/{REPO}/{ref}/"

    def link(m):
        target = m.group(2)
        if re.match(r"[a-z][a-z0-9+.-]*:|#|//", target):
            return m.group(0)
        return f"{m.group(1)}({blob}{target.removeprefix('./')})"

    def image(m):
        target = m.group(2)
        if re.match(r"[a-z][a-z0-9+.-]*:|//", target):
            return m.group(0)
        return f'{m.group(1)}"{raw}{target}"'

    def md_image(m):
        target = m.group(2)
        if re.match(r"[a-z][a-z0-9+.-]*:|//", target):
            return m.group(0)
        return f"{m.group(1)}{raw}{target.removeprefix('./')})"

    # PyPI does not render Mermaid: point to the diagram on GitHub instead of showing its source
    diagram = f"*(Diagram: see the [README on GitHub]({blob}README.md#how-it-works).)*"
    text = re.sub(r"```mermaid\n.*?\n```", lambda m: diagram, text, flags=re.S)
    text = re.sub(r"(!\[[^\]]*\]\()([^)\s]+)\)", md_image, text)   # Markdown images: raw file URLs
    text = re.sub(r"(\]\s*)\(([^)\s]+)\)", link, text)
    return re.sub(r'(<img\b[^>]*?\bsrc=)"([^"]+)"', image, text)


def main(argv) -> int:
    if len(argv) != 1 or not re.fullmatch(r"[A-Za-z0-9._-]+", argv[0]):
        sys.stderr.write("usage: python scripts/pypi_readme.py <tag>\n")
        return 2
    path = os.path.join(ROOT, "README.md")
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(absolute(text, argv[0]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
