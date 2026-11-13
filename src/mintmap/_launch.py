"""Console entry point (`mintmap`, `python -m mintmap`).

If MintMap cannot even be imported, for example on an unsupported Python, exit 128 ("MintMap could not run"),
never 1, which is the new_path bit."""
import sys


def main() -> int:
    if sys.version_info < (3, 11):
        sys.stderr.write("mintmap: could not start on Python %s: MintMap needs Python 3.11 or newer\n"
                         % sys.version.split()[0])
        return 128
    try:
        from .cli import entry
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"mintmap: could not start on Python {sys.version.split()[0]}: {exc!r}\n")
        return 128
    return entry()
