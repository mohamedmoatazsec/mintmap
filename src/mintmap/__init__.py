"""MintMap: a reviewed map of the code paths that create a login session or credential in a Django app, enforced
in CI."""
__all__ = ["__version__"]


def __getattr__(name):
    # Imported lazily, so that the console entry point (_launch) can report an import failure with exit 128.
    if name == "__version__":
        from .core.analysis import TOOL_VERSION
        return TOOL_VERSION
    raise AttributeError(f"module 'mintmap' has no attribute {name!r}")
