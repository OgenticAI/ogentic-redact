"""Type stub for the `_native` Rust extension (see `python/ogentic-redact-py`)."""

from typing import TypedDict

__version__: str

class RedactionResult(TypedDict):
    """Return shape of :func:`redact` / :func:`redact_with_salt`."""

    text: str
    tokens: dict[str, str]

def redact(text: str) -> RedactionResult: ...
def redact_with_salt(text: str, salt: bytes) -> RedactionResult: ...
def unredact(text: str, tokens: dict[str, str]) -> str: ...
