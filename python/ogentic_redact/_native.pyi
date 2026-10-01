"""Type stub for the native extension. Private mapping helpers contain PII."""
from typing import TypedDict

__version__: str

class RedactionResult(TypedDict):
    text: str
    redaction_count: int

class _MappingResult(TypedDict):
    text: str
    tokens: dict[str, str]

def redact(text: str) -> RedactionResult: ...
def redact_with_salt(text: str, salt: bytes) -> RedactionResult: ...
def unredact(text: str, tokens: dict[str, str], *, max_output_bytes: int = 16777216, max_replacements: int = 100000) -> str: ...
def _redact_to_mapping(text: str) -> _MappingResult: ...
def _redact_to_mapping_with_salt(text: str, salt: bytes) -> _MappingResult: ...
