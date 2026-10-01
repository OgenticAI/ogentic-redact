"""Restoration budgets and failed-consume regression cases."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from ogentic_redact import InProcessMappingStore, Redactor, SQLiteMappingStore
from ogentic_redact._restoration import restore_mapping
from ogentic_redact.errors import MappingNotFound


@pytest.fixture(params=[InProcessMappingStore, SQLiteMappingStore])
def store(request):
    value = request.param()
    yield value
    if isinstance(value, SQLiteMappingStore):
        value.close()


def test_utf8_budget_counts_bytes_including_untouched_text() -> None:
    assert restore_mapping("é[t]", {"[t]": "😀"}, max_output_bytes=6) == "é😀"
    with pytest.raises(ValueError, match="limits"):
        restore_mapping("é[t]", {"[t]": "😀"}, max_output_bytes=5)
    with pytest.raises(ValueError, match="limits"):
        restore_mapping("é", {}, max_output_bytes=1)
    assert restore_mapping("", {}, max_output_bytes=0, max_replacements=0) == ""


def test_replacements_count_occurrences_without_recursive_substitution() -> None:
    mapping = {"[a]": "[b]", "[b]": "secret"}
    assert restore_mapping("[a][a]", mapping, max_replacements=2) == "[b][b]"
    with pytest.raises(ValueError, match="limits"):
        restore_mapping("[a][a]", mapping, max_replacements=1)
    assert restore_mapping("plain", mapping, max_replacements=0) == "plain"


@pytest.mark.parametrize("limit", [-1, True, 1.5, None])
def test_invalid_limits_are_rejected(limit) -> None:
    with pytest.raises(ValueError, match="non-negative integer"):
        restore_mapping("", {}, max_output_bytes=limit)
    with pytest.raises(ValueError, match="non-negative integer"):
        restore_mapping("", {}, max_replacements=limit)


def test_failed_output_budget_does_not_consume_mapping(store) -> None:
    mapping_id = store.store({"[t]": "a" * 65536}, "scope")
    redactor = Redactor(reversible=True, mapping_store=store)
    with pytest.raises(ValueError, match="limits"):
        redactor.unredact("[t]" * 1024, mapping_id, "scope", consume=True)
    assert store.fetch(mapping_id, "scope") == {"[t]": "a" * 65536}
    assert redactor.unredact("[t]", mapping_id, "scope", consume=True) == "a" * 65536
    with pytest.raises(MappingNotFound):
        store.fetch(mapping_id, "scope")


def test_failed_unicode_validation_does_not_consume_mapping(store) -> None:
    mapping_id = store.store({"[t]": "secret"}, "scope")
    redactor = Redactor(reversible=True, mapping_store=store)
    with pytest.raises(ValueError, match="UTF-8"):
        redactor.unredact("\ud800", mapping_id, "scope", consume=True)
    assert store.fetch(mapping_id, "scope") == {"[t]": "secret"}


def test_failed_replacement_budget_does_not_consume_mapping(store) -> None:
    mapping_id = store.store({"[t]": "secret"}, "scope")
    redactor = Redactor(reversible=True, mapping_store=store)
    with pytest.raises(ValueError, match="limits"):
        redactor.unredact("[t][t]", mapping_id, "scope", consume=True, max_replacements=1)
    assert redactor.unredact("[t]", mapping_id, "scope", consume=True, max_replacements=1) == "secret"


def test_only_one_concurrent_restoration_returns_consumed_mapping(store) -> None:
    mapping_id = store.store({"[t]": "secret"}, "scope")
    redactor = Redactor(reversible=True, mapping_store=store)

    def restore(_):
        try:
            return redactor.unredact("[t]", mapping_id, "scope", consume=True)
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(restore, range(8)))
    assert results.count("secret") == 1
    assert results.count(None) == 7
