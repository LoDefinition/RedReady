"""Version comparison for CPE range matching.

NVD version strings are not PEP 440 or semver — ``8.2p1``, ``1.1.1w``, ``2.4.54-1ubuntu1`` all
occur — so versions are compared as a sequence of numeric and alphabetic chunks.
"""

from __future__ import annotations

import re

_CHUNK_RE = re.compile(r"(\d+|[A-Za-z]+)")


def parse_version(value: str) -> tuple[tuple[int, str], ...]:
    """Split a version into comparable ``(numeric, alphabetic)`` chunks.

    Numeric chunks compare numerically and sort before alphabetic chunks of the same position, so
    ``8.2`` < ``8.2p1`` and ``1.1.1a`` < ``1.1.1w``.
    """
    return tuple(
        (int(chunk), "") if chunk.isdigit() else (-1, chunk.lower())
        for chunk in _CHUNK_RE.findall(value)
    )


def _strip_trailing_zeros(chunks: tuple[tuple[int, str], ...]) -> tuple[tuple[int, str], ...]:
    """``2.0.0`` and ``2.0`` denote the same release, so trailing zero chunks are insignificant."""
    end = len(chunks)
    while end > 1 and chunks[end - 1] == (0, ""):
        end -= 1
    return chunks[:end]


def compare_versions(left: str, right: str) -> int:
    """Return -1, 0 or 1 for ``left`` <, == or > ``right``."""
    lhs = _strip_trailing_zeros(parse_version(left))
    rhs = _strip_trailing_zeros(parse_version(right))
    for a, b in zip(lhs, rhs, strict=False):
        if a != b:
            return -1 if a < b else 1
    if len(lhs) == len(rhs):
        return 0
    return -1 if len(lhs) < len(rhs) else 1


def version_in_range(
    version: str,
    *,
    exact: str | None = None,
    start_including: str | None = None,
    end_excluding: str | None = None,
) -> bool:
    """Check a version against a CPE match range.

    ``start_including``/``end_excluding`` carry an ``<`` or ``<=`` prefix when the source range was
    exclusive/inclusive respectively; see :func:`redready.intel.sources.nvd.encode_bound`.
    """
    if exact is not None:
        return compare_versions(version, exact) == 0

    if start_including is not None:
        inclusive, bound = decode_bound(start_including)
        cmp = compare_versions(version, bound)
        if cmp < 0 or (cmp == 0 and not inclusive):
            return False

    if end_excluding is not None:
        inclusive, bound = decode_bound(end_excluding)
        cmp = compare_versions(version, bound)
        if cmp > 0 or (cmp == 0 and not inclusive):
            return False

    return start_including is not None or end_excluding is not None


def encode_bound(value: str, *, inclusive: bool) -> str:
    """Encode a version bound and its inclusivity into a single storable string."""
    return ("=" if inclusive else ">") + value


def decode_bound(value: str) -> tuple[bool, str]:
    if value[:1] in ("=", ">"):
        return value[0] == "=", value[1:]
    return True, value
