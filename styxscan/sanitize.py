"""Helpers for rendering untrusted values safely."""

from __future__ import annotations

import re

_CONTROL_RE = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]"
)

MAX_DISPLAY_LENGTH = 512


def sanitize(value: object, limit: int = MAX_DISPLAY_LENGTH) -> str:
    """Remove control characters and bound the length of untrusted text.

    Rich markup is neutralized by the caller wrapping this value in
    ``rich.text.Text``; this helper only handles characters and length.
    """

    text = _CONTROL_RE.sub("", str(value))
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text
