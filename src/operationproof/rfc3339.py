from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Final

_RFC3339_TIMESTAMP_RE: Final = re.compile(
    r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"
    r"[Tt](?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?P<fraction>\.\d+)?(?P<timezone>[Zz]|[+-]\d{2}:\d{2})$"
)
_EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)

ParsedTimestamp = tuple[int, str]


def parse_rfc3339(value: object) -> ParsedTimestamp:
    """Return exact UTC whole seconds plus unrounded fractional digits."""

    if not isinstance(value, str) or not value:
        raise ValueError("RFC3339 timestamp required")
    match = _RFC3339_TIMESTAMP_RE.fullmatch(value)
    if match is None:
        raise ValueError("invalid RFC3339 timestamp syntax")

    year = int(match.group("year"))
    month = int(match.group("month"))
    day = int(match.group("day"))
    hour = int(match.group("hour"))
    minute = int(match.group("minute"))
    second = int(match.group("second"))
    if hour > 23 or minute > 59 or second > 60:
        raise ValueError("invalid RFC3339 time component")

    timezone = match.group("timezone")
    offset_seconds = 0
    if timezone.casefold() != "z":
        offset_hour = int(timezone[1:3])
        offset_minute = int(timezone[4:6])
        if offset_hour > 23 or offset_minute > 59:
            raise ValueError("invalid RFC3339 offset")
        offset_seconds = offset_hour * 3600 + offset_minute * 60
        if timezone[0] == "-":
            offset_seconds = -offset_seconds

    base_second = min(second, 59)
    try:
        base = datetime(year, month, day, hour, minute, base_second, tzinfo=UTC)
    except ValueError as exc:
        raise ValueError("invalid RFC3339 calendar value") from exc

    delta = base - _EPOCH
    whole_seconds = delta.days * 86400 + delta.seconds
    if second == 60:
        whole_seconds += 1
    whole_seconds -= offset_seconds

    fraction = match.group("fraction")
    return whole_seconds, "" if fraction is None else fraction[1:]


def timestamp_from_datetime(value: datetime) -> ParsedTimestamp:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    normalized = value.astimezone(UTC)
    whole = normalized.replace(microsecond=0)
    delta = whole - _EPOCH
    fraction = f"{normalized.microsecond:06d}".rstrip("0")
    return delta.days * 86400 + delta.seconds, fraction


def compare_timestamps(left: ParsedTimestamp, right: ParsedTimestamp) -> int:
    left_whole, left_fraction = left
    right_whole, right_fraction = right
    if left_whole < right_whole:
        return -1
    if left_whole > right_whole:
        return 1

    common_length = min(len(left_fraction), len(right_fraction))
    left_common = left_fraction[:common_length]
    right_common = right_fraction[:common_length]
    if left_common < right_common:
        return -1
    if left_common > right_common:
        return 1

    if len(left_fraction) < len(right_fraction):
        return -1 if any(digit != "0" for digit in right_fraction[common_length:]) else 0
    if len(left_fraction) > len(right_fraction):
        return 1 if any(digit != "0" for digit in left_fraction[common_length:]) else 0
    return 0
