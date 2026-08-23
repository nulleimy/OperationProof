from __future__ import annotations

import re
from bisect import bisect_right
from datetime import UTC, datetime, timedelta
from typing import Final

_RFC3339_TIMESTAMP_RE: Final = re.compile(
    r"^(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
    r"[Tt](?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?P<fraction>\.[0-9]+)?(?P<timezone>[Zz]|[+-][0-9]{2}:[0-9]{2})$"
)
_EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)

# Positive UTC leap seconds published by NIST/IERS through the current table.
# A future leap second must be added explicitly before second=60 is accepted.
_LEAP_SECOND_UTC_DATES: Final = (
    (1972, 6, 30),
    (1972, 12, 31),
    (1973, 12, 31),
    (1974, 12, 31),
    (1975, 12, 31),
    (1976, 12, 31),
    (1977, 12, 31),
    (1978, 12, 31),
    (1979, 12, 31),
    (1981, 6, 30),
    (1982, 6, 30),
    (1983, 6, 30),
    (1985, 6, 30),
    (1987, 12, 31),
    (1989, 12, 31),
    (1990, 12, 31),
    (1992, 6, 30),
    (1993, 6, 30),
    (1994, 6, 30),
    (1995, 12, 31),
    (1997, 6, 30),
    (1998, 12, 31),
    (2005, 12, 31),
    (2008, 12, 31),
    (2012, 6, 30),
    (2015, 6, 30),
    (2016, 12, 31),
)

ParsedTimestamp = tuple[int, str]


def _posix_whole_seconds(value: datetime) -> int:
    delta = value - _EPOCH
    return delta.days * 86400 + delta.seconds


_LEAP_BOUNDARIES_POSIX: Final = tuple(
    _posix_whole_seconds(datetime(year, month, day, tzinfo=UTC) + timedelta(days=1))
    for year, month, day in _LEAP_SECOND_UTC_DATES
)


def parse_rfc3339(value: object) -> ParsedTimestamp:
    """Return exact monotonic UTC seconds plus unrounded fractional digits.

    Ordinary Python/POSIX time aliases a positive leap second with the following
    minute. This representation inserts each known leap second into the integer
    timeline, so exact comparisons preserve ``23:59:60.x < 00:00:00.y``.
    """

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
    if timezone == "-00:00":
        raise ValueError("RFC3339 unknown local offset is not an exact instant")

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
        local_base = datetime(year, month, day, hour, minute, base_second, tzinfo=UTC)
    except ValueError as exc:
        raise ValueError("invalid RFC3339 calendar value") from exc

    utc_base = local_base - timedelta(seconds=offset_seconds)
    posix_whole = _posix_whole_seconds(utc_base)

    if second == 60:
        leap_boundary = posix_whole + 1
        if (
            utc_base.hour != 23
            or utc_base.minute != 59
            or utc_base.second != 59
            or leap_boundary not in _LEAP_BOUNDARIES_POSIX
        ):
            raise ValueError("second 60 is not a known UTC leap second")
        whole_seconds = posix_whole + bisect_right(_LEAP_BOUNDARIES_POSIX, posix_whole) + 1
    else:
        whole_seconds = posix_whole + bisect_right(_LEAP_BOUNDARIES_POSIX, posix_whole)

    fraction = match.group("fraction")
    return whole_seconds, "" if fraction is None else fraction[1:]


def timestamp_from_datetime(value: datetime) -> ParsedTimestamp:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    normalized = value.astimezone(UTC)
    whole = normalized.replace(microsecond=0)
    posix_whole = _posix_whole_seconds(whole)
    exact_whole = posix_whole + bisect_right(_LEAP_BOUNDARIES_POSIX, posix_whole)
    fraction = f"{normalized.microsecond:06d}".rstrip("0")
    return exact_whole, fraction


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
