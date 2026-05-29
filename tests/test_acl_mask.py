"""Regression tests for ACL mask interpretation.

The 0.3.2 release falsely flagged read-only ACEs (the very common
'Authenticated Users can read everything' pattern) as Full Control,
producing dozens of bogus 'DCSync granted to LocalSystem / Creator
Owner / etc.' findings on a real DC. These tests pin the corrected
semantics so the regression can't sneak back.
"""

from __future__ import annotations

from adex.utils import (
    ADS_CONTROL_ACCESS,
    ADS_SELF,
    ADS_WRITE_PROP,
    GENERIC_ALL_BIT,
    GENERIC_ALL_BITPATTERN,
    GENERIC_WRITE_BIT,
    WRITE_DACL,
    WRITE_OWNER,
    grants_full_control,
    is_dangerous_write_mask,
)


# Common read-only mask seen on default ACEs (READ_CONTROL | LIST_OBJECT |
# READ_PROP | LIST_CONTENTS). Must NOT be flagged.
READONLY_MASK = 0x00020094


def test_readonly_mask_is_not_dangerous():
    assert is_dangerous_write_mask(READONLY_MASK) == 0
    assert grants_full_control(READONLY_MASK) is False


def test_control_access_alone_is_not_dangerous():
    """An extended-right ACE without a known ObjectType GUID isn't a write."""
    assert is_dangerous_write_mask(ADS_CONTROL_ACCESS) == 0


def test_full_control_bitpattern_is_dangerous():
    assert is_dangerous_write_mask(GENERIC_ALL_BITPATTERN) != 0
    assert grants_full_control(GENERIC_ALL_BITPATTERN) is True


def test_partial_full_control_bits_are_not_full_control():
    """Reading READ_PROP | LIST_CONTENTS (subset of Full Control bitpattern)
    must not be reported as Full Control."""
    partial = 0x14  # LIST_CONTENTS | READ_PROP
    assert grants_full_control(partial) is False
    # is_dangerous_write_mask returns 0 — no write bits.
    assert is_dangerous_write_mask(partial) == 0


def test_write_dac_alone_is_dangerous():
    assert is_dangerous_write_mask(WRITE_DACL) == WRITE_DACL


def test_write_owner_alone_is_dangerous():
    assert is_dangerous_write_mask(WRITE_OWNER) == WRITE_OWNER


def test_write_property_alone_is_dangerous():
    assert is_dangerous_write_mask(ADS_WRITE_PROP) == ADS_WRITE_PROP


def test_self_validated_write_is_dangerous():
    assert is_dangerous_write_mask(ADS_SELF) == ADS_SELF


def test_high_generic_all_bit_grants_full_control():
    assert grants_full_control(GENERIC_ALL_BIT) is True
    assert is_dangerous_write_mask(GENERIC_ALL_BIT) != 0


def test_high_generic_write_bit_is_dangerous():
    assert is_dangerous_write_mask(GENERIC_WRITE_BIT) != 0


def test_combined_read_and_write_extracts_write_only():
    """An ACE with read + WRITE_PROP returns just the WRITE_PROP bit."""
    mask = READONLY_MASK | ADS_WRITE_PROP
    assert is_dangerous_write_mask(mask) == ADS_WRITE_PROP
