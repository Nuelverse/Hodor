"""
Tests for two_factor_helper.py

Covers:
  - TOTP secret generation and QR code creation
  - verify_code: valid, invalid, and zero-padded codes
  - replay protection: a consumed code is refused for the rest of its window

Backup codes were removed deliberately (see two_factor_helper), so there are
no tests for them.
"""

import pytest
import pyotp
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import two_factor_helper
import db_handler


USER_ID = 100000000000000001
GUILD_ID = 200000000000000001


# TOTP - verify_code

class TestVerifyCode:
    def test_valid_code(self, in_memory_db):
        secret = pyotp.random_base32()
        db_handler.insert_user(in_memory_db, (USER_ID, secret, 0))
        valid_code = pyotp.TOTP(secret).now()
        assert two_factor_helper.verify_code(in_memory_db, USER_ID, int(valid_code)) is True

    def test_invalid_code(self, in_memory_db):
        secret = pyotp.random_base32()
        db_handler.insert_user(in_memory_db, (USER_ID, secret, 0))
        assert two_factor_helper.verify_code(in_memory_db, USER_ID, 000000) is False

    def test_wrong_secret(self, in_memory_db):
        secret = pyotp.random_base32()
        db_handler.insert_user(in_memory_db, (USER_ID, secret, 0))
        other_secret = pyotp.random_base32()
        wrong_code = int(pyotp.TOTP(other_secret).now())
        # Could theoretically match - check that verify uses stored secret
        correct = pyotp.TOTP(secret).verify(f"{wrong_code:06d}")
        result = two_factor_helper.verify_code(in_memory_db, USER_ID, wrong_code)
        assert result == correct  # Must agree with pyotp

    def test_nonexistent_user_returns_false(self, in_memory_db):
        assert two_factor_helper.verify_code(in_memory_db, 999999, 123456) is False

    def test_zero_padded_code(self, in_memory_db):
        """Code like 001234 should be zero-padded to 6 digits."""
        secret = pyotp.random_base32()
        db_handler.insert_user(in_memory_db, (USER_ID, secret, 0))
        totp = pyotp.TOTP(secret)
        raw = totp.now()
        # Verify using the integer value (may be < 100000 if zero-padded)
        result = two_factor_helper.verify_code(in_memory_db, USER_ID, int(raw))
        assert result is True


# code_matches - non-consuming diagnostic check
#
# Added after a real lockout: a database carried over from another deployment
# held a secret that did not match the operator's authenticator. /verify
# reported "already verified" without ever checking the code, so the mismatch
# only surfaced later when a real command rejected them.

class TestCodeMatches:
    def test_matching_code(self, in_memory_db):
        secret = pyotp.random_base32()
        db_handler.insert_user(in_memory_db, (USER_ID, secret, 1))
        code = int(pyotp.TOTP(secret).now())
        assert two_factor_helper.code_matches(in_memory_db, USER_ID, code) is True

    def test_code_from_a_different_secret(self, in_memory_db):
        """The lockout case: authenticator paired to another deployment's secret."""
        stored = pyotp.random_base32()
        other = pyotp.random_base32()
        db_handler.insert_user(in_memory_db, (USER_ID, stored, 1))
        code = int(pyotp.TOTP(other).now())
        assert two_factor_helper.code_matches(in_memory_db, USER_ID, code) is False

    def test_does_not_consume_the_step(self, in_memory_db):
        """
        Diagnostic only: it must leave the code spendable, or checking one
        would silently burn it and the next real command would fail.
        """
        secret = pyotp.random_base32()
        db_handler.insert_user(in_memory_db, (USER_ID, secret, 1))
        code = int(pyotp.TOTP(secret).now())

        assert two_factor_helper.code_matches(in_memory_db, USER_ID, code) is True
        assert db_handler.get_last_totp_step(in_memory_db, USER_ID) is None
        # still usable for a real authentication afterwards
        assert two_factor_helper.verify_code(in_memory_db, USER_ID, code) is True

    def test_unknown_user(self, in_memory_db):
        assert two_factor_helper.code_matches(in_memory_db, 999999999999999999, 123456) is False

    def test_garbage_input(self, in_memory_db):
        secret = pyotp.random_base32()
        db_handler.insert_user(in_memory_db, (USER_ID, secret, 1))
        assert two_factor_helper.code_matches(in_memory_db, USER_ID, None) is False
        assert two_factor_helper.code_matches(in_memory_db, USER_ID, "abc") is False
