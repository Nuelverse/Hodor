"""
Tests for the verification system.

Covers:
  - captcha generation: answer shape, single-digit problems, unpredictability
  - the challenge is NOT leaked in text (the whole point of image-only)
  - db_handler verification config: upsert, read, panel, toggle, delete
  - session mechanics: progress rendering, expiry, rate limiting
"""

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import captcha as captcha_lib
import db_handler


GUILD_ID = 200000000000000001
CHANNEL_ID = 300000000000000001
ROLE_ID = 400000000000000001


# Captcha generation

class TestCaptchaGeneration:
    def test_answer_length_matches_problem_count(self):
        for count in (4, 6, 8):
            _, answer = captcha_lib.generate(problem_count=count)
            assert len(answer) == count

    def test_answer_is_all_digits(self):
        _, answer = captcha_lib.generate()
        assert answer.isdigit()

    def test_every_problem_resolves_to_single_digit(self):
        """Answers must map onto a 0-9 keypad, so no problem may exceed 9."""
        for _ in range(500):
            _, value = captcha_lib._make_problem()
            assert 0 <= value <= 9

    def test_returns_valid_png(self):
        buffer, _ = captcha_lib.generate()
        data = buffer.getvalue()
        assert data[:8] == b"\x89PNG\r\n\x1a\n"
        assert len(data) > 500

    def test_answers_are_not_predictable(self):
        """Seeded from secrets, so repeated calls must not repeat."""
        answers = {captcha_lib.generate()[1] for _ in range(30)}
        assert len(answers) > 20

    def test_word_numbers_are_used(self):
        """Spelled-out operands defeat a naive numeral regex."""
        texts = [captcha_lib._make_problem()[0] for _ in range(200)]
        assert any(w in " ".join(texts) for w in ("one", "two", "three", "four", "five"))

    def test_problem_answers_are_consistent_with_text(self):
        """The stated arithmetic must actually equal the recorded answer."""
        words = {v: k for k, v in captcha_lib._WORD_NUMBERS.items()}

        def to_int(tok):
            return int(tok) if tok.isdigit() else words[tok]

        for _ in range(300):
            text, answer = captcha_lib._make_problem()
            left, op, right = text.replace(" = ?", "").split()
            expected = to_int(left) + to_int(right) if op == "+" else to_int(left) - to_int(right)
            assert expected == answer, f"{text} claimed {answer}"


class TestChallengeNotLeaked:
    """
    The reason this system exists: a captcha whose problems appear in message
    text is solvable by reading the message. generate() must hand back only an
    image and the answer - never the problem text.
    """

    def test_generate_returns_only_buffer_and_answer(self):
        result = captcha_lib.generate()
        assert len(result) == 2
        buffer, answer = result
        assert hasattr(buffer, "read")
        assert isinstance(answer, str)

    def test_answer_string_contains_no_problem_text(self):
        _, answer = captcha_lib.generate()
        for token in ("+", "-", "=", "?", "one", "two"):
            assert token not in answer


# Database layer

class TestVerificationConfig:
    def _init_guild(self, conn):
        db_handler.init_guild(conn, GUILD_ID, 1, 2)

    def test_unset_returns_none(self, in_memory_db):
        assert db_handler.get_verification_config(in_memory_db, GUILD_ID) is None

    def test_set_and_get(self, in_memory_db):
        self._init_guild(in_memory_db)
        db_handler.set_verification_config(in_memory_db, GUILD_ID, CHANNEL_ID, ROLE_ID, 24)
        cfg = db_handler.get_verification_config(in_memory_db, GUILD_ID)
        assert cfg['channel_id'] == CHANNEL_ID
        assert cfg['role_id'] == ROLE_ID
        assert cfg['min_account_age'] == 24
        assert cfg['enabled'] == 1

    def test_reconfigure_updates_instead_of_failing(self, in_memory_db):
        """Re-running /verify-setup must not blow up on the primary key."""
        self._init_guild(in_memory_db)
        db_handler.set_verification_config(in_memory_db, GUILD_ID, CHANNEL_ID, ROLE_ID, 0)
        db_handler.set_verification_config(in_memory_db, GUILD_ID, 999, 888, 12)
        cfg = db_handler.get_verification_config(in_memory_db, GUILD_ID)
        assert cfg['channel_id'] == 999
        assert cfg['role_id'] == 888
        assert cfg['min_account_age'] == 12

    def test_panel_message_id_roundtrip(self, in_memory_db):
        self._init_guild(in_memory_db)
        db_handler.set_verification_config(in_memory_db, GUILD_ID, CHANNEL_ID, ROLE_ID)
        db_handler.set_verification_panel(in_memory_db, GUILD_ID, 555)
        assert db_handler.get_verification_config(in_memory_db, GUILD_ID)['panel_message_id'] == 555

    def test_toggle_preserves_config(self, in_memory_db):
        self._init_guild(in_memory_db)
        db_handler.set_verification_config(in_memory_db, GUILD_ID, CHANNEL_ID, ROLE_ID, 6)
        db_handler.set_verification_enabled(in_memory_db, GUILD_ID, False)
        cfg = db_handler.get_verification_config(in_memory_db, GUILD_ID)
        assert cfg['enabled'] == 0
        assert cfg['role_id'] == ROLE_ID  # config survives being disabled

    def test_delete(self, in_memory_db):
        self._init_guild(in_memory_db)
        db_handler.set_verification_config(in_memory_db, GUILD_ID, CHANNEL_ID, ROLE_ID)
        assert db_handler.delete_verification_config(in_memory_db, GUILD_ID) is True
        assert db_handler.get_verification_config(in_memory_db, GUILD_ID) is None

    def test_only_enabled_guilds_listed(self, in_memory_db):
        self._init_guild(in_memory_db)
        db_handler.set_verification_config(in_memory_db, GUILD_ID, CHANNEL_ID, ROLE_ID)
        assert len(db_handler.get_all_verification_configs(in_memory_db)) == 1
        db_handler.set_verification_enabled(in_memory_db, GUILD_ID, False)
        assert len(db_handler.get_all_verification_configs(in_memory_db)) == 0

    def test_cache_invalidated_on_write(self, in_memory_db):
        """A stale cache here would silently keep verification pointing at an old role."""
        self._init_guild(in_memory_db)
        db_handler.set_verification_config(in_memory_db, GUILD_ID, CHANNEL_ID, ROLE_ID)
        assert db_handler.get_verification_config(in_memory_db, GUILD_ID)['role_id'] == ROLE_ID
        db_handler.set_verification_config(in_memory_db, GUILD_ID, CHANNEL_ID, 777)
        assert db_handler.get_verification_config(in_memory_db, GUILD_ID)['role_id'] == 777


# Branding

class TestGuildBranding:
    def test_defaults_when_unset(self, in_memory_db):
        b = db_handler.get_guild_branding(in_memory_db, GUILD_ID)
        assert b['color'] == db_handler.DEFAULT_BRAND_COLOR
        assert b['footer'] is None

    def test_set_and_get(self, in_memory_db):
        db_handler.init_guild(in_memory_db, GUILD_ID, 1, 2)
        db_handler.set_guild_branding(in_memory_db, GUILD_ID, color=0xFF0000, footer="Acme")
        b = db_handler.get_guild_branding(in_memory_db, GUILD_ID)
        assert b['color'] == 0xFF0000
        assert b['footer'] == "Acme"

    def test_partial_update_keeps_other_fields(self, in_memory_db):
        db_handler.init_guild(in_memory_db, GUILD_ID, 1, 2)
        db_handler.set_guild_branding(in_memory_db, GUILD_ID, color=0x00FF00, footer="Keep me")
        db_handler.set_guild_branding(in_memory_db, GUILD_ID, color=0x0000FF)
        b = db_handler.get_guild_branding(in_memory_db, GUILD_ID)
        assert b['color'] == 0x0000FF
        assert b['footer'] == "Keep me"


# Session mechanics

class TestSession:
    def _cog(self):
        from cogs.verification import Verification
        import types
        bot = types.SimpleNamespace(CONN=None)
        return Verification(bot)

    def test_progress_rendering(self):
        from cogs.verification import Verification, _Session
        s = _Session("123456")
        assert "(0/6)" in Verification._progress(s)
        s.entered = "123"
        text = Verification._progress(s)
        assert "(3/6)" in text
        assert "123" in text

    def test_expiry(self):
        from cogs.verification import _Session
        s = _Session("1234")
        assert s.expired is False
        s.expires_at = time.monotonic() - 1
        assert s.expired is True

    def test_rate_limit_trips_after_max_attempts(self):
        from cogs.verification import MAX_ATTEMPTS
        cog = self._cog()
        key = (GUILD_ID, 12345)
        assert cog._rate_limited(key) is False
        for _ in range(MAX_ATTEMPTS):
            cog._record_failure(key)
        assert cog._rate_limited(key) is True

    def test_expired_sessions_are_pruned(self):
        cog = self._cog()
        from cogs.verification import _Session
        live, dead = (GUILD_ID, 1), (GUILD_ID, 2)
        cog._sessions[live] = _Session("1234")
        stale = _Session("1234")
        stale.expires_at = time.monotonic() - 1
        cog._sessions[dead] = stale
        cog._prune_sessions()
        assert live in cog._sessions
        assert dead not in cog._sessions


# Name filter - action modes

class TestNameFilterActions:
    def test_action_labels(self):
        from cogs.name_filter import _action_label
        assert _action_label('ban') == "Ban"
        assert _action_label('kick') == "Kick"
        assert _action_label('timeout:24') == "Timeout (24h)"
        assert "log only" in _action_label('flag')

    def test_new_guilds_default_to_flag(self, in_memory_db):
        """
        A fresh server should report, not auto-ban. Patterns are untested at
        that point and a mistaken ban cannot be undone in bulk.
        """
        db_handler.init_guild(in_memory_db, GUILD_ID, 1, 2)
        assert db_handler.get_name_filter_action(in_memory_db, GUILD_ID) == 'flag'

    def test_action_can_be_raised_and_lowered(self, in_memory_db):
        db_handler.init_guild(in_memory_db, GUILD_ID, 1, 2)
        db_handler.set_name_filter_action(in_memory_db, GUILD_ID, 'ban')
        assert db_handler.get_name_filter_action(in_memory_db, GUILD_ID) == 'ban'
        db_handler.set_name_filter_action(in_memory_db, GUILD_ID, 'flag')
        assert db_handler.get_name_filter_action(in_memory_db, GUILD_ID) == 'flag'

    def test_existing_guild_action_is_not_silently_changed(self, in_memory_db):
        """Upgrading must not quietly downgrade a server that chose 'ban'."""
        in_memory_db.execute(
            "INSERT INTO guilds(guild_id, log_channel, name_filter_action) VALUES (?,?,?)",
            (GUILD_ID, 1, 'ban'))
        in_memory_db.commit()
        db_handler.clear_cache()
        assert db_handler.get_name_filter_action(in_memory_db, GUILD_ID) == 'ban'


# Join-log routing

class TestJoinLogRouting:
    def test_defaults_to_main_log_channel(self, in_memory_db):
        """No dedicated channel configured -> None, so logger falls back."""
        db_handler.init_guild(in_memory_db, GUILD_ID, 1, 2)
        db_handler.set_verification_config(in_memory_db, GUILD_ID, CHANNEL_ID, ROLE_ID)
        assert db_handler.get_verification_config(in_memory_db, GUILD_ID)['log_channel_id'] is None

    def test_can_be_set_at_setup(self, in_memory_db):
        db_handler.init_guild(in_memory_db, GUILD_ID, 1, 2)
        db_handler.set_verification_config(
            in_memory_db, GUILD_ID, CHANNEL_ID, ROLE_ID, 0, log_channel_id=777)
        assert db_handler.get_verification_config(in_memory_db, GUILD_ID)['log_channel_id'] == 777

    def test_can_be_changed_later(self, in_memory_db):
        db_handler.init_guild(in_memory_db, GUILD_ID, 1, 2)
        db_handler.set_verification_config(in_memory_db, GUILD_ID, CHANNEL_ID, ROLE_ID)
        db_handler.set_verification_log_channel(in_memory_db, GUILD_ID, 888)
        assert db_handler.get_verification_config(in_memory_db, GUILD_ID)['log_channel_id'] == 888

    def test_can_be_cleared_back_to_default(self, in_memory_db):
        db_handler.init_guild(in_memory_db, GUILD_ID, 1, 2)
        db_handler.set_verification_config(
            in_memory_db, GUILD_ID, CHANNEL_ID, ROLE_ID, 0, log_channel_id=777)
        db_handler.set_verification_log_channel(in_memory_db, GUILD_ID, None)
        assert db_handler.get_verification_config(in_memory_db, GUILD_ID)['log_channel_id'] is None

    def test_rerunning_setup_does_not_wipe_the_join_channel(self, in_memory_db):
        """Re-running /verify-setup without naming a channel must not reset it."""
        db_handler.init_guild(in_memory_db, GUILD_ID, 1, 2)
        db_handler.set_verification_config(
            in_memory_db, GUILD_ID, CHANNEL_ID, ROLE_ID, 0, log_channel_id=777)
        db_handler.set_verification_config(in_memory_db, GUILD_ID, CHANNEL_ID, ROLE_ID, 12)
        cfg = db_handler.get_verification_config(in_memory_db, GUILD_ID)
        assert cfg['log_channel_id'] == 777
        assert cfg['min_account_age'] == 12
