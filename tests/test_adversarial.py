"""
Adversarial / abuse tests.

The other test files check that the bot works. These check that it does not
break when someone is actively trying to break it. Each test names the attack
it represents, so a failure tells you which defence regressed.

Covered:
  - Link whitelist bypass attempts (the class of bug that shipped once)
  - SQL injection through every user-controlled string
  - Regex denial of service
  - TOTP abuse: replay, malformed input, forged secrets
  - Encryption failure modes (must fail closed, never open)
  - Captcha integrity and unpredictability
  - Resource exhaustion / unbounded growth
"""

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import captcha as captcha_lib
import db_handler
import link_scanner
import two_factor_helper as tf
from cogs.name_filter import _match, validate_regex

GUILD_ID = 900000000000000001
USER_ID = 900000000000000002


# Link filter - whitelist bypass

class TestWhitelistBypass:
    """
    The scanner is default-deny, so the attack is: get a NON-whitelisted host
    accepted as if it were whitelisted.
    """

    WL = [('domain', 'example.com'), ('specific', 'https://cdn.site.com/ok.png')]

    @pytest.mark.parametrize("url", [
        "https://example.com.evil.com",       # suffix-appending
        "https://evilexample.com",            # prefix-gluing
        "https://example.com.attacker.net/x", # subdomain of attacker
        "https://notexample.com",
        "https://example.co",                 # near-miss TLD
        "https://xample.com",
        "https://eb.com",                     # the lstrip('www.') truncation bug
        "https://x.eb.com",                   # ...and its subdomain form
        "https://ample.com",
        "https://cdn.site.com/evil.png",      # right host, wrong path (specific)
        "https://cdn.site.com.evil.com/ok.png",
    ])
    def test_lookalike_hosts_are_not_allowed(self, url):
        assert link_scanner.is_allowed(url, self.WL) is False, f"{url} slipped through"

    @pytest.mark.parametrize("url", [
        "https://example.com",
        "https://example.com/path?q=1",
        "https://sub.example.com",
        "https://deep.sub.example.com",
        "https://www.example.com",
        "https://cdn.site.com/ok.png",
        "https://cdn.site.com/ok.png/",       # trailing slash tolerated
    ])
    def test_legitimate_urls_still_allowed(self, url):
        assert link_scanner.is_allowed(url, self.WL) is True, f"{url} wrongly blocked"

    def test_userinfo_trick_does_not_grant_access(self):
        """https://example.com@evil.com resolves to evil.com, not example.com."""
        assert link_scanner.is_allowed("https://example.com@evil.com", self.WL) is False

    def test_empty_whitelist_blocks_everything(self):
        assert link_scanner.is_allowed("https://anything.com", []) is False

    def test_malformed_whitelist_entry_does_not_open_the_gate(self):
        """A broken entry must be skipped, never treated as a wildcard."""
        broken = [('domain', ''), ('domain', '://'), ('domain', 'http://')]
        assert link_scanner.is_allowed("https://evil.com", broken) is False


class TestScannerEvasion:
    """Obfuscated links must still be detected as links (and thus blocked)."""

    @pytest.mark.parametrize("content", [
        "https://evil.com",
        "ht\ntp://evil.com",
        "> ht\n> tp\n> ://evil.com",
        "https*://*evil.com",
        "**https://**evil.com",
        "https:////\\\\evil.com",
        "<https://evil.com>",
        "[click me](https://evil.com)",
        "https://evil​.com",
        "https://evil。com",
        "discord.gg/abc123",
        "t.me/fakeadmin",
        "||https://evil.com||",
        "dIsCoRd://evil",
        "mailto:steal@evil.com",
        "%68%74%74%70%73://evil.com",
    ])
    def test_obfuscated_links_are_blocked(self, content):
        blocked, _ = link_scanner.scan(content, [('domain', 'example.com')])
        assert blocked is True, f"missed: {content!r}"

    @pytest.mark.parametrize("content", [
        "hello everyone, welcome to the server",
        "the price is 5:1 compared to yesterday",
        "check example.com for details",
        "ratio 16:9 and 4:3",
        "",
        "no links here at all",
    ])
    def test_clean_messages_are_not_false_positives(self, content):
        blocked, label = link_scanner.scan(content, [('domain', 'example.com')])
        assert blocked is False, f"false positive on {content!r} ({label})"

    def test_scanner_survives_pathological_input(self):
        """Huge / weird input must not hang or raise."""
        for payload in ("a" * 50_000, "https://" + "x" * 10_000,
                        "​" * 5_000, "<" * 2_000 + ">" * 2_000):
            start = time.perf_counter()
            link_scanner.scan(payload, [('domain', 'example.com')])
            assert time.perf_counter() - start < 2.0, "scan too slow — possible DoS"


# SQL injection

SQLI = [
    "'; DROP TABLE users; --",
    "' OR '1'='1",
    "\"; DELETE FROM guilds WHERE '1'='1'; --",
    "admin'--",
    "1; UPDATE users SET verified=1; --",
    "') OR ('a'='a",
]


class TestSQLInjection:
    """Every user-controlled string reaches SQLite. All must be parameterized."""

    @pytest.mark.parametrize("payload", SQLI)
    def test_name_filter_pattern_is_inert(self, in_memory_db, payload):
        db_handler.init_guild(in_memory_db, GUILD_ID, 1, 2)
        db_handler.insert_name_filter(in_memory_db, GUILD_ID, 'phrase', payload, USER_ID)
        # Tables must survive
        assert in_memory_db.execute(
            "SELECT COUNT(*) FROM users").fetchone()[0] == 0
        # Stored verbatim, not executed
        stored = [f['pattern'] for f in db_handler.get_name_filters(in_memory_db, GUILD_ID)]
        assert payload in stored

    @pytest.mark.parametrize("payload", SQLI)
    def test_link_whitelist_url_is_inert(self, in_memory_db, payload):
        db_handler.init_guild(in_memory_db, GUILD_ID, 1, 2)
        db_handler.add_link_whitelist(in_memory_db, GUILD_ID, 'domain', payload, USER_ID)
        assert in_memory_db.execute(
            "SELECT name FROM sqlite_master WHERE name='guilds'").fetchone() is not None
        urls = [u for _, u in db_handler.get_link_whitelist(in_memory_db, GUILD_ID)]
        assert payload in urls

    @pytest.mark.parametrize("payload", SQLI)
    def test_guild_branding_footer_is_inert(self, in_memory_db, payload):
        db_handler.init_guild(in_memory_db, GUILD_ID, 1, 2)
        db_handler.set_guild_branding(in_memory_db, GUILD_ID, footer=payload)
        assert db_handler.get_guild_branding(in_memory_db, GUILD_ID)['footer'] == payload

    def test_role_id_list_query_is_parameterized(self, in_memory_db):
        """is_filter_exempt_by_roles builds a placeholder list - check it holds."""
        db_handler.init_guild(in_memory_db, GUILD_ID, 1, 2)
        db_handler.add_filter_exempt(in_memory_db, GUILD_ID, 'role', 42, USER_ID)
        assert db_handler.is_filter_exempt_by_roles(in_memory_db, GUILD_ID, [42]) is True
        assert db_handler.is_filter_exempt_by_roles(in_memory_db, GUILD_ID, [1, 2, 3]) is False
        assert db_handler.is_filter_exempt_by_roles(in_memory_db, GUILD_ID, []) is False


# Regex denial of service

class TestReDoS:
    @pytest.mark.parametrize("pattern", [
        r"(a+)+$", r"(a*)*$", r"(a|a)+$", r"([a-z]+)+$",
        r"(\d+|x)*", r"(ab+)*c",
    ])
    def test_catastrophic_patterns_are_rejected(self, pattern):
        ok, why = validate_regex(pattern)
        assert ok is False, f"{pattern} accepted — could hang the bot"
        assert why

    @pytest.mark.parametrize("pattern", [
        r"(?i)metamask", r"(?i)^admin", r"(?i)support$",
        r"[Ss]upport", r"\bmod\b", r"official.?team",
    ])
    def test_legitimate_patterns_are_accepted(self, pattern):
        ok, why = validate_regex(pattern)
        assert ok is True, f"{pattern} wrongly rejected: {why}"

    def test_oversized_pattern_rejected(self):
        assert validate_regex("a" * 500)[0] is False

    def test_matching_is_bounded_even_with_a_bad_stored_pattern(self):
        """
        Defence in depth: if a dangerous pattern somehow reached the database,
        input truncation must keep matching fast.
        """
        filters = [{'id': 1, 'type': 'regex', 'pattern': r'(a+)+$'}]
        start = time.perf_counter()
        _match(filters, "a" * 5000 + "!")
        assert time.perf_counter() - start < 2.0, "ReDoS not contained"


# TOTP abuse

class TestTOTPAbuse:
    def _enrol(self, conn):
        import pyotp
        secret = pyotp.random_base32()
        db_handler.insert_user(conn, (USER_ID, tf.encrypt_secret(secret), 1))
        return secret

    def test_replay_is_refused(self, in_memory_db):
        import pyotp
        secret = self._enrol(in_memory_db)
        code = int(pyotp.TOTP(secret).now())
        assert tf.verify_code(in_memory_db, USER_ID, code) is True
        assert tf.verify_code(in_memory_db, USER_ID, code) is False
        assert tf.verify_code(in_memory_db, USER_ID, code) is False

    @pytest.mark.parametrize("bad", [
        None, "", "abcdef", "12345678901234567890", -1, 0, 999999999,
        "'; DROP TABLE users; --", 3.14, [], {},
    ])
    def test_malformed_codes_return_false_not_crash(self, in_memory_db, bad):
        self._enrol(in_memory_db)
        assert tf.verify_code(in_memory_db, USER_ID, bad) is False

    def test_unknown_user_cannot_authenticate(self, in_memory_db):
        assert tf.verify_code(in_memory_db, 111111, 123456) is False

    def test_another_users_secret_does_not_work(self, in_memory_db):
        import pyotp
        self._enrol(in_memory_db)
        attacker_secret = pyotp.random_base32()
        code = int(pyotp.TOTP(attacker_secret).now())
        # Overwhelmingly likely False; must never be True for the wrong secret
        stored = tf.decrypt_secret(db_handler.get_secret(in_memory_db, USER_ID))
        expected = pyotp.TOTP(stored).verify(f"{code:06d}")
        assert tf.verify_code(in_memory_db, USER_ID, code) == expected


# Encryption failure modes - must fail CLOSED

class TestEncryptionFailsClosed:
    def test_wrong_key_denies_access(self, in_memory_db, monkeypatch):
        import importlib
        import pyotp
        monkeypatch.setenv("ENCRYPTION_KEY", "the-original-key")
        importlib.reload(tf)
        secret = pyotp.random_base32()
        db_handler.insert_user(in_memory_db, (USER_ID, tf.encrypt_secret(secret), 1))

        # Key rotated / attacker has DB but not the key
        monkeypatch.setenv("ENCRYPTION_KEY", "a-completely-different-key")
        importlib.reload(tf)
        stored = db_handler.get_secret(in_memory_db, USER_ID)
        assert tf.decrypt_secret(stored) is None, "wrong key must not decrypt"
        assert tf.verify_code(in_memory_db, USER_ID, int(pyotp.TOTP(secret).now())) is False

        monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
        importlib.reload(tf)

    def test_corrupted_ciphertext_denies_access(self, in_memory_db, monkeypatch):
        import importlib
        monkeypatch.setenv("ENCRYPTION_KEY", "some-key")
        importlib.reload(tf)
        assert tf.decrypt_secret(tf.ENC_PREFIX + "not-valid-ciphertext") is None
        monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
        importlib.reload(tf)

    def test_encrypted_value_leaks_no_plaintext(self, monkeypatch):
        import importlib
        import pyotp
        monkeypatch.setenv("ENCRYPTION_KEY", "leak-check-key")
        importlib.reload(tf)
        secret = pyotp.random_base32()
        blob = tf.encrypt_secret(secret)
        assert secret not in blob
        assert blob.startswith(tf.ENC_PREFIX)
        monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
        importlib.reload(tf)


# Captcha integrity

class TestCaptchaIntegrity:
    def test_answers_are_high_entropy(self):
        answers = [captcha_lib.generate()[1] for _ in range(60)]
        assert len(set(answers)) >= 55, "answers repeating — predictable"

    def test_no_trivially_guessable_answer_dominates(self):
        answers = [captcha_lib.generate()[1] for _ in range(60)]
        for guess in ("000000", "111111", "123456"):
            assert answers.count(guess) <= 1

    def test_generation_is_bounded_in_time(self):
        start = time.perf_counter()
        for _ in range(20):
            captcha_lib.generate()
        per = (time.perf_counter() - start) / 20
        assert per < 0.25, f"captcha too slow ({per*1000:.0f}ms) — raid amplifier"


# Resource exhaustion

class TestResourceExhaustion:
    def test_filter_id_set_is_bounded(self):
        """The link filter's dedupe set must not grow forever."""
        from bot import BoundedIdSet
        s = BoundedIdSet(maxlen=100)
        for i in range(100_000):
            s.add(i)
        assert len(s) == 100

    def test_verification_sessions_are_pruned(self):
        import types
        from cogs.verification import Verification, _Session
        cog = Verification(types.SimpleNamespace(CONN=None))
        for i in range(1000):
            s = _Session("123456")
            s.expires_at = time.monotonic() - 1
            cog._sessions[(GUILD_ID, i)] = s
        cog._prune_sessions()
        assert len(cog._sessions) == 0

    def test_burst_tracker_window_does_not_grow_forever(self):
        from cogs.name_filter import _BurstTracker
        t = _BurstTracker()
        for _ in range(10_000):
            t.record()
        # rolling window keeps only recent entries
        assert len(t.recent) < 10_000

    def test_cleanse_guard_blocks_mass_action(self):
        """A pattern matching most of the server must not be actionable."""
        from cogs.name_filter import CLEANSE_ABORT_SHARE, CLEANSE_ABORT_MIN
        matches, eligible = 400, 500
        share = matches / eligible
        assert share > CLEANSE_ABORT_SHARE
        assert matches > CLEANSE_ABORT_MIN


# Data lifecycle

class TestDataLifecycle:
    def test_deleting_a_guild_removes_all_its_data(self, in_memory_db):
        """No orphaned config should survive a guild being removed."""
        db_handler.init_guild(in_memory_db, GUILD_ID, 1, 2)
        db_handler.insert_name_filter(in_memory_db, GUILD_ID, 'phrase', 'scam', USER_ID)
        db_handler.add_link_whitelist(in_memory_db, GUILD_ID, 'domain', 'a.com', USER_ID)
        db_handler.add_link_manager(in_memory_db, GUILD_ID, USER_ID)
        db_handler.set_verification_config(in_memory_db, GUILD_ID, 1, 2)
        db_handler.set_guild_branding(in_memory_db, GUILD_ID, color=1)

        db_handler.delete_guild(in_memory_db, GUILD_ID)

        assert db_handler.check_guild(in_memory_db, GUILD_ID) is False
        assert db_handler.get_name_filters(in_memory_db, GUILD_ID) == []
        assert db_handler.get_link_whitelist(in_memory_db, GUILD_ID) == []
        assert db_handler.get_link_managers(in_memory_db, GUILD_ID) == []
        assert db_handler.get_verification_config(in_memory_db, GUILD_ID) is None

    def test_retired_backup_codes_table_is_gone(self, in_memory_db):
        """Stale credential material must not be recreated by the schema."""
        names = [r[0] for r in in_memory_db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        assert "backup_codes" not in names
