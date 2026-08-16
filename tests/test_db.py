"""
Tests for db_handler.py

Covers every table and every function:
  - Users (2FA)         - insert, check, get_secret, verify, delete
  - Guilds              - init_guild, check_guild, delete_guild, log/event channels,
                          link_filter toggle, panic_active, announce_timeout
  - Webhook settings    - check_webhook, set_webhook_parameters, temp_disable CRUD
  - Trusted members     - authorise, deauthorise, check, get
  - Announcement channels - insert, delete, get
  - Link whitelist      - add, remove, get (domain + specific, duplicate prevention)
  - Link filter exempt  - add, remove, is_exempt, is_exempt_by_roles, get_all
  - Safe roles          - add, remove, is_safe, get
  - Link managers       - add, remove, is_manager, get
  - Panic backups       - save role/channel backup, get, clear
  - delete_guild cascade - verifies all child records are removed
"""

import pytest
import sqlite3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import db_handler


# Shared IDs

USER_A    = 100000000000000001
USER_B    = 100000000000000002
GUILD_1   = 200000000000000001
GUILD_2   = 200000000000000002
CHANNEL_1 = 300000000000000001
CHANNEL_2 = 300000000000000002
ROLE_1    = 400000000000000001
ROLE_2    = 400000000000000002


# Helper

def _insert_guild(conn, guild_id=GUILD_1, log_channel=CHANNEL_1):
    db_handler.init_guild(conn, guild_id, log_channel=log_channel)


# Users (2FA)

class TestUsers:
    def test_insert_and_check(self, in_memory_db):
        db_handler.insert_user(in_memory_db, (USER_A, "SECRET", 0))
        assert db_handler.check_user(in_memory_db, USER_A) is True

    def test_check_nonexistent_returns_false(self, in_memory_db):
        assert db_handler.check_user(in_memory_db, 999) is False

    def test_get_secret(self, in_memory_db):
        db_handler.insert_user(in_memory_db, (USER_A, "MYSECRET", 0))
        assert db_handler.get_secret(in_memory_db, USER_A) == "MYSECRET"

    def test_get_secret_nonexistent_returns_none(self, in_memory_db):
        assert db_handler.get_secret(in_memory_db, 999) is None

    def test_check_verified_default_zero(self, in_memory_db):
        db_handler.insert_user(in_memory_db, (USER_A, "SECRET", 0))
        assert db_handler.check_verified(in_memory_db, USER_A) == 0

    def test_verify_sets_flag(self, in_memory_db):
        db_handler.insert_user(in_memory_db, (USER_A, "SECRET", 0))
        db_handler.verify(in_memory_db, USER_A)
        assert db_handler.check_verified(in_memory_db, USER_A) == 1

    def test_check_verified_nonexistent_returns_zero(self, in_memory_db):
        assert db_handler.check_verified(in_memory_db, 999) == 0

    def test_delete_user(self, in_memory_db):
        db_handler.insert_user(in_memory_db, (USER_A, "SECRET", 0))
        db_handler.delete_user(in_memory_db, USER_A)
        assert db_handler.check_user(in_memory_db, USER_A) is False

    def test_duplicate_user_raises(self, in_memory_db):
        db_handler.insert_user(in_memory_db, (USER_A, "SECRET", 0))
        with pytest.raises(Exception):
            db_handler.insert_user(in_memory_db, (USER_A, "OTHER", 0))


# Guilds

class TestGuilds:
    def test_init_guild_and_check(self, in_memory_db):
        _insert_guild(in_memory_db)
        assert db_handler.check_guild(in_memory_db, GUILD_1) is True

    def test_check_guild_nonexistent(self, in_memory_db):
        assert db_handler.check_guild(in_memory_db, 999) is False

    def test_get_log_channel(self, in_memory_db):
        _insert_guild(in_memory_db, log_channel=CHANNEL_1)
        assert db_handler.get_log_channel(in_memory_db, GUILD_1) == CHANNEL_1

    def test_set_log_channel(self, in_memory_db):
        _insert_guild(in_memory_db)
        db_handler.set_log_channel(in_memory_db, GUILD_1, CHANNEL_2)
        assert db_handler.get_log_channel(in_memory_db, GUILD_1) == CHANNEL_2

    def test_link_filter_default_off(self, in_memory_db):
        _insert_guild(in_memory_db)
        assert db_handler.get_link_filter_enabled(in_memory_db, GUILD_1) is False

    def test_set_link_filter_on(self, in_memory_db):
        _insert_guild(in_memory_db)
        db_handler.set_link_filter_enabled(in_memory_db, GUILD_1, True)
        assert db_handler.get_link_filter_enabled(in_memory_db, GUILD_1) is True

    def test_toggle_link_filter(self, in_memory_db):
        _insert_guild(in_memory_db)
        new_state = db_handler.toggle_link_filter(in_memory_db, GUILD_1)
        assert new_state is True
        new_state = db_handler.toggle_link_filter(in_memory_db, GUILD_1)
        assert new_state is False

    def test_panic_active_default_false(self, in_memory_db):
        _insert_guild(in_memory_db)
        assert db_handler.get_panic_active(in_memory_db, GUILD_1) is False

    def test_set_panic_active(self, in_memory_db):
        _insert_guild(in_memory_db)
        db_handler.set_panic_active(in_memory_db, GUILD_1, True)
        assert db_handler.get_panic_active(in_memory_db, GUILD_1) is True
        db_handler.set_panic_active(in_memory_db, GUILD_1, False)
        assert db_handler.get_panic_active(in_memory_db, GUILD_1) is False

    def test_announce_timeout_default(self, in_memory_db):
        _insert_guild(in_memory_db)
        assert db_handler.get_announce_timeout(in_memory_db, GUILD_1) == 300

    def test_set_announce_timeout(self, in_memory_db):
        _insert_guild(in_memory_db)
        db_handler.set_announce_timeout(in_memory_db, GUILD_1, 600)
        assert db_handler.get_announce_timeout(in_memory_db, GUILD_1) == 600

    def test_announce_timeout_missing_guild_returns_default(self, in_memory_db):
        """No guild row → returns the fallback 300."""
        assert db_handler.get_announce_timeout(in_memory_db, 999) == 300

    def test_delete_guild_removes_row(self, in_memory_db):
        _insert_guild(in_memory_db)
        db_handler.delete_guild(in_memory_db, GUILD_1)
        assert db_handler.check_guild(in_memory_db, GUILD_1) is False


# Webhook settings

class TestWebhooks:
    def test_webhook_protection_default_on(self, in_memory_db):
        """init_guild sets webhook_protection=1 by default."""
        _insert_guild(in_memory_db)
        assert db_handler.check_webhook(in_memory_db, GUILD_1) is True

    def test_set_webhook_parameters(self, in_memory_db):
        _insert_guild(in_memory_db)
        db_handler.set_webhook_parameters(in_memory_db, (0, 1, GUILD_1))
        assert db_handler.check_webhook(in_memory_db, GUILD_1) is False
        assert db_handler.check_verified_bots(in_memory_db, GUILD_1) is True

    def test_temp_disable_set_and_get(self, in_memory_db):
        _insert_guild(in_memory_db)
        db_handler.set_webhook_temp_disable(in_memory_db, GUILD_1, USER_A, "2099-01-01T00:00:00")
        result = db_handler.get_webhook_temp_disable(in_memory_db, GUILD_1)
        assert result == "2099-01-01T00:00:00"

    def test_temp_disable_upsert(self, in_memory_db):
        """Calling set_webhook_temp_disable twice updates the record."""
        _insert_guild(in_memory_db)
        db_handler.set_webhook_temp_disable(in_memory_db, GUILD_1, USER_A, "2099-01-01T00:00:00")
        db_handler.set_webhook_temp_disable(in_memory_db, GUILD_1, USER_B, "2099-06-01T00:00:00")
        result = db_handler.get_webhook_temp_disable(in_memory_db, GUILD_1)
        assert result == "2099-06-01T00:00:00"

    def test_temp_disable_clear(self, in_memory_db):
        _insert_guild(in_memory_db)
        db_handler.set_webhook_temp_disable(in_memory_db, GUILD_1, USER_A, "2099-01-01T00:00:00")
        db_handler.clear_webhook_temp_disable(in_memory_db, GUILD_1)
        assert db_handler.get_webhook_temp_disable(in_memory_db, GUILD_1) is None

    def test_temp_disable_missing_returns_none(self, in_memory_db):
        _insert_guild(in_memory_db)
        assert db_handler.get_webhook_temp_disable(in_memory_db, GUILD_1) is None


# Trusted members (Announcers)

class TestTrustedMembers:
    def test_authorise_and_check(self, in_memory_db):
        db_handler.authorise_member(in_memory_db, (GUILD_1, USER_A))
        assert db_handler.check_authorised(in_memory_db, (GUILD_1, USER_A)) is True

    def test_check_unauthorised_returns_false(self, in_memory_db):
        assert db_handler.check_authorised(in_memory_db, (GUILD_1, USER_A)) is False

    def test_deauthorise(self, in_memory_db):
        db_handler.authorise_member(in_memory_db, (GUILD_1, USER_A))
        db_handler.deauthorise_member(in_memory_db, (GUILD_1, USER_A))
        assert db_handler.check_authorised(in_memory_db, (GUILD_1, USER_A)) is False

    def test_get_trusted_members(self, in_memory_db):
        db_handler.authorise_member(in_memory_db, (GUILD_1, USER_A))
        db_handler.authorise_member(in_memory_db, (GUILD_1, USER_B))
        members = db_handler.get_trusted_members(in_memory_db, GUILD_1)
        assert set(members) == {USER_A, USER_B}

    def test_guild_isolation(self, in_memory_db):
        """Adding a member in guild 1 should not appear in guild 2."""
        db_handler.authorise_member(in_memory_db, (GUILD_1, USER_A))
        assert db_handler.check_authorised(in_memory_db, (GUILD_2, USER_A)) is False

    def test_duplicate_authorise_raises(self, in_memory_db):
        db_handler.authorise_member(in_memory_db, (GUILD_1, USER_A))
        with pytest.raises(Exception):
            db_handler.authorise_member(in_memory_db, (GUILD_1, USER_A))


# Announcement channels

class TestAnnouncementChannels:
    def test_insert_and_get(self, in_memory_db):
        db_handler.insert_channel(in_memory_db, (CHANNEL_1, GUILD_1))
        channels = db_handler.get_channels(in_memory_db, GUILD_1)
        assert CHANNEL_1 in channels

    def test_delete_channel(self, in_memory_db):
        db_handler.insert_channel(in_memory_db, (CHANNEL_1, GUILD_1))
        db_handler.delete_channel(in_memory_db, CHANNEL_1)
        assert CHANNEL_1 not in db_handler.get_channels(in_memory_db, GUILD_1)

    def test_multiple_channels(self, in_memory_db):
        db_handler.insert_channel(in_memory_db, (CHANNEL_1, GUILD_1))
        db_handler.insert_channel(in_memory_db, (CHANNEL_2, GUILD_1))
        channels = db_handler.get_channels(in_memory_db, GUILD_1)
        assert set(channels) == {CHANNEL_1, CHANNEL_2}

    def test_channels_empty_by_default(self, in_memory_db):
        assert db_handler.get_channels(in_memory_db, GUILD_1) == []


# Link whitelist

class TestLinkWhitelist:
    def test_add_domain_entry(self, in_memory_db):
        result = db_handler.add_link_whitelist(in_memory_db, GUILD_1, "domain", "example.com", USER_A)
        assert result is True
        entries = db_handler.get_link_whitelist(in_memory_db, GUILD_1)
        assert ("domain", "example.com") in entries

    def test_add_specific_entry(self, in_memory_db):
        db_handler.add_link_whitelist(in_memory_db, GUILD_1, "specific", "https://example.com/page", USER_A)
        entries = db_handler.get_link_whitelist(in_memory_db, GUILD_1)
        assert ("specific", "https://example.com/page") in entries

    def test_duplicate_returns_false(self, in_memory_db):
        db_handler.add_link_whitelist(in_memory_db, GUILD_1, "domain", "example.com", USER_A)
        result = db_handler.add_link_whitelist(in_memory_db, GUILD_1, "domain", "example.com", USER_A)
        assert result is False

    def test_remove_existing_entry(self, in_memory_db):
        db_handler.add_link_whitelist(in_memory_db, GUILD_1, "domain", "example.com", USER_A)
        result = db_handler.remove_link_whitelist(in_memory_db, GUILD_1, "example.com")
        assert result is True
        entries = db_handler.get_link_whitelist(in_memory_db, GUILD_1)
        assert ("domain", "example.com") not in entries

    def test_remove_nonexistent_returns_false(self, in_memory_db):
        result = db_handler.remove_link_whitelist(in_memory_db, GUILD_1, "nothere.com")
        assert result is False

    def test_guild_isolation(self, in_memory_db):
        db_handler.add_link_whitelist(in_memory_db, GUILD_1, "domain", "example.com", USER_A)
        entries_g2 = db_handler.get_link_whitelist(in_memory_db, GUILD_2)
        assert entries_g2 == []

    def test_empty_whitelist(self, in_memory_db):
        assert db_handler.get_link_whitelist(in_memory_db, GUILD_1) == []


# Link filter entity whitelist (exempt channels/roles/users/categories)

class TestFilterExemptions:
    def test_add_channel_exempt(self, in_memory_db):
        result = db_handler.add_filter_exempt(in_memory_db, GUILD_1, "channel", CHANNEL_1, USER_A)
        assert result is True
        assert db_handler.is_filter_exempt(in_memory_db, GUILD_1, "channel", CHANNEL_1) is True

    def test_add_role_exempt(self, in_memory_db):
        db_handler.add_filter_exempt(in_memory_db, GUILD_1, "role", ROLE_1, USER_A)
        assert db_handler.is_filter_exempt(in_memory_db, GUILD_1, "role", ROLE_1) is True

    def test_add_user_exempt(self, in_memory_db):
        db_handler.add_filter_exempt(in_memory_db, GUILD_1, "user", USER_A, USER_A)
        assert db_handler.is_filter_exempt(in_memory_db, GUILD_1, "user", USER_A) is True

    def test_add_category_exempt(self, in_memory_db):
        db_handler.add_filter_exempt(in_memory_db, GUILD_1, "category", 500, USER_A)
        assert db_handler.is_filter_exempt(in_memory_db, GUILD_1, "category", 500) is True

    def test_duplicate_exempt_returns_false(self, in_memory_db):
        db_handler.add_filter_exempt(in_memory_db, GUILD_1, "channel", CHANNEL_1, USER_A)
        result = db_handler.add_filter_exempt(in_memory_db, GUILD_1, "channel", CHANNEL_1, USER_A)
        assert result is False

    def test_remove_exempt(self, in_memory_db):
        db_handler.add_filter_exempt(in_memory_db, GUILD_1, "channel", CHANNEL_1, USER_A)
        result = db_handler.remove_filter_exempt(in_memory_db, GUILD_1, "channel", CHANNEL_1)
        assert result is True
        assert db_handler.is_filter_exempt(in_memory_db, GUILD_1, "channel", CHANNEL_1) is False

    def test_remove_nonexistent_returns_false(self, in_memory_db):
        result = db_handler.remove_filter_exempt(in_memory_db, GUILD_1, "channel", 9999)
        assert result is False

    def test_is_exempt_by_roles_true(self, in_memory_db):
        db_handler.add_filter_exempt(in_memory_db, GUILD_1, "role", ROLE_1, USER_A)
        assert db_handler.is_filter_exempt_by_roles(in_memory_db, GUILD_1, [ROLE_1, ROLE_2]) is True

    def test_is_exempt_by_roles_false(self, in_memory_db):
        db_handler.add_filter_exempt(in_memory_db, GUILD_1, "role", ROLE_1, USER_A)
        assert db_handler.is_filter_exempt_by_roles(in_memory_db, GUILD_1, [ROLE_2]) is False

    def test_is_exempt_by_roles_empty_list(self, in_memory_db):
        assert db_handler.is_filter_exempt_by_roles(in_memory_db, GUILD_1, []) is False

    def test_get_filter_exemptions(self, in_memory_db):
        db_handler.add_filter_exempt(in_memory_db, GUILD_1, "channel", CHANNEL_1, USER_A)
        db_handler.add_filter_exempt(in_memory_db, GUILD_1, "role", ROLE_1, USER_A)
        exemptions = db_handler.get_filter_exemptions(in_memory_db, GUILD_1)
        assert ("channel", CHANNEL_1) in exemptions
        assert ("role", ROLE_1) in exemptions

    def test_not_exempt_by_default(self, in_memory_db):
        assert db_handler.is_filter_exempt(in_memory_db, GUILD_1, "user", USER_A) is False


# Safe roles

class TestSafeRoles:
    def test_add_safe_role(self, in_memory_db):
        result = db_handler.add_safe_role(in_memory_db, GUILD_1, ROLE_1)
        assert result is True
        assert db_handler.is_safe_role(in_memory_db, GUILD_1, ROLE_1) is True

    def test_duplicate_safe_role_returns_false(self, in_memory_db):
        db_handler.add_safe_role(in_memory_db, GUILD_1, ROLE_1)
        assert db_handler.add_safe_role(in_memory_db, GUILD_1, ROLE_1) is False

    def test_remove_safe_role(self, in_memory_db):
        db_handler.add_safe_role(in_memory_db, GUILD_1, ROLE_1)
        result = db_handler.remove_safe_role(in_memory_db, GUILD_1, ROLE_1)
        assert result is True
        assert db_handler.is_safe_role(in_memory_db, GUILD_1, ROLE_1) is False

    def test_remove_nonexistent_safe_role(self, in_memory_db):
        assert db_handler.remove_safe_role(in_memory_db, GUILD_1, 9999) is False

    def test_get_safe_roles(self, in_memory_db):
        db_handler.add_safe_role(in_memory_db, GUILD_1, ROLE_1)
        db_handler.add_safe_role(in_memory_db, GUILD_1, ROLE_2)
        roles = db_handler.get_safe_roles(in_memory_db, GUILD_1)
        assert set(roles) == {ROLE_1, ROLE_2}

    def test_guild_isolation(self, in_memory_db):
        db_handler.add_safe_role(in_memory_db, GUILD_1, ROLE_1)
        assert db_handler.is_safe_role(in_memory_db, GUILD_2, ROLE_1) is False


# Name filter exempt roles

class TestNameFilterExemptRoles:
    def test_add_returns_true_and_is_stored(self, in_memory_db):
        assert db_handler.add_name_filter_exempt_role(
            in_memory_db, GUILD_1, ROLE_1, USER_A) is True
        assert ROLE_1 in db_handler.get_name_filter_exempt_roles(in_memory_db, GUILD_1)

    def test_duplicate_returns_false(self, in_memory_db):
        db_handler.add_name_filter_exempt_role(in_memory_db, GUILD_1, ROLE_1, USER_A)
        assert db_handler.add_name_filter_exempt_role(
            in_memory_db, GUILD_1, ROLE_1, USER_A) is False

    def test_remove(self, in_memory_db):
        db_handler.add_name_filter_exempt_role(in_memory_db, GUILD_1, ROLE_1, USER_A)
        assert db_handler.remove_name_filter_exempt_role(
            in_memory_db, GUILD_1, ROLE_1) is True
        assert ROLE_1 not in db_handler.get_name_filter_exempt_roles(in_memory_db, GUILD_1)

    def test_remove_nonexistent_returns_false(self, in_memory_db):
        assert db_handler.remove_name_filter_exempt_role(
            in_memory_db, GUILD_1, 9999) is False

    def test_empty_by_default(self, in_memory_db):
        assert db_handler.get_name_filter_exempt_roles(in_memory_db, GUILD_1) == set()

    def test_guild_isolation(self, in_memory_db):
        db_handler.add_name_filter_exempt_role(in_memory_db, GUILD_1, ROLE_1, USER_A)
        assert ROLE_1 not in db_handler.get_name_filter_exempt_roles(in_memory_db, GUILD_2)

    def test_add_invalidates_cache(self, in_memory_db):
        """A stale cache would keep scanning a role the owner just exempted."""
        db_handler.get_name_filter_exempt_roles(in_memory_db, GUILD_1)  # prime
        db_handler.add_name_filter_exempt_role(in_memory_db, GUILD_1, ROLE_1, USER_A)
        assert ROLE_1 in db_handler.get_name_filter_exempt_roles(in_memory_db, GUILD_1)

    def test_remove_invalidates_cache(self, in_memory_db):
        """The dangerous direction: a stale cache would keep a role exempt."""
        db_handler.add_name_filter_exempt_role(in_memory_db, GUILD_1, ROLE_1, USER_A)
        db_handler.get_name_filter_exempt_roles(in_memory_db, GUILD_1)  # prime
        db_handler.remove_name_filter_exempt_role(in_memory_db, GUILD_1, ROLE_1)
        assert ROLE_1 not in db_handler.get_name_filter_exempt_roles(in_memory_db, GUILD_1)


# Link managers


class TestLinkManagers:
    def test_add_and_check(self, in_memory_db):
        result = db_handler.add_link_manager(in_memory_db, GUILD_1, USER_A)
        assert result is True
        assert db_handler.is_link_manager(in_memory_db, GUILD_1, USER_A) is True

    def test_duplicate_returns_false(self, in_memory_db):
        db_handler.add_link_manager(in_memory_db, GUILD_1, USER_A)
        assert db_handler.add_link_manager(in_memory_db, GUILD_1, USER_A) is False

    def test_remove(self, in_memory_db):
        db_handler.add_link_manager(in_memory_db, GUILD_1, USER_A)
        result = db_handler.remove_link_manager(in_memory_db, GUILD_1, USER_A)
        assert result is True
        assert db_handler.is_link_manager(in_memory_db, GUILD_1, USER_A) is False

    def test_remove_nonexistent(self, in_memory_db):
        assert db_handler.remove_link_manager(in_memory_db, GUILD_1, 9999) is False

    def test_get_link_managers(self, in_memory_db):
        db_handler.add_link_manager(in_memory_db, GUILD_1, USER_A)
        db_handler.add_link_manager(in_memory_db, GUILD_1, USER_B)
        managers = db_handler.get_link_managers(in_memory_db, GUILD_1)
        assert set(managers) == {USER_A, USER_B}

    def test_guild_isolation(self, in_memory_db):
        db_handler.add_link_manager(in_memory_db, GUILD_1, USER_A)
        assert db_handler.is_link_manager(in_memory_db, GUILD_2, USER_A) is False

    def test_not_manager_by_default(self, in_memory_db):
        assert db_handler.is_link_manager(in_memory_db, GUILD_1, USER_A) is False


# Panic backups

class TestPanicBackups:
    def test_save_and_get_role_backup(self, in_memory_db):
        db_handler.save_panic_role_backup(in_memory_db, GUILD_1, ROLE_1, 0x8)
        backups = db_handler.get_panic_role_backups(in_memory_db, GUILD_1)
        assert (ROLE_1, 0x8) in backups

    def test_save_multiple_role_backups(self, in_memory_db):
        db_handler.save_panic_role_backup(in_memory_db, GUILD_1, ROLE_1, 0x8)
        db_handler.save_panic_role_backup(in_memory_db, GUILD_1, ROLE_2, 0x4)
        backups = db_handler.get_panic_role_backups(in_memory_db, GUILD_1)
        assert len(backups) == 2

    def test_save_and_get_channel_backup(self, in_memory_db):
        db_handler.save_panic_channel_backup(in_memory_db, GUILD_1, CHANNEL_1, allow_value=0, deny_value=1024)
        backups = db_handler.get_panic_channel_backups(in_memory_db, GUILD_1)
        assert (CHANNEL_1, 0, 1024) in backups

    def test_clear_panic_backups(self, in_memory_db):
        db_handler.save_panic_role_backup(in_memory_db, GUILD_1, ROLE_1, 0x8)
        db_handler.save_panic_channel_backup(in_memory_db, GUILD_1, CHANNEL_1, 0, 1024)
        db_handler.clear_panic_backups(in_memory_db, GUILD_1)
        assert db_handler.get_panic_role_backups(in_memory_db, GUILD_1) == []
        assert db_handler.get_panic_channel_backups(in_memory_db, GUILD_1) == []

    def test_guild_isolation(self, in_memory_db):
        db_handler.save_panic_role_backup(in_memory_db, GUILD_1, ROLE_1, 0x8)
        assert db_handler.get_panic_role_backups(in_memory_db, GUILD_2) == []

    def test_empty_backups_before_panic(self, in_memory_db):
        assert db_handler.get_panic_role_backups(in_memory_db, GUILD_1) == []
        assert db_handler.get_panic_channel_backups(in_memory_db, GUILD_1) == []


# delete_guild cascade

class TestDeleteGuildCascade:
    def test_cascade_removes_trusted_members(self, in_memory_db):
        _insert_guild(in_memory_db)
        db_handler.authorise_member(in_memory_db, (GUILD_1, USER_A))
        db_handler.delete_guild(in_memory_db, GUILD_1)
        assert db_handler.check_authorised(in_memory_db, (GUILD_1, USER_A)) is False

    def test_cascade_removes_channels(self, in_memory_db):
        _insert_guild(in_memory_db)
        db_handler.insert_channel(in_memory_db, (CHANNEL_1, GUILD_1))
        db_handler.delete_guild(in_memory_db, GUILD_1)
        assert db_handler.get_channels(in_memory_db, GUILD_1) == []

    def test_cascade_removes_link_whitelist(self, in_memory_db):
        _insert_guild(in_memory_db)
        db_handler.add_link_whitelist(in_memory_db, GUILD_1, "domain", "example.com", USER_A)
        db_handler.delete_guild(in_memory_db, GUILD_1)
        assert db_handler.get_link_whitelist(in_memory_db, GUILD_1) == []

    def test_cascade_removes_link_managers(self, in_memory_db):
        _insert_guild(in_memory_db)
        db_handler.add_link_manager(in_memory_db, GUILD_1, USER_A)
        db_handler.delete_guild(in_memory_db, GUILD_1)
        assert db_handler.is_link_manager(in_memory_db, GUILD_1, USER_A) is False

    def test_cascade_removes_filter_exemptions(self, in_memory_db):
        _insert_guild(in_memory_db)
        db_handler.add_filter_exempt(in_memory_db, GUILD_1, "channel", CHANNEL_1, USER_A)
        db_handler.delete_guild(in_memory_db, GUILD_1)
        assert db_handler.is_filter_exempt(in_memory_db, GUILD_1, "channel", CHANNEL_1) is False

    def test_cascade_removes_webhook_temp_disable(self, in_memory_db):
        _insert_guild(in_memory_db)
        db_handler.set_webhook_temp_disable(in_memory_db, GUILD_1, USER_A, "2099-01-01T00:00:00")
        db_handler.delete_guild(in_memory_db, GUILD_1)
        assert db_handler.get_webhook_temp_disable(in_memory_db, GUILD_1) is None

    def test_cascade_removes_name_filter_exempt_roles(self, in_memory_db):
        _insert_guild(in_memory_db)
        db_handler.add_name_filter_exempt_role(in_memory_db, GUILD_1, ROLE_1, USER_A)
        db_handler.delete_guild(in_memory_db, GUILD_1)
        assert db_handler.get_name_filter_exempt_roles(in_memory_db, GUILD_1) == set()

    def test_cascade_does_not_affect_other_guilds(self, in_memory_db):
        _insert_guild(in_memory_db, guild_id=GUILD_1)
        _insert_guild(in_memory_db, guild_id=GUILD_2, log_channel=CHANNEL_2)
        db_handler.add_link_manager(in_memory_db, GUILD_2, USER_A)
        db_handler.delete_guild(in_memory_db, GUILD_1)
        assert db_handler.is_link_manager(in_memory_db, GUILD_2, USER_A) is True


# init_guild - announcement channel auto-registered in channel_table

class TestInitGuild:
    def test_announcement_channel_auto_added(self, in_memory_db):
        db_handler.init_guild(in_memory_db, GUILD_1, log_channel=CHANNEL_1, announcement_channel=CHANNEL_2)
        channels = db_handler.get_channels(in_memory_db, GUILD_1)
        assert CHANNEL_2 in channels

    def test_no_announcement_channel_no_channel_table_entry(self, in_memory_db):
        db_handler.init_guild(in_memory_db, GUILD_1, log_channel=CHANNEL_1)
        assert db_handler.get_channels(in_memory_db, GUILD_1) == []

    def test_duplicate_init_raises(self, in_memory_db):
        """SQLite PRIMARY KEY constraint - second init must raise."""
        db_handler.init_guild(in_memory_db, GUILD_1, log_channel=CHANNEL_1)
        with pytest.raises(Exception):
            db_handler.init_guild(in_memory_db, GUILD_1, log_channel=CHANNEL_2)


# Audit-log tamper detection
#
# Deleting audit entries has to leave one of its own, and losing the log
# channel has to reach the owner some other way - it cannot be reported into
# the channel that just disappeared.

class TestLogChannelCanBeCleared:
    def test_set_log_channel_accepts_none(self, in_memory_db):
        """on_guild_channel_delete clears the pointer so it can't dangle."""
        gid = 555000000000000001
        db_handler.init_guild(in_memory_db, gid, 999000000000000001)
        assert db_handler.get_log_channel(in_memory_db, gid) == 999000000000000001

        db_handler.set_log_channel(in_memory_db, gid, None)
        assert db_handler.get_log_channel(in_memory_db, gid) is None
