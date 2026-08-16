"""
Tests for announcement session management.

Verifies:
  - insert_active_announcement records the correct (channel_id, member_id) pair
  - OR REPLACE semantics: re-running /announce refreshes the session (no error, no duplicate)
  - delete_active_announcement removes only the targeted session
  - Sessions are user-isolated: user A's session is invisible to user B on the same channel
  - Sessions are channel-isolated: a session on channel 1 is invisible to channel 2
  - Sessions from different guilds do not interfere
  - announce_timeout defaults to 300 and can be overridden
  - Only channels in channel_table pass the authorization check (/announce channel guard)
  - An announcer added to trusted_members is recognized; a non-announcer is not
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import db_handler

# Shared test IDs

GUILD_1   = 200000000000000001
GUILD_2   = 200000000000000002
USER_A    = 100000000000000001
USER_B    = 100000000000000002
CHANNEL_1 = 300000000000000001
CHANNEL_2 = 300000000000000002
LOG_CH    = 300000000000000099


# Helpers

def _setup_guild(conn, guild_id=GUILD_1):
    db_handler.init_guild(conn, guild_id, log_channel=LOG_CH)


def _add_announce_channel(conn, channel_id=CHANNEL_1, guild_id=GUILD_1):
    db_handler.insert_channel(conn, (channel_id, guild_id))


def _insert_session(conn, channel_id=CHANNEL_1, member_id=USER_A):
    db_handler.insert_active_announcement(conn, (channel_id, member_id))


def _has_session(conn, channel_id, member_id) -> bool:
    """Direct SQL check - avoids coupling to any future helper."""
    cur = conn.execute(
        "SELECT EXISTS(SELECT 1 FROM active_announcements WHERE channel_id=? AND member_id=?)",
        (channel_id, member_id),
    )
    return bool(cur.fetchone()[0])


# Active announcement session - DB layer

class TestActiveAnnouncementSession:

    def test_insert_creates_session(self, in_memory_db):
        _insert_session(in_memory_db, CHANNEL_1, USER_A)
        assert _has_session(in_memory_db, CHANNEL_1, USER_A)

    def test_no_session_by_default(self, in_memory_db):
        assert not _has_session(in_memory_db, CHANNEL_1, USER_A)

    def test_insert_or_replace_does_not_raise_on_duplicate(self, in_memory_db):
        """Running /announce twice should reset the timer, not crash."""
        _insert_session(in_memory_db, CHANNEL_1, USER_A)
        # Second call must succeed (INSERT OR REPLACE)
        _insert_session(in_memory_db, CHANNEL_1, USER_A)
        assert _has_session(in_memory_db, CHANNEL_1, USER_A)

    def test_insert_or_replace_single_row(self, in_memory_db):
        """After two inserts for the same pair, there must still be exactly one row."""
        _insert_session(in_memory_db, CHANNEL_1, USER_A)
        _insert_session(in_memory_db, CHANNEL_1, USER_A)
        cur = in_memory_db.execute(
            "SELECT COUNT(*) FROM active_announcements WHERE channel_id=? AND member_id=?",
            (CHANNEL_1, USER_A),
        )
        assert cur.fetchone()[0] == 1

    def test_delete_removes_session(self, in_memory_db):
        _insert_session(in_memory_db, CHANNEL_1, USER_A)
        db_handler.delete_active_announcement(in_memory_db, (CHANNEL_1, USER_A))
        assert not _has_session(in_memory_db, CHANNEL_1, USER_A)

    def test_delete_nonexistent_is_silent(self, in_memory_db):
        """Deleting a session that was never created should not raise."""
        db_handler.delete_active_announcement(in_memory_db, (CHANNEL_1, USER_A))


# Session isolation - user scope

class TestSessionUserIsolation:

    def test_user_a_session_does_not_grant_user_b(self, in_memory_db):
        """Granting access to USER_A must not create a session for USER_B."""
        _insert_session(in_memory_db, CHANNEL_1, USER_A)
        assert not _has_session(in_memory_db, CHANNEL_1, USER_B)

    def test_delete_user_a_leaves_user_b_intact(self, in_memory_db):
        _insert_session(in_memory_db, CHANNEL_1, USER_A)
        _insert_session(in_memory_db, CHANNEL_1, USER_B)
        db_handler.delete_active_announcement(in_memory_db, (CHANNEL_1, USER_A))
        assert not _has_session(in_memory_db, CHANNEL_1, USER_A)
        assert _has_session(in_memory_db, CHANNEL_1, USER_B)

    def test_multiple_users_independent_sessions(self, in_memory_db):
        _insert_session(in_memory_db, CHANNEL_1, USER_A)
        _insert_session(in_memory_db, CHANNEL_1, USER_B)
        assert _has_session(in_memory_db, CHANNEL_1, USER_A)
        assert _has_session(in_memory_db, CHANNEL_1, USER_B)


# Session isolation - channel scope

class TestSessionChannelIsolation:

    def test_session_on_channel_1_invisible_on_channel_2(self, in_memory_db):
        _insert_session(in_memory_db, CHANNEL_1, USER_A)
        assert not _has_session(in_memory_db, CHANNEL_2, USER_A)

    def test_delete_channel_1_session_leaves_channel_2_intact(self, in_memory_db):
        _insert_session(in_memory_db, CHANNEL_1, USER_A)
        _insert_session(in_memory_db, CHANNEL_2, USER_A)
        db_handler.delete_active_announcement(in_memory_db, (CHANNEL_1, USER_A))
        assert not _has_session(in_memory_db, CHANNEL_1, USER_A)
        assert _has_session(in_memory_db, CHANNEL_2, USER_A)


# Announce timeout

class TestAnnounceTimeout:

    def test_default_timeout_is_300(self, in_memory_db):
        """Guilds initialized without specifying a timeout default to 300 seconds."""
        _setup_guild(in_memory_db)
        assert db_handler.get_announce_timeout(in_memory_db, GUILD_1) == 300

    def test_set_timeout(self, in_memory_db):
        _setup_guild(in_memory_db)
        db_handler.set_announce_timeout(in_memory_db, GUILD_1, 600)
        assert db_handler.get_announce_timeout(in_memory_db, GUILD_1) == 600

    def test_timeout_minimum_boundary(self, in_memory_db):
        _setup_guild(in_memory_db)
        db_handler.set_announce_timeout(in_memory_db, GUILD_1, 30)
        assert db_handler.get_announce_timeout(in_memory_db, GUILD_1) == 30

    def test_timeout_maximum_boundary(self, in_memory_db):
        _setup_guild(in_memory_db)
        db_handler.set_announce_timeout(in_memory_db, GUILD_1, 3600)
        assert db_handler.get_announce_timeout(in_memory_db, GUILD_1) == 3600

    def test_timeout_guild_isolated(self, in_memory_db):
        _setup_guild(in_memory_db, GUILD_1)
        _setup_guild(in_memory_db, GUILD_2)
        db_handler.set_announce_timeout(in_memory_db, GUILD_1, 120)
        assert db_handler.get_announce_timeout(in_memory_db, GUILD_2) == 300


# Channel authorization guard (/announce channel must be in channel_table)

class TestChannelAuthorization:

    def test_configured_channel_is_authorized(self, in_memory_db):
        _setup_guild(in_memory_db)
        _add_announce_channel(in_memory_db, CHANNEL_1, GUILD_1)
        assert CHANNEL_1 in db_handler.get_channels(in_memory_db, GUILD_1)

    def test_unconfigured_channel_is_not_authorized(self, in_memory_db):
        _setup_guild(in_memory_db)
        _add_announce_channel(in_memory_db, CHANNEL_1, GUILD_1)
        assert CHANNEL_2 not in db_handler.get_channels(in_memory_db, GUILD_1)

    def test_channel_from_other_guild_is_not_authorized(self, in_memory_db):
        _setup_guild(in_memory_db, GUILD_1)
        _setup_guild(in_memory_db, GUILD_2)
        _add_announce_channel(in_memory_db, CHANNEL_1, GUILD_2)
        # CHANNEL_1 belongs to GUILD_2, so GUILD_1 must not see it
        assert CHANNEL_1 not in db_handler.get_channels(in_memory_db, GUILD_1)

    def test_removing_channel_deauthorizes_it(self, in_memory_db):
        _setup_guild(in_memory_db)
        _add_announce_channel(in_memory_db, CHANNEL_1, GUILD_1)
        db_handler.delete_channel(in_memory_db, CHANNEL_1)
        assert CHANNEL_1 not in db_handler.get_channels(in_memory_db, GUILD_1)


# Announcer role check (/announce requires trusted_members entry)

class TestAnnouncerAuthorization:

    def test_authorized_announcer_is_recognized(self, in_memory_db):
        _setup_guild(in_memory_db)
        db_handler.authorise_member(in_memory_db, (GUILD_1, USER_A))
        assert db_handler.check_authorised(in_memory_db, (GUILD_1, USER_A)) is True

    def test_non_announcer_is_not_recognized(self, in_memory_db):
        _setup_guild(in_memory_db)
        assert db_handler.check_authorised(in_memory_db, (GUILD_1, USER_A)) is False

    def test_announcer_in_guild_1_not_authorized_in_guild_2(self, in_memory_db):
        _setup_guild(in_memory_db, GUILD_1)
        _setup_guild(in_memory_db, GUILD_2)
        db_handler.authorise_member(in_memory_db, (GUILD_1, USER_A))
        assert db_handler.check_authorised(in_memory_db, (GUILD_2, USER_A)) is False

    def test_removed_announcer_loses_access(self, in_memory_db):
        _setup_guild(in_memory_db)
        db_handler.authorise_member(in_memory_db, (GUILD_1, USER_A))
        db_handler.deauthorise_member(in_memory_db, (GUILD_1, USER_A))
        assert db_handler.check_authorised(in_memory_db, (GUILD_1, USER_A)) is False

    def test_user_b_not_affected_by_user_a_removal(self, in_memory_db):
        _setup_guild(in_memory_db)
        db_handler.authorise_member(in_memory_db, (GUILD_1, USER_A))
        db_handler.authorise_member(in_memory_db, (GUILD_1, USER_B))
        db_handler.deauthorise_member(in_memory_db, (GUILD_1, USER_A))
        assert db_handler.check_authorised(in_memory_db, (GUILD_1, USER_B)) is True
