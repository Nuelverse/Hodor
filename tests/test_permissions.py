"""
Tests for permissions.py

Covers every check() level and every helper:
  - is_bot_owner, is_server_owner, is_2fa_ready
  - is_link_manager, is_announcer, is_registered, is_elevated
  - can_setup_2fa
  - check(): bot_owner / owner / owner_no_2fa / link_manager / announcer / any_registered
  - guild_required
"""

import pytest
import types
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import db_handler
import permissions
import inspect
import cogs.link_filter as link_filter_cog
import cogs.name_filter as name_filter_cog


# Shared IDs

BOT_OWNER_ID   = 999999999999999999   # same as mock_bot.master_user in conftest
GUILD_OWNER_ID = 111111111111111111
GUILD_ID       = 200000000000000001
MANAGER_ID     = 300000000000000001
ANNOUNCER_ID   = 400000000000000001
RANDOM_ID      = 500000000000000001


# Helpers to build bot/ctx fixtures

def _make_bot(in_memory_db):
    bot = types.SimpleNamespace()
    bot.CONN = in_memory_db
    bot.master_user = BOT_OWNER_ID
    return bot


def _make_ctx(author_id, guild_id=GUILD_ID, guild_owner_id=GUILD_OWNER_ID):
    guild = types.SimpleNamespace()
    guild.id = guild_id
    guild.owner_id = guild_owner_id

    author = types.SimpleNamespace()
    author.id = author_id

    ctx = types.SimpleNamespace()
    ctx.guild = guild
    ctx.author = author
    return ctx


def _setup_verified_user(conn, user_id):
    """Insert a user that has completed 2FA setup."""
    db_handler.insert_user(conn, (user_id, "DUMMY", 1))


def _setup_unverified_user(conn, user_id):
    """Insert a user with 2FA registered but not yet verified."""
    db_handler.insert_user(conn, (user_id, "DUMMY", 0))


# is_bot_owner

class TestIsBotOwner:
    def test_returns_true_for_master_user(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        assert permissions.is_bot_owner(bot, BOT_OWNER_ID) is True

    def test_returns_false_for_other_user(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        assert permissions.is_bot_owner(bot, RANDOM_ID) is False


# is_server_owner

class TestIsServerOwner:
    def test_returns_true_for_guild_owner(self, in_memory_db):
        ctx = _make_ctx(GUILD_OWNER_ID)
        assert permissions.is_server_owner(ctx) is True

    def test_returns_false_for_non_owner(self, in_memory_db):
        ctx = _make_ctx(RANDOM_ID)
        assert permissions.is_server_owner(ctx) is False


# is_2fa_ready

class TestIs2faReady:
    def test_verified_user_is_ready(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        _setup_verified_user(in_memory_db, BOT_OWNER_ID)
        assert permissions.is_2fa_ready(bot, BOT_OWNER_ID) is True

    def test_unverified_user_not_ready(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        _setup_unverified_user(in_memory_db, BOT_OWNER_ID)
        assert permissions.is_2fa_ready(bot, BOT_OWNER_ID) is False

    def test_nonexistent_user_not_ready(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        assert permissions.is_2fa_ready(bot, RANDOM_ID) is False


# is_link_manager / is_announcer / is_registered

class TestRoleChecks:
    def test_is_link_manager_true(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        db_handler.add_link_manager(in_memory_db, GUILD_ID, MANAGER_ID)
        assert permissions.is_link_manager(bot, GUILD_ID, MANAGER_ID) is True

    def test_is_link_manager_false(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        assert permissions.is_link_manager(bot, GUILD_ID, RANDOM_ID) is False

    def test_is_announcer_true(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        db_handler.authorise_member(in_memory_db, (GUILD_ID, ANNOUNCER_ID))
        assert permissions.is_announcer(bot, GUILD_ID, ANNOUNCER_ID) is True

    def test_is_announcer_false(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        assert permissions.is_announcer(bot, GUILD_ID, RANDOM_ID) is False

    def test_is_registered_as_manager(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        db_handler.add_link_manager(in_memory_db, GUILD_ID, MANAGER_ID)
        assert permissions.is_registered(bot, GUILD_ID, MANAGER_ID) is True

    def test_is_registered_as_announcer(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        db_handler.authorise_member(in_memory_db, (GUILD_ID, ANNOUNCER_ID))
        assert permissions.is_registered(bot, GUILD_ID, ANNOUNCER_ID) is True

    def test_is_registered_neither(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        assert permissions.is_registered(bot, GUILD_ID, RANDOM_ID) is False


# can_setup_2fa

class TestCanSetup2FA:
    def test_bot_owner_can_setup(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        ctx = _make_ctx(BOT_OWNER_ID)
        assert permissions.can_setup_2fa(bot, ctx) is True

    def test_guild_owner_can_setup(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        ctx = _make_ctx(GUILD_OWNER_ID)
        assert permissions.can_setup_2fa(bot, ctx) is True

    def test_registered_manager_can_setup(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        db_handler.add_link_manager(in_memory_db, GUILD_ID, MANAGER_ID)
        ctx = _make_ctx(MANAGER_ID)
        assert permissions.can_setup_2fa(bot, ctx) is True

    def test_registered_announcer_can_setup(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        db_handler.authorise_member(in_memory_db, (GUILD_ID, ANNOUNCER_ID))
        ctx = _make_ctx(ANNOUNCER_ID)
        assert permissions.can_setup_2fa(bot, ctx) is True

    def test_random_user_cannot_setup(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        ctx = _make_ctx(RANDOM_ID)
        assert permissions.can_setup_2fa(bot, ctx) is False


# check() - bot_owner level

class TestCheckBotOwner:
    def test_bot_owner_with_2fa_allowed(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        _setup_verified_user(in_memory_db, BOT_OWNER_ID)
        ctx = _make_ctx(BOT_OWNER_ID)
        ok, msg = permissions.check(bot, ctx, 'bot_owner')
        assert ok is True
        assert msg == ""

    def test_bot_owner_without_2fa_denied(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        ctx = _make_ctx(BOT_OWNER_ID)
        ok, msg = permissions.check(bot, ctx, 'bot_owner')
        assert ok is False
        assert "create-2fa" in msg or "verify" in msg.lower() or "Complete" in msg

    def test_server_owner_denied_at_bot_owner_level(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        _setup_verified_user(in_memory_db, GUILD_OWNER_ID)
        ctx = _make_ctx(GUILD_OWNER_ID)
        ok, msg = permissions.check(bot, ctx, 'bot_owner')
        assert ok is False

    def test_link_manager_denied_at_bot_owner_level(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        db_handler.add_link_manager(in_memory_db, GUILD_ID, MANAGER_ID)
        _setup_verified_user(in_memory_db, MANAGER_ID)
        ctx = _make_ctx(MANAGER_ID)
        ok, _ = permissions.check(bot, ctx, 'bot_owner')
        assert ok is False


# check() - owner level

class TestCheckOwner:
    def test_bot_owner_with_2fa_allowed(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        _setup_verified_user(in_memory_db, BOT_OWNER_ID)
        ctx = _make_ctx(BOT_OWNER_ID)
        ok, _ = permissions.check(bot, ctx, 'owner')
        assert ok is True

    def test_server_owner_with_2fa_allowed(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        _setup_verified_user(in_memory_db, GUILD_OWNER_ID)
        ctx = _make_ctx(GUILD_OWNER_ID)
        ok, _ = permissions.check(bot, ctx, 'owner')
        assert ok is True

    def test_server_owner_without_2fa_denied(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        ctx = _make_ctx(GUILD_OWNER_ID)
        ok, msg = permissions.check(bot, ctx, 'owner')
        assert ok is False

    def test_random_user_denied_at_owner_level(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        _setup_verified_user(in_memory_db, RANDOM_ID)
        ctx = _make_ctx(RANDOM_ID)
        ok, _ = permissions.check(bot, ctx, 'owner')
        assert ok is False


# check() - owner_no_2fa level

class TestCheckOwnerNo2FA:
    def test_bot_owner_without_2fa_allowed(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        ctx = _make_ctx(BOT_OWNER_ID)
        ok, _ = permissions.check(bot, ctx, 'owner_no_2fa')
        assert ok is True

    def test_server_owner_without_2fa_allowed(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        ctx = _make_ctx(GUILD_OWNER_ID)
        ok, _ = permissions.check(bot, ctx, 'owner_no_2fa')
        assert ok is True

    def test_link_manager_denied(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        db_handler.add_link_manager(in_memory_db, GUILD_ID, MANAGER_ID)
        ctx = _make_ctx(MANAGER_ID)
        ok, _ = permissions.check(bot, ctx, 'owner_no_2fa')
        assert ok is False

    def test_random_user_denied(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        ctx = _make_ctx(RANDOM_ID)
        ok, _ = permissions.check(bot, ctx, 'owner_no_2fa')
        assert ok is False


# check() - link_manager level

class TestCheckLinkManager:
    def test_link_manager_with_2fa_allowed(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        db_handler.add_link_manager(in_memory_db, GUILD_ID, MANAGER_ID)
        _setup_verified_user(in_memory_db, MANAGER_ID)
        ctx = _make_ctx(MANAGER_ID)
        ok, _ = permissions.check(bot, ctx, 'link_manager')
        assert ok is True

    def test_link_manager_without_2fa_denied(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        db_handler.add_link_manager(in_memory_db, GUILD_ID, MANAGER_ID)
        ctx = _make_ctx(MANAGER_ID)
        ok, _ = permissions.check(bot, ctx, 'link_manager')
        assert ok is False

    def test_bot_owner_with_2fa_allowed(self, in_memory_db):
        """Elevated users bypass the role check but still need 2FA."""
        bot = _make_bot(in_memory_db)
        _setup_verified_user(in_memory_db, BOT_OWNER_ID)
        ctx = _make_ctx(BOT_OWNER_ID)
        ok, _ = permissions.check(bot, ctx, 'link_manager')
        assert ok is True

    def test_server_owner_with_2fa_allowed(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        _setup_verified_user(in_memory_db, GUILD_OWNER_ID)
        ctx = _make_ctx(GUILD_OWNER_ID)
        ok, _ = permissions.check(bot, ctx, 'link_manager')
        assert ok is True

    def test_bot_owner_without_2fa_denied(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        ctx = _make_ctx(BOT_OWNER_ID)
        ok, _ = permissions.check(bot, ctx, 'link_manager')
        assert ok is False

    def test_announcer_only_denied(self, in_memory_db):
        """Being an announcer alone is not enough for link_manager level."""
        bot = _make_bot(in_memory_db)
        db_handler.authorise_member(in_memory_db, (GUILD_ID, ANNOUNCER_ID))
        _setup_verified_user(in_memory_db, ANNOUNCER_ID)
        ctx = _make_ctx(ANNOUNCER_ID)
        ok, _ = permissions.check(bot, ctx, 'link_manager')
        assert ok is False

    def test_random_user_denied(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        _setup_verified_user(in_memory_db, RANDOM_ID)
        ctx = _make_ctx(RANDOM_ID)
        ok, _ = permissions.check(bot, ctx, 'link_manager')
        assert ok is False


# check() - announcer level

class TestCheckAnnouncer:
    def test_announcer_with_2fa_allowed(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        db_handler.authorise_member(in_memory_db, (GUILD_ID, ANNOUNCER_ID))
        _setup_verified_user(in_memory_db, ANNOUNCER_ID)
        ctx = _make_ctx(ANNOUNCER_ID)
        ok, _ = permissions.check(bot, ctx, 'announcer')
        assert ok is True

    def test_announcer_without_2fa_denied(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        db_handler.authorise_member(in_memory_db, (GUILD_ID, ANNOUNCER_ID))
        ctx = _make_ctx(ANNOUNCER_ID)
        ok, _ = permissions.check(bot, ctx, 'announcer')
        assert ok is False

    def test_bot_owner_with_2fa_allowed(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        _setup_verified_user(in_memory_db, BOT_OWNER_ID)
        ctx = _make_ctx(BOT_OWNER_ID)
        ok, _ = permissions.check(bot, ctx, 'announcer')
        assert ok is True

    def test_link_manager_only_denied(self, in_memory_db):
        """Being a link manager alone is not enough for announcer level."""
        bot = _make_bot(in_memory_db)
        db_handler.add_link_manager(in_memory_db, GUILD_ID, MANAGER_ID)
        _setup_verified_user(in_memory_db, MANAGER_ID)
        ctx = _make_ctx(MANAGER_ID)
        ok, _ = permissions.check(bot, ctx, 'announcer')
        assert ok is False

    def test_random_user_denied(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        ctx = _make_ctx(RANDOM_ID)
        ok, _ = permissions.check(bot, ctx, 'announcer')
        assert ok is False


# check() - any_registered level

class TestCheckAnyRegistered:
    def test_link_manager_allowed_no_2fa_needed(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        db_handler.add_link_manager(in_memory_db, GUILD_ID, MANAGER_ID)
        ctx = _make_ctx(MANAGER_ID)
        ok, _ = permissions.check(bot, ctx, 'any_registered')
        assert ok is True

    def test_announcer_allowed_no_2fa_needed(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        db_handler.authorise_member(in_memory_db, (GUILD_ID, ANNOUNCER_ID))
        ctx = _make_ctx(ANNOUNCER_ID)
        ok, _ = permissions.check(bot, ctx, 'any_registered')
        assert ok is True

    def test_bot_owner_allowed(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        ctx = _make_ctx(BOT_OWNER_ID)
        ok, _ = permissions.check(bot, ctx, 'any_registered')
        assert ok is True

    def test_server_owner_allowed(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        ctx = _make_ctx(GUILD_OWNER_ID)
        ok, _ = permissions.check(bot, ctx, 'any_registered')
        assert ok is True

    def test_random_user_denied(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        ctx = _make_ctx(RANDOM_ID)
        ok, _ = permissions.check(bot, ctx, 'any_registered')
        assert ok is False


# guild_required

class TestGuildRequired:
    def test_initialized_guild_passes(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        db_handler.init_guild(in_memory_db, GUILD_ID, log_channel=12345)
        ctx = _make_ctx(BOT_OWNER_ID)
        ok, _ = permissions.guild_required(bot, ctx)
        assert ok is True

    def test_uninitialized_guild_fails(self, in_memory_db):
        bot = _make_bot(in_memory_db)
        ctx = _make_ctx(BOT_OWNER_ID, guild_id=999)
        ok, msg = permissions.guild_required(bot, ctx)
        assert ok is False
        assert "setup" in msg.lower() or "set up" in msg.lower()


# Filter exemptions after the "nothing goes behind" change
#
# Privileged accounts used to be skipped entirely by both filters. That is the
# opposite of what you want: a stolen owner or staff account is the most
# valuable one an attacker can get, and it was the only account whose links
# were never scanned. Everyone is checked now; only irreversible name-filter
# actions are still withheld from staff.

class TestNoIdentityBypassInLinkFilter:
    def test_link_filter_has_no_owner_bypass(self):
        """The implicit master/server-owner bypass must stay gone."""
        src = inspect.getsource(link_filter_cog.LinkFilter._is_bypassed)
        assert "master_user" not in src, (
            "link filter regained an implicit operator bypass - a phished "
            "owner account would post unscanned links"
        )
        assert "owner_id" not in src, (
            "link filter regained an implicit server-owner bypass"
        )

    def test_link_filter_still_honours_explicit_exemptions(self):
        """Opt-in exemptions via /add-whitelist-linkfilter must still work."""
        src = inspect.getsource(link_filter_cog.LinkFilter._is_bypassed)
        assert "is_filter_exempt" in src


class TestNameFilterProtectsOnlyDestructiveActions:
    """
    The filter has two separate exemption tiers and they must not merge.

      _is_privileged  - implicit (owner, mod perms, announcer). Downgrades
                        the action to 'flag' but STILL LOGS. A staff account
                        renaming itself to "MetaMask Support" is what a
                        compromise looks like, so it must stay visible.

      _is_role_exempt - an operator explicitly exempted a role. Skips the
                        scan outright, no log entry.

    Collapsing the first into the second would silently hide compromised
    staff accounts, which is the bug these tests exist to prevent.
    """

    def test_privileged_members_are_still_matched(self):
        """Privileged status must not short-circuit the check itself."""
        join_src = inspect.getsource(name_filter_cog.NameFilter.on_member_join)
        assert "_is_privileged" not in join_src, (
            "on_member_join skips privileged members again - they would never "
            "be flagged, which is the bug this replaced"
        )

    def test_take_action_downgrades_privileged_instead_of_skipping(self):
        src = inspect.getsource(name_filter_cog._take_action)
        assert "_is_privileged" in src and "downgraded" in src, (
            "_take_action must downgrade destructive actions for privileged "
            "members rather than skipping them entirely"
        )

    def test_role_exempt_members_are_skipped_before_matching(self):
        """Explicit role exemptions are a full skip - no action, no log."""
        join_src = inspect.getsource(name_filter_cog.NameFilter.on_member_join)
        assert "_is_role_exempt" in join_src, (
            "on_member_join must skip explicitly exempted roles before matching"
        )

    def test_take_action_also_guards_role_exempt(self):
        """Defence in depth: a missed call site must not ban a staff member."""
        src = inspect.getsource(name_filter_cog._take_action)
        assert "_is_role_exempt" in src, (
            "_take_action lost its role-exemption guard"
        )

    def test_role_exemption_is_not_implicit(self):
        """
        Exemption must come from the database, never from a permission bit.
        Otherwise any moderator role would silently become invisible to the
        filter without the owner ever choosing that.
        """
        src = inspect.getsource(name_filter_cog._is_role_exempt)
        assert "get_name_filter_exempt_roles" in src
        assert "guild_permissions" not in src
