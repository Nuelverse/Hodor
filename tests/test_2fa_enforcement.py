"""
Tests: 2FA code enforcement on sensitive commands.

Every command that accepts a 'code' parameter must:
  - Respond "Incorrect 2FA code." (ephemeral) when verify_code returns False.
  - NOT send that message when verify_code returns True.

Tested cogs:
  Admin      - set_logs, add_channel, remove_channel, change_timeout
  Moderation - role, bulk_role, new_role, rename_channel, toggle_channel,
               sync_channels, restrict_channel, lock_threads, export,
               export_category, list_overrides
"""

import asyncio
import types
import pytest
import sys
import os
from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


# Helpers

WRONG_CODE = 0
RIGHT_CODE = 123456
GUILD_ID   = 200000000000000001
AUTHOR_ID  = 300000000000000001
PERM_OK    = (True, "")


def _make_ctx():
    """Minimal async-capable mock context."""
    guild  = types.SimpleNamespace(
        id=GUILD_ID, owner_id=999999999999999999,
        categories=[], channels=[], roles=[], member_count=0, members=[]
    )
    author = types.SimpleNamespace(id=AUTHOR_ID, mention=f"<@{AUTHOR_ID}>")
    ctx    = types.SimpleNamespace(guild=guild, author=author)
    ctx.respond    = AsyncMock()
    ctx.defer      = AsyncMock()
    ctx.send_modal = AsyncMock()
    return ctx


def _make_bot(conn):
    bot = types.SimpleNamespace()
    bot.CONN        = conn
    bot.master_user = 999999999999999999
    bot.config      = {}
    bot.get_channel = MagicMock(return_value=None)
    return bot


def run(coro):
    return asyncio.run(coro)


def _stack(verify_result, *extra):
    """
    Return an ExitStack that patches permissions + verify_code.
    Pass additional patch() calls as *extra.
    """
    s = ExitStack()
    s.enter_context(patch("permissions.check",          return_value=PERM_OK))
    s.enter_context(patch("permissions.guild_required", return_value=PERM_OK))
    s.enter_context(patch("two_factor_helper.verify_code", return_value=verify_result))
    for p in extra:
        s.enter_context(p)
    return s


def _no_2fa_error(ctx):
    """Assert ctx.respond was never called with the 2FA error message."""
    for call in ctx.respond.await_args_list:
        assert "Incorrect 2FA code." not in str(call)


# ===========================================================================
# Admin cog
# ===========================================================================

class TestAdminCog2FA:

    def _cog(self, conn):
        from cogs.admin import Admin
        return Admin(_make_bot(conn))

    # /set-logs ---------------------------------------------------------------

    def test_set_logs_rejects_wrong_code(self, in_memory_db):
        cog, ctx = self._cog(in_memory_db), _make_ctx()
        channel = MagicMock()
        with _stack(False):
            run(cog.set_logs.callback(cog, ctx, channel=channel, code=WRONG_CODE))
        ctx.respond.assert_awaited_once_with("Incorrect 2FA code.", ephemeral=True)

    def test_set_logs_passes_correct_code(self, in_memory_db):
        cog, ctx = self._cog(in_memory_db), _make_ctx()
        channel = AsyncMock(); channel.id = 1; channel.mention = "#logs"
        with _stack(True,
                    patch("db_handler.get_log_channel", return_value=None),
                    patch("db_handler.set_log_channel"),
                    patch("logger.safe_send", new_callable=AsyncMock)):
            run(cog.set_logs.callback(cog, ctx, channel=channel, code=RIGHT_CODE))
        _no_2fa_error(ctx)

    # /add-channel ------------------------------------------------------------

    def test_add_channel_rejects_wrong_code(self, in_memory_db):
        cog, ctx = self._cog(in_memory_db), _make_ctx()
        with _stack(False):
            run(cog.add_channel.callback(cog, ctx, channel=MagicMock(), code=WRONG_CODE))
        ctx.respond.assert_awaited_once_with("Incorrect 2FA code.", ephemeral=True)

    def test_add_channel_passes_correct_code(self, in_memory_db):
        cog, ctx = self._cog(in_memory_db), _make_ctx()
        ch = MagicMock(); ch.id = 42; ch.mention = "#ann"
        with _stack(True,
                    patch("db_handler.get_channels",  return_value=[]),
                    patch("db_handler.insert_channel"),
                    patch("logger.log_action", new_callable=AsyncMock)):
            run(cog.add_channel.callback(cog, ctx, channel=ch, code=RIGHT_CODE))
        _no_2fa_error(ctx)

    # /remove-channel ---------------------------------------------------------

    def test_remove_channel_rejects_wrong_code(self, in_memory_db):
        cog, ctx = self._cog(in_memory_db), _make_ctx()
        with _stack(False):
            run(cog.remove_channel.callback(cog, ctx, channel=MagicMock(), code=WRONG_CODE))
        ctx.respond.assert_awaited_once_with("Incorrect 2FA code.", ephemeral=True)

    def test_remove_channel_passes_correct_code(self, in_memory_db):
        cog, ctx = self._cog(in_memory_db), _make_ctx()
        ch = MagicMock(); ch.id = 42; ch.mention = "#ann"
        with _stack(True,
                    patch("db_handler.get_channels",  return_value=[42]),
                    patch("db_handler.delete_channel"),
                    patch("logger.log_action", new_callable=AsyncMock)):
            run(cog.remove_channel.callback(cog, ctx, channel=ch, code=RIGHT_CODE))
        _no_2fa_error(ctx)

    # /change-timeout ---------------------------------------------------------

    def test_change_timeout_rejects_wrong_code(self, in_memory_db):
        cog, ctx = self._cog(in_memory_db), _make_ctx()
        with _stack(False):
            run(cog.change_timeout.callback(cog, ctx, seconds=300, code=WRONG_CODE))
        ctx.respond.assert_awaited_once_with("Incorrect 2FA code.", ephemeral=True)

    def test_change_timeout_passes_correct_code(self, in_memory_db):
        cog, ctx = self._cog(in_memory_db), _make_ctx()
        with _stack(True,
                    patch("db_handler.set_announce_timeout"),
                    patch("logger.log_action", new_callable=AsyncMock)):
            run(cog.change_timeout.callback(cog, ctx, seconds=300, code=RIGHT_CODE))
        _no_2fa_error(ctx)


# ===========================================================================
# Moderation cog
# ===========================================================================

class TestModerationCog2FA:

    def _cog(self, conn):
        from cogs.moderation import Moderation
        return Moderation(_make_bot(conn))

    # /role -------------------------------------------------------------------

    def test_role_rejects_wrong_code(self, in_memory_db):
        cog, ctx = self._cog(in_memory_db), _make_ctx()
        with _stack(False):
            run(cog.role.callback(cog, ctx,
                                  member=MagicMock(), role=MagicMock(), code=WRONG_CODE))
        ctx.respond.assert_awaited_once_with("Incorrect 2FA code.", ephemeral=True)

    def test_role_passes_correct_code(self, in_memory_db):
        cog, ctx = self._cog(in_memory_db), _make_ctx()
        role = MagicMock(); role.permissions = MagicMock()
        with _stack(True,
                    patch("cogs.moderation.role_has_dangerous_perms", return_value=False),
                    patch("db_handler.is_safe_role", return_value=False)):
            run(cog.role.callback(cog, ctx,
                                  member=MagicMock(), role=role, code=RIGHT_CODE))
        _no_2fa_error(ctx)

    # /bulk-role --------------------------------------------------------------

    def test_bulk_role_rejects_wrong_code(self, in_memory_db):
        cog, ctx = self._cog(in_memory_db), _make_ctx()
        with _stack(False):
            run(cog.bulk_role.callback(cog, ctx, code=WRONG_CODE))
        ctx.respond.assert_awaited_once_with("Incorrect 2FA code.", ephemeral=True)

    def test_bulk_role_passes_correct_code_opens_modal(self, in_memory_db):
        cog, ctx = self._cog(in_memory_db), _make_ctx()
        with _stack(True):
            run(cog.bulk_role.callback(cog, ctx, code=RIGHT_CODE))
        ctx.send_modal.assert_awaited_once()
        _no_2fa_error(ctx)

    # /new-role ---------------------------------------------------------------

    def test_new_role_rejects_wrong_code(self, in_memory_db):
        cog, ctx = self._cog(in_memory_db), _make_ctx()
        with _stack(False):
            run(cog.new_role.callback(cog, ctx, name="Test", code=WRONG_CODE, color=None))
        ctx.respond.assert_awaited_once_with("Incorrect 2FA code.", ephemeral=True)

    # /rename-channel ---------------------------------------------------------

    def test_rename_channel_rejects_wrong_code(self, in_memory_db):
        cog, ctx = self._cog(in_memory_db), _make_ctx()
        with _stack(False):
            run(cog.rename_channel.callback(cog, ctx,
                                             channel=MagicMock(), new_name="x", code=WRONG_CODE))
        ctx.respond.assert_awaited_once_with("Incorrect 2FA code.", ephemeral=True)

    # /toggle-channel ---------------------------------------------------------

    def test_toggle_channel_rejects_wrong_code(self, in_memory_db):
        cog, ctx = self._cog(in_memory_db), _make_ctx()
        with _stack(False):
            run(cog.toggle_channel.callback(cog, ctx,
                                             channel=MagicMock(), role=MagicMock(), code=WRONG_CODE))
        ctx.respond.assert_awaited_once_with("Incorrect 2FA code.", ephemeral=True)

    # /sync-channels ----------------------------------------------------------

    def test_sync_channels_rejects_wrong_code(self, in_memory_db):
        cog, ctx = self._cog(in_memory_db), _make_ctx()
        with _stack(False):
            run(cog.sync_channels.callback(cog, ctx,
                                            category=MagicMock(), code=WRONG_CODE))
        ctx.respond.assert_awaited_once_with("Incorrect 2FA code.", ephemeral=True)

    # /restrict-channel -------------------------------------------------------

    def test_restrict_channel_rejects_wrong_code(self, in_memory_db):
        cog, ctx = self._cog(in_memory_db), _make_ctx()
        with _stack(False):
            run(cog.restrict_channel.callback(cog, ctx,
                                               member=MagicMock(), action="restrict",
                                               channel=MagicMock(), code=WRONG_CODE))
        ctx.respond.assert_awaited_once_with("Incorrect 2FA code.", ephemeral=True)

    # /lock-threads -----------------------------------------------------------

    def test_lock_threads_rejects_wrong_code(self, in_memory_db):
        cog, ctx = self._cog(in_memory_db), _make_ctx()
        with _stack(False):
            run(cog.lock_threads.callback(cog, ctx, code=WRONG_CODE, channel=None))
        ctx.respond.assert_awaited_once_with("Incorrect 2FA code.", ephemeral=True)

    # /export -----------------------------------------------------------------

    def test_export_rejects_wrong_code(self, in_memory_db):
        cog, ctx = self._cog(in_memory_db), _make_ctx()
        with _stack(False):
            run(cog.export.callback(cog, ctx, code=WRONG_CODE))
        ctx.respond.assert_awaited_once_with("Incorrect 2FA code.", ephemeral=True)

    # /export-category --------------------------------------------------------

    def test_export_category_rejects_wrong_code(self, in_memory_db):
        cog, ctx = self._cog(in_memory_db), _make_ctx()
        with _stack(False):
            run(cog.export_category.callback(cog, ctx,
                                              category=MagicMock(), code=WRONG_CODE))
        ctx.respond.assert_awaited_once_with("Incorrect 2FA code.", ephemeral=True)

    # /list-overrides ---------------------------------------------------------

    def test_list_overrides_rejects_wrong_code(self, in_memory_db):
        cog, ctx = self._cog(in_memory_db), _make_ctx()
        with _stack(False):
            run(cog.list_overrides.callback(cog, ctx, code=WRONG_CODE))
        ctx.respond.assert_awaited_once_with("Incorrect 2FA code.", ephemeral=True)

    def test_list_overrides_passes_correct_code(self, in_memory_db):
        cog, ctx = self._cog(in_memory_db), _make_ctx()
        with _stack(True):
            run(cog.list_overrides.callback(cog, ctx, code=RIGHT_CODE))
        _no_2fa_error(ctx)
