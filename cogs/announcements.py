"""
Announcements — temporarily grants an announcer send permissions in a configured
announcement channel so they can post directly.

Commands:
  /announce channel:<channel> code:<2FA>  — Announcers only.
      Verifies 2FA, grants send_messages + embed_links + attach_files + mention_everyone
      for the configured timeout, then auto-revokes on expiry.

Note: The link filter still applies during the window. Any links to be posted must
      be whitelisted via /allow-link before the announcement.
"""

import asyncio
import time

import discord
from discord.ext import commands
from discord.commands import Option
from discord.enums import ChannelType
import db_handler
import two_factor_helper
import permissions
import logger


class Announcements(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        # Active revocation tasks keyed by (guild_id, member_id, channel_id)
        self._revoke_tasks: dict[tuple, asyncio.Task] = {}
        self._reconciled = False

    # ------------------------------------------------------------------
    # Startup reconciliation
    # ------------------------------------------------------------------

    @commands.Cog.listener()
    async def on_ready(self):
        """
        Re-arm or revoke grants that outlived the process.

        Revocation used to live only in an in-memory asyncio task, so a restart
        during an active window left the member holding send_messages and
        mention_everyone forever. Every grant is now persisted, so on startup we
        revoke the expired ones immediately and schedule the rest.
        """
        if self._reconciled:
            return
        self._reconciled = True
        await self._reconcile_grants()

    async def _reconcile_grants(self):
        try:
            grants = db_handler.get_pending_announcement_grants(self.bot.CONN)
        except Exception as e:
            print(f"[announce] Could not read pending grants: {e}")
            return

        now = int(time.time())
        restored, revoked = 0, 0

        for guild_id, channel_id, member_id, expires_at in grants:
            guild = self.bot.get_guild(guild_id) if guild_id else None
            channel = self.bot.get_channel(channel_id)
            member = guild.get_member(member_id) if guild else None

            if channel is None or member is None:
                # Can't act on it any more — drop the stale row.
                db_handler.delete_active_announcement(self.bot.CONN, (channel_id, member_id))
                continue

            remaining = (expires_at or 0) - now
            if remaining <= 0:
                try:
                    await channel.set_permissions(member, overwrite=None)
                except (discord.Forbidden, discord.HTTPException):
                    pass
                db_handler.delete_active_announcement(self.bot.CONN, (channel_id, member_id))
                revoked += 1
                await logger.log_action(
                    self.bot, guild, "Announcement Access Revoked", member,
                    details={
                        "Channel": channel.mention,
                        "Reason": "Grant expired while the bot was offline",
                    },
                    level='warning',
                )
            else:
                key = (guild.id, member_id, channel_id)
                task = asyncio.create_task(
                    self._revoke_announce(guild, member, channel, remaining, key)
                )
                self._revoke_tasks[key] = task
                restored += 1

        if restored or revoked:
            print(f"[announce] Reconciled grants on startup: "
                  f"{revoked} revoked (expired), {restored} rescheduled.")

    # ------------------------------------------------------------------
    # /announce
    # ------------------------------------------------------------------

    @commands.guild_only()
    @commands.cooldown(1, 5, commands.BucketType.user)
    @commands.slash_command(
        description="Get temporary send access to an announcement channel. Announcers only. Requires 2FA."
    )
    async def announce(
        self,
        ctx: discord.ApplicationContext,
        announcement_channel: Option(
            discord.abc.GuildChannel,
            "Channel to post in",
            required=True,
            channel_types=[ChannelType.text, ChannelType.news],
        ),
        code: Option(int, "Your 6-digit 2FA code", required=True),
    ):
        allowed, err = permissions.check(self.bot, ctx, 'announcer')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return

        ok, err2 = permissions.guild_required(self.bot, ctx)
        if not ok:
            await ctx.respond(err2, ephemeral=True)
            return

        # Channel must be in the configured announcement channels list
        configured_channels = db_handler.get_channels(self.bot.CONN, ctx.guild.id)
        if announcement_channel.id not in configured_channels:
            await ctx.respond(
                f"{announcement_channel.mention} is not in the announcement channel list. "
                "Ask an admin to add it with `/add-channel`.",
                ephemeral=True,
            )
            return

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        timeout = db_handler.get_announce_timeout(self.bot.CONN, ctx.guild.id)

        # Grant channel permissions (send_messages, embed_links, attach_files, mention roles)
        try:
            await announcement_channel.set_permissions(
                ctx.author,
                send_messages=True,
                embed_links=True,
                attach_files=True,
                mention_everyone=True,
            )
        except discord.Forbidden:
            await ctx.respond(
                "I don't have permission to modify channel permissions. "
                "Ensure I have **Manage Channels** in that channel.",
                ephemeral=True,
            )
            return

        # Persist the grant so it can still be revoked if the bot restarts
        # before the timer fires.
        db_handler.record_announcement_grant(
            self.bot.CONN,
            ctx.guild.id,
            announcement_channel.id,
            ctx.author.id,
            int(time.time()) + timeout,
        )

        # Cancel any existing revocation task for this (user, channel) pair
        key = (ctx.guild.id, ctx.author.id, announcement_channel.id)
        existing = self._revoke_tasks.pop(key, None)
        if existing and not existing.done():
            existing.cancel()

        task = asyncio.create_task(
            self._revoke_announce(ctx.guild, ctx.author, announcement_channel, timeout, key)
        )
        self._revoke_tasks[key] = task

        mins, secs = divmod(timeout, 60)
        time_str = f"{mins}m {secs}s" if mins else f"{secs}s"

        await ctx.respond(
            f"Permission granted. You can now post in {announcement_channel.mention} for **{time_str}**.\n"
            "You can mention roles and attach files.\n"
            "**Note:** The link filter still applies — whitelist any links via `/allow-link` before posting.\n"
            "Permissions are revoked automatically when the timer expires.",
            ephemeral=True,
        )

        await logger.log_action(
            self.bot, ctx.guild,
            "Announcement Access Granted",
            ctx.author,
            details={
                "Channel": announcement_channel.mention,
                "Duration": time_str,
                "Expires": logger.fmt_timestamp_offset(timeout),
            },
            level='info',
        )

    # ------------------------------------------------------------------
    # Revocation task
    # ------------------------------------------------------------------

    async def _revoke_announce(
        self,
        guild: discord.Guild,
        member: discord.Member,
        channel: discord.TextChannel,
        timeout: int,
        key: tuple,
    ):
        await asyncio.sleep(timeout)

        # Remove all permission overrides granted to this member on the channel
        try:
            await channel.set_permissions(member, overwrite=None)
        except (discord.Forbidden, discord.HTTPException):
            pass

        # Remove active session record
        db_handler.delete_active_announcement(self.bot.CONN, (channel.id, member.id))

        # Clean up task reference
        self._revoke_tasks.pop(key, None)

        await logger.log_action(
            self.bot, guild,
            "Announcement Access Revoked",
            member,
            details={
                "Channel": channel.mention,
                "Reason": f"Timeout ({timeout}s) expired",
            },
            level='warning',
        )


def setup(bot):
    bot.add_cog(Announcements(bot))
