"""
Audit Log — logs deleted/edited messages and member bans to the guild log channel.

Events handled:
  on_message_delete      →  full embed: author, channel, message ID, content
  on_message_edit        →  full embed: before/after diff, jump link
  on_raw_message_delete  →  fallback for messages Discord never cached
  on_raw_bulk_message_delete → purges / bulk deletions
  on_member_ban          →  banned user, responsible mod, audit-log reason

THE CACHE PROBLEM
-----------------
on_message_delete only fires for messages in the bot's in-memory cache — which
holds roughly the last 1000 messages it has SEEN SINCE IT STARTED. Delete a
message older than that (or anything sent before the last restart) and Discord
dispatches on_raw_message_delete instead; on_message_delete never runs at all.

This used to mean older deletions were logged as nothing whatsoever, which is
exactly backwards for a security bot: quietly removing an old message is more
suspicious than deleting a fresh one, not less.

The raw handlers below close that gap. They cannot recover the content —
Discord does not keep it, and neither do we — but they record that a deletion
happened, where, and (where Discord's audit log exposes it) who did it. A
raw handler skips anything already covered by the cached handler, so nothing
is logged twice.
"""

import asyncio

import discord
from discord.ext import commands
import db_handler


class AuditLog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    def _get_log_ch(self, guild_id: int):
        log_id = db_handler.get_log_channel(self.bot.CONN, guild_id)
        return self.bot.get_channel(log_id) if log_id else None

    async def _safe_send(self, channel, **kwargs):
        if channel is None:
            return
        try:
            await channel.send(**kwargs)
        except (discord.Forbidden, discord.HTTPException):
            pass

    # ------------------------------------------------------------------
    # Deleted messages
    # ------------------------------------------------------------------

    @commands.Cog.listener()
    async def on_message_delete(self, message: discord.Message):
        if message.author.bot or not message.guild:
            return
        # Suppressed — link filter already logged this deletion specifically
        if message.id in self.bot.deleted_by_filter:
            self.bot.deleted_by_filter.discard(message.id)
            return
        if not db_handler.check_guild(self.bot.CONN, message.guild.id):
            return
        log_ch = self._get_log_ch(message.guild.id)
        if not log_ch:
            return

        embed = discord.Embed(title="Message Deleted", color=0xe74c3c)
        embed.add_field(
            name="Channel",
            value=f"{message.channel.mention} | `{message.channel.id}`",
            inline=False,
        )
        embed.add_field(name="Message ID", value=f"`{message.id}`", inline=True)
        embed.add_field(
            name="Author",
            value=f"{message.author.mention} | `{message.author.id}`",
            inline=False,
        )

        content = message.content or ""
        if content:
            # Truncate — Discord embed field cap is 1024 chars
            display = content[:950]
            if len(content) > 950:
                display += f"\n… ({len(content) - 950} chars truncated)"
            embed.add_field(name="Content", value=f"```{display}```", inline=False)
        else:
            embed.add_field(name="Content", value="*(empty or not cached)*", inline=False)

        if message.attachments:
            embed.add_field(
                name="Attachments",
                value="\n".join(a.filename for a in message.attachments),
                inline=False,
            )

        embed.timestamp = discord.utils.utcnow()
        embed.set_footer(text=f"Guild: {message.guild.name}")
        await self._safe_send(log_ch, embed=embed)

    # ------------------------------------------------------------------
    # Deleted messages Discord never cached (older than the bot's memory)
    # ------------------------------------------------------------------

    async def _find_deleter(self, guild: discord.Guild, channel_id: int):
        """
        Best-effort attribution for a deletion.

        Discord only writes an audit-log entry when someone deletes SOMEONE
        ELSE'S message. A member removing their own post produces nothing, so
        "Unknown" here genuinely means "self-deleted, or Discord didn't say".
        """
        try:
            async for entry in guild.audit_logs(limit=5,
                                                action=discord.AuditLogAction.message_delete):
                extra_channel = getattr(entry.extra, "channel", None)
                if extra_channel is not None and extra_channel.id != channel_id:
                    continue
                age = (discord.utils.utcnow() - entry.created_at).total_seconds()
                if age < 10:  # only trust a very recent entry
                    return f"{entry.user.mention} | `{entry.user.id}`"
        except (discord.Forbidden, discord.HTTPException):
            pass
        return None

    @commands.Cog.listener()
    async def on_raw_message_delete(self, payload: discord.RawMessageDeleteEvent):
        # Cached messages are handled by on_message_delete with full content.
        if payload.cached_message is not None:
            return
        if payload.guild_id is None:
            return
        if payload.message_id in self.bot.deleted_by_filter:
            self.bot.deleted_by_filter.discard(payload.message_id)
            return
        if not db_handler.check_guild(self.bot.CONN, payload.guild_id):
            return

        log_ch = self._get_log_ch(payload.guild_id)
        if not log_ch:
            return

        guild = self.bot.get_guild(payload.guild_id)
        channel = self.bot.get_channel(payload.channel_id)
        await asyncio.sleep(1)  # let Discord's audit log populate
        deleter = await self._find_deleter(guild, payload.channel_id) if guild else None

        embed = discord.Embed(title="Message Deleted (older message)", color=0xe67e22)
        embed.add_field(
            name="Channel",
            value=f"{channel.mention} | `{payload.channel_id}`" if channel else f"`{payload.channel_id}`",
            inline=False)
        embed.add_field(name="Message ID", value=f"`{payload.message_id}`", inline=True)
        embed.add_field(name="Deleted By", value=deleter or "Unknown (likely self-deleted)", inline=True)
        embed.add_field(
            name="Content",
            value="*Unavailable — this message predates the bot's cache. "
                  "Discord does not retain deleted content.*",
            inline=False)
        embed.timestamp = discord.utils.utcnow()
        embed.set_footer(text=f"Guild: {guild.name}" if guild else "")
        await self._safe_send(log_ch, embed=embed)

    @commands.Cog.listener()
    async def on_raw_bulk_message_delete(self, payload: discord.RawBulkMessageDeleteEvent):
        """A purge. Worth one summary rather than N entries."""
        if payload.guild_id is None:
            return
        if not db_handler.check_guild(self.bot.CONN, payload.guild_id):
            return
        log_ch = self._get_log_ch(payload.guild_id)
        if not log_ch:
            return

        guild = self.bot.get_guild(payload.guild_id)
        channel = self.bot.get_channel(payload.channel_id)
        cached = len(payload.cached_messages)

        embed = discord.Embed(title="Bulk Message Deletion", color=0xe74c3c)
        embed.add_field(
            name="Channel",
            value=f"{channel.mention} | `{payload.channel_id}`" if channel else f"`{payload.channel_id}`",
            inline=False)
        embed.add_field(name="Messages Removed", value=str(len(payload.message_ids)), inline=True)
        embed.add_field(name="Content Recoverable", value=f"{cached} of {len(payload.message_ids)}", inline=True)
        if cached:
            preview = "\n".join(
                f"{m.author}: {(m.content or '(no text)')[:80]}"
                for m in list(payload.cached_messages)[:5])
            embed.add_field(name="Sample", value=f"```{preview[:900]}```", inline=False)
        embed.timestamp = discord.utils.utcnow()
        embed.set_footer(text=f"Guild: {guild.name}" if guild else "")
        await self._safe_send(log_ch, embed=embed)

    # ------------------------------------------------------------------
    # Edited messages
    # ------------------------------------------------------------------

    @commands.Cog.listener()
    async def on_message_edit(self, before: discord.Message, after: discord.Message):
        # Skip if only an embed was loaded (Discord auto-fetches OG tags)
        if before.content == after.content:
            return
        if after.author.bot or not after.guild:
            return
        # Yield briefly so the link filter can run its edit handler first.
        # If it catches the URL it will mark the ID; we skip to avoid double-logging.
        await asyncio.sleep(0.2)
        if after.id in self.bot.deleted_by_filter:
            # The delete event will clean up the set — don't discard here
            return
        if not db_handler.check_guild(self.bot.CONN, after.guild.id):
            return
        log_ch = self._get_log_ch(after.guild.id)
        if not log_ch:
            return

        embed = discord.Embed(title="Message Edited", color=0xf39c12)
        embed.add_field(
            name="Author",
            value=f"{after.author.mention} | `{after.author.id}`",
            inline=False,
        )
        embed.add_field(
            name="Channel",
            value=f"{after.channel.mention} | `{after.channel.id}`",
            inline=False,
        )

        before_text = (before.content or "*(empty)*")[:512]
        after_text = (after.content or "*(empty)*")[:512]
        embed.add_field(name="Before", value=f"```{before_text}```", inline=False)
        embed.add_field(name="After", value=f"```{after_text}```", inline=False)
        embed.add_field(
            name="Jump to Message",
            value=f"[Go to message]({after.jump_url})",
            inline=False,
        )

        embed.timestamp = discord.utils.utcnow()
        embed.set_footer(text=f"Message ID: {after.id}")
        await self._safe_send(log_ch, embed=embed)

    # ------------------------------------------------------------------
    # Member banned
    # ------------------------------------------------------------------

    @commands.Cog.listener()
    async def on_member_ban(self, guild: discord.Guild, user: discord.User):
        if not db_handler.check_guild(self.bot.CONN, guild.id):
            return
        log_ch = self._get_log_ch(guild.id)
        if not log_ch:
            return

        # Brief wait so Discord's audit log has time to populate
        await asyncio.sleep(1)

        moderator = "Unknown"
        reason    = "No reason provided"
        try:
            async for entry in guild.audit_logs(limit=5, action=discord.AuditLogAction.ban):
                if entry.target.id == user.id:
                    moderator = f"{entry.user.mention} | `{entry.user.id}`"
                    if entry.reason:
                        reason = entry.reason
                    break
        except (discord.Forbidden, discord.HTTPException):
            pass

        # If the ban was issued by the bot itself (name filter / panic), skip —
        # those actions already produce their own detailed log entry.
        if moderator != "Unknown" and f"`{self.bot.user.id}`" in moderator:
            return

        embed = discord.Embed(title="Member Banned", color=0xe74c3c)
        embed.set_thumbnail(url=user.display_avatar.url)
        embed.add_field(
            name="Banned User",
            value=f"{user.mention} | `{user.id}`",
            inline=False,
        )
        embed.add_field(name="Username", value=str(user), inline=True)
        embed.add_field(name="Banned By", value=moderator, inline=False)
        embed.add_field(name="Reason", value=reason, inline=False)
        embed.timestamp = discord.utils.utcnow()
        embed.set_footer(text=f"Guild: {guild.name}")
        await self._safe_send(log_ch, embed=embed)


def setup(bot):
    bot.add_cog(AuditLog(bot))
