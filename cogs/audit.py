import asyncio
import time

import discord
from discord.ext import commands
import db_handler
import logger


class AuditLog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        # guild_id -> [count, asyncio.Task] for pending tamper summaries
        self._tamper: dict[int, list] = {}
        # guild_id -> timestamps of recent log-channel rebuilds
        self._recreates: dict[int, list[float]] = {}

    TAMPER_WINDOW = 6.0

    # Rebuild the log channel at most this many times per window, so a repeat
    # deleter cannot pull the bot into a create/delete loop.
    RECREATE_LIMIT = 3
    RECREATE_WINDOW = 600.0

    def _note_tamper(self, guild: discord.Guild, count: int = 1):
        entry = self._tamper.get(guild.id)
        if entry:
            entry[0] += count
            return
        self._tamper[guild.id] = [count, asyncio.create_task(self._flush_tamper(guild))]

    async def _flush_tamper(self, guild: discord.Guild):
        await asyncio.sleep(self.TAMPER_WINDOW)
        entry = self._tamper.pop(guild.id, None)
        if not entry:
            return
        count = entry[0]

        log_id = db_handler.get_log_channel(self.bot.CONN, guild.id)
        deleter = await self._find_deleter(guild, log_id)
        await logger.log_action(
            self.bot, guild,
            "Audit Log Tampering — Entries Deleted",
            guild.me,
            details={
                "Entries removed": str(count),
                "Deleted by": deleter or "Unknown — Discord did not record it",
                "Note": (
                    "Somebody removed Hodor's own audit entries from this channel. "
                    "Deny **Manage Messages** on this channel so the log cannot be "
                    "edited by anyone."
                ),
            },
            level='critical',
        )

    def _is_own_log_message(self, guild_id: int, channel_id: int, author_id=None) -> bool:
        """True if this message is one of our audit entries in the log channel."""
        log_id = db_handler.get_log_channel(self.bot.CONN, guild_id)
        if not log_id or channel_id != log_id:
            return False
        return author_id is None or author_id == self.bot.user.id

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

    # Deleted messages

    @commands.Cog.listener()
    async def on_message_delete(self, message: discord.Message):
        if not message.guild:
            return
        if message.author.bot:
            if (self.bot.user and message.author.id == self.bot.user.id
                    and db_handler.check_guild(self.bot.CONN, message.guild.id)
                    and self._is_own_log_message(message.guild.id, message.channel.id)):
                self._note_tamper(message.guild)
            return
        # Suppressed - link filter already logged this deletion specifically
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
            # Truncate - Discord embed field cap is 1024 chars
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

    # Deleted messages Discord never cached (older than the bot's memory)

    async def _find_deleter(self, guild: discord.Guild, channel_id: int):
        """
        Best-effort attribution for a deletion.

        Discord only writes an audit-log entry when someone deletes someone else's
        message. "Unknown" means self-deleted, or Discord didn't say.
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
        if payload.cached_message is not None:
            return
        if payload.guild_id is None:
            return
        if payload.message_id in self.bot.deleted_by_filter:
            self.bot.deleted_by_filter.discard(payload.message_id)
            return
        if not db_handler.check_guild(self.bot.CONN, payload.guild_id):
            return

        if self._is_own_log_message(payload.guild_id, payload.channel_id):
            guild = self.bot.get_guild(payload.guild_id)
            if guild:
                self._note_tamper(guild)
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

        # A purge of the log channel is the loud version of tampering.
        if self._is_own_log_message(payload.guild_id, payload.channel_id):
            guild = self.bot.get_guild(payload.guild_id)
            if guild:
                self._note_tamper(guild, count=len(payload.message_ids))
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

    # Edited messages

    @commands.Cog.listener()
    async def on_message_edit(self, before: discord.Message, after: discord.Message):
        # Skip if only an embed was loaded (Discord auto-fetches OG tags)
        if before.content == after.content:
            return
        if after.author.bot or not after.guild:
            return
        
        await asyncio.sleep(0.2)
        if after.id in self.bot.deleted_by_filter:
            # The delete event will clean up the set - don't discard here
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

    # Member banned

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


    # The log channel itself being deleted

    @commands.Cog.listener()
    async def on_guild_channel_delete(self, channel):
        """
        Losing the log channel is the one failure the log cannot report.

        Every other event ends up in that channel; when the channel is what
        went missing, the bot would just fall silent and keep running, and the
        first anyone notices is when they go looking for an entry that was
        never written. So this is delivered by DM instead - to the server owner
        and to the operator - and the stored channel is cleared so the config
        does not point at something that no longer exists. The bot now tries to 
        build a new channel.
        """
        guild = getattr(channel, "guild", None)
        if guild is None:
            return
        if not db_handler.check_guild(self.bot.CONN, guild.id):
            return
        if db_handler.get_log_channel(self.bot.CONN, guild.id) != channel.id:
            return

        culprit = None
        try:
            async for entry in guild.audit_logs(
                    limit=5, action=discord.AuditLogAction.channel_delete):
                if (discord.utils.utcnow() - entry.created_at).total_seconds() < 15:
                    culprit = f"{entry.user} (`{entry.user.id}`)"
                    break
        except (discord.Forbidden, discord.HTTPException):
            pass

        replacement = None
        if self._may_recreate(guild.id):
            replacement = await self._recreate_log_channel(guild, channel, culprit)

        if replacement:
            db_handler.set_log_channel(self.bot.CONN, guild.id, replacement.id)
            head = (
                f"**Your Hodor log channel was deleted in {guild.name} - I rebuilt it.**\n\n"
                f"Replacement: {replacement.mention} (`{replacement.id}`), same category "
                f"and position, visible only to the roles that could see the old one.\n"
            )
            tail = (
                "\n**The previous entries are gone.** Discord does not return deleted "
                "messages to anyone, including bots, so logging resumes from now.\n\n"
                "Deny **Manage Channels** and **Manage Messages** on it so this cannot "
                "happen again."
            )
        else:
            db_handler.set_log_channel(self.bot.CONN, guild.id, None)
            head = (
                f"**Your Hodor log channel was deleted in {guild.name}.**\n\n"
                f"Channel: `#{channel.name}` (`{channel.id}`)\n"
                "I could not rebuild it - I need the **Manage Channels** permission, "
                "or it has been deleted too many times in a row.\n"
            )
            tail = (
                "\n**Security events are not being recorded right now.** Everything else "
                "still runs - links are still filtered, 2FA still applies - but nothing "
                "is being written down.\n\n"
                "Set a new one with `/set-logs channel:#your-channel code:<2FA>`."
            )

        text = f"{head}Deleted by: {culprit or 'unknown - Discord did not record it'}\n{tail}"

        targets = [guild.owner_id, getattr(self.bot, "master_user", None)]
        for uid in {t for t in targets if t}:
            try:
                user = self.bot.get_user(uid) or await self.bot.fetch_user(uid)
                await user.send(text)
            except (discord.Forbidden, discord.HTTPException, discord.NotFound):
                continue

        state = f"rebuilt as #{replacement.name}" if replacement else "NOT rebuilt"
        print(f"[audit] Log channel deleted in {guild.name} ({guild.id}) - {state}.")

    def _may_recreate(self, guild_id: int) -> bool:
        """
        Rate-limit rebuilds.

        Someone deleting the channel repeatedly should not get an endless
        create/delete fight with the bot - after a few attempts, stop and let
        the DM stand on its own.
        """
        now = time.monotonic()
        seen = [t for t in self._recreates.get(guild_id, []) if now - t < self.RECREATE_WINDOW]
        if len(seen) >= self.RECREATE_LIMIT:
            self._recreates[guild_id] = seen
            return False
        seen.append(now)
        self._recreates[guild_id] = seen
        return True

    async def _recreate_log_channel(self, guild, old, culprit):
        """
        Rebuild the log channel where the old one was.

        Overwrites are carried over so whoever could read the log still can,
        but two are forced regardless of how the old channel was configured:
        @everyone is denied view, and the bot is granted what it needs to post.
        A rebuilt audit log that ordinary members can suddenly read would leak
        every moderation action in the server.
        """
        overwrites = {}
        try:
            overwrites = dict(getattr(old, "overwrites", {}) or {})
        except (AttributeError, TypeError):
            pass

        overwrites[guild.default_role] = discord.PermissionOverwrite(view_channel=False)
        if guild.me is not None:
            overwrites[guild.me] = discord.PermissionOverwrite(
                view_channel=True, send_messages=True, embed_links=True,
                attach_files=True, read_message_history=True,
            )

        try:
            new = await guild.create_text_channel(
                name=old.name,
                category=getattr(old, "category", None),
                position=getattr(old, "position", None),
                topic=getattr(old, "topic", None),
                overwrites=overwrites,
                reason="Hodor: log channel was deleted, rebuilding it",
            )
        except (discord.Forbidden, discord.HTTPException) as exc:
            print(f"[audit] Could not rebuild log channel in {guild.id}: {exc}")
            return None

        embed = discord.Embed(
            title="Log channel rebuilt",
            description=(
                f"`#{old.name}` was deleted and I recreated it here, in the same "
                f"category and position.\n\n"
                "**The entries that were in it are gone.** Discord does not return "
                "deleted messages to anyone, so this log starts from now."
            ),
            color=0x8b0000,
            timestamp=discord.utils.utcnow(),
        )
        embed.add_field(name="Deleted by",
                        value=culprit or "Unknown - Discord did not record it",
                        inline=False)
        embed.add_field(
            name="Stop it happening again",
            value=("Deny **Manage Channels** and **Manage Messages** on this channel "
                   "for every role. Only the bot needs to write here."),
            inline=False,
        )
        await self._safe_send(new, embed=embed)
        return new


def setup(bot):
    bot.add_cog(AuditLog(bot))
