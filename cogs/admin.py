# Admin - server management commands for bot owners and server owners.

import discord
from discord.ext import commands
from discord.commands import Option
from discord.enums import ChannelType
import db_handler
import two_factor_helper
import permissions
import logger


# Cog

class Admin(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    # /setup-guild  (bot owner + 2FA, one-time)

    @commands.guild_only()
    @commands.cooldown(1, 5, commands.BucketType.user)
    @commands.slash_command(
        name="setup-guild",
        description="[Owner] Initialize this server with the bot. Run once. Requires 2FA."
    )
    async def setup_guild(
        self, ctx: discord.ApplicationContext,
        log_channel: Option(discord.TextChannel, "Channel for bot logs and audit trail", required=True),
        announcement_channel: Option(discord.abc.GuildChannel, "Initial announcement channel", required=True),
        code: Option(int, "Your 6-digit 2FA code", required=True)
    ):
        # Server owner, not just the global operator: a client must be able to
        # set up their own server without waiting on whoever hosts the bot.
        allowed, err = permissions.check(self.bot, ctx, 'owner')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        if db_handler.check_guild(self.bot.CONN, ctx.guild.id):
            await ctx.respond("This server is already set up.", ephemeral=True)
            return

        if log_channel.id == announcement_channel.id:
            await ctx.respond("Log channel and announcement channel cannot be the same.", ephemeral=True)
            return

        try:
            db_handler.init_guild(self.bot.CONN, ctx.guild.id, log_channel.id, announcement_channel.id)
        except Exception as e:
            print(f"[setup_guild] {e}")
            await ctx.respond("Failed to set up server. Check the console for details.", ephemeral=True)
            return

        await ctx.respond(
            f"Server set up. Log channel: {log_channel.mention}. "
            f"Announcement channel: {announcement_channel.mention}.\n"
            "Webhook protection is **ON** by default. Use `/allow-webhook` for a 30-min window when needed.",
            ephemeral=True
        )
        try:
            await log_channel.send(
                f"**{self.bot.user.name}** configured for this server by {ctx.author.mention}."
            )
        except (discord.Forbidden, discord.HTTPException):
            pass

    # /add-announcer  (owner + 2FA)

    @commands.guild_only()
    @commands.cooldown(1, 5, commands.BucketType.user)
    @commands.slash_command(
        name="add-announcer",
        description="[Owner] Add a user as an announcer. They must then run /create-2fa. Requires 2FA."
    )
    async def add_announcer(self, ctx: discord.ApplicationContext,
                            member: Option(discord.Member, "Member to add as announcer"),
                            code: Option(int, "Your 6-digit 2FA code", required=True)):
        allowed, err = permissions.check(self.bot, ctx, 'owner')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return

        ok, err2 = permissions.guild_required(self.bot, ctx)
        if not ok:
            await ctx.respond(err2, ephemeral=True)
            return

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        if db_handler.check_authorised(self.bot.CONN, (ctx.guild.id, member.id)):
            await ctx.respond(f"{member.mention} is already an announcer.", ephemeral=True)
            return

        db_handler.authorise_member(self.bot.CONN, (ctx.guild.id, member.id))
        await ctx.respond(
            f"{member.mention} added as an announcer. "
            "They must run `/create-2fa` before using `/announce`.",
            ephemeral=True
        )

        # DM the new announcer
        try:
            await member.send(
                f"You have been added as an **announcer** in **{ctx.guild.name}**.\n"
                "Run `/create-2fa` in the server to set up 2FA before you can post announcements."
            )
        except (discord.Forbidden, discord.HTTPException):
            pass

        await logger.log_action(
            self.bot, ctx.guild, "Announcer Added", ctx.author,
            details={"Member": f"{member} ({member.id})", "Action": "Added to announcers list"},
            level='success'
        )

    # /remove-announcer  (owner + 2FA)

    @commands.guild_only()
    @commands.cooldown(1, 5, commands.BucketType.user)
    @commands.slash_command(
        name="remove-announcer",
        description="[Owner] Remove announce permissions from a user. Requires 2FA."
    )
    async def remove_announcer(self, ctx: discord.ApplicationContext,
                               member: Option(discord.Member, "Member to remove from announcers"),
                               code: Option(int, "Your 6-digit 2FA code", required=True)):
        allowed, err = permissions.check(self.bot, ctx, 'owner')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return

        ok, err2 = permissions.guild_required(self.bot, ctx)
        if not ok:
            await ctx.respond(err2, ephemeral=True)
            return

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        if not db_handler.check_authorised(self.bot.CONN, (ctx.guild.id, member.id)):
            await ctx.respond(f"{member.mention} is not an announcer.", ephemeral=True)
            return

        db_handler.deauthorise_member(self.bot.CONN, (ctx.guild.id, member.id))
        await ctx.respond(f"{member.mention} removed from announcers.", ephemeral=True)

        await logger.log_action(
            self.bot, ctx.guild, "Announcer Removed", ctx.author,
            details={"Member": f"{member} ({member.id})", "Action": "Removed from announcers list"},
            level='warning'
        )

    # /add-linkmanager  (owner + 2FA)

    @commands.guild_only()
    @commands.cooldown(1, 5, commands.BucketType.user)
    @commands.slash_command(
        name="add-linkmanager",
        description="[Owner] Add a user as a link manager. They must then run /create-2fa. Requires 2FA."
    )
    async def add_linkmanager(self, ctx: discord.ApplicationContext,
                              member: Option(discord.Member, "Member to add as link manager"),
                              code: Option(int, "Your 6-digit 2FA code", required=True)):
        allowed, err = permissions.check(self.bot, ctx, 'owner')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return

        ok, err2 = permissions.guild_required(self.bot, ctx)
        if not ok:
            await ctx.respond(err2, ephemeral=True)
            return

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        added = db_handler.add_link_manager(self.bot.CONN, ctx.guild.id, member.id)
        if not added:
            await ctx.respond(f"{member.mention} is already a link manager.", ephemeral=True)
            return

        await ctx.respond(
            f"{member.mention} added as a link manager. "
            "They must run `/create-2fa` before managing the link whitelist.",
            ephemeral=True
        )

        try:
            await member.send(
                f"You have been added as a **link manager** in **{ctx.guild.name}**.\n"
                "Run `/create-2fa` in the server to set up 2FA before managing link filters."
            )
        except (discord.Forbidden, discord.HTTPException):
            pass

        await logger.log_action(
            self.bot, ctx.guild, "Link Manager Added", ctx.author,
            details={"Member": f"{member} ({member.id})", "Action": "Added to link managers list"},
            level='success'
        )

    # /remove-linkmanager  (owner + 2FA)

    @commands.guild_only()
    @commands.cooldown(1, 5, commands.BucketType.user)
    @commands.slash_command(
        name="remove-linkmanager",
        description="[Owner] Remove a user from the link managers list. Requires 2FA."
    )
    async def remove_linkmanager(self, ctx: discord.ApplicationContext,
                                 member: Option(discord.Member, "Member to remove from link managers"),
                                 code: Option(int, "Your 6-digit 2FA code", required=True)):
        allowed, err = permissions.check(self.bot, ctx, 'owner')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return

        ok, err2 = permissions.guild_required(self.bot, ctx)
        if not ok:
            await ctx.respond(err2, ephemeral=True)
            return

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        removed = db_handler.remove_link_manager(self.bot.CONN, ctx.guild.id, member.id)
        if not removed:
            await ctx.respond(f"{member.mention} is not a link manager.", ephemeral=True)
            return

        await ctx.respond(f"{member.mention} removed from link managers.", ephemeral=True)
        await logger.log_action(
            self.bot, ctx.guild, "Link Manager Removed", ctx.author,
            details={"Member": f"{member} ({member.id})", "Action": "Removed from link managers list"},
            level='warning'
        )

    # /set-logs  (owner)

    @commands.guild_only()
    @commands.cooldown(1, 5, commands.BucketType.user)
    @commands.slash_command(
        name="set-logs",
        description="[Owner] Set or change the log channel for this server. Requires 2FA."
    )
    async def set_logs(self, ctx: discord.ApplicationContext,
                       channel: Option(discord.TextChannel, "New log channel", required=True),
                       code: Option(int, "Your 6-digit 2FA code", required=True)):
        allowed, err = permissions.check(self.bot, ctx, 'owner')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return

        ok, err2 = permissions.guild_required(self.bot, ctx)
        if not ok:
            await ctx.respond(err2, ephemeral=True)
            return

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        old_id = db_handler.get_log_channel(self.bot.CONN, ctx.guild.id)
        db_handler.set_log_channel(self.bot.CONN, ctx.guild.id, channel.id)
        await ctx.respond(f"Log channel updated to {channel.mention}.", ephemeral=True)

        # Notify the old log channel
        if old_id and old_id != channel.id:
            old_ch = self.bot.get_channel(old_id)
            await logger.safe_send(
                old_ch,
                content=f"Log channel changed to {channel.mention} by {ctx.author.mention}."
            )

        try:
            await channel.send(f"This channel is now the log channel. Set by {ctx.author.mention}.")
        except (discord.Forbidden, discord.HTTPException):
            pass

    # /change-timeout  (bot owner)

    @commands.guild_only()
    @commands.cooldown(1, 5, commands.BucketType.user)
    @commands.slash_command(
        name="change-timeout",
        description="[Owner] Change the announcement permission lifetime in seconds. Requires 2FA."
    )
    async def change_timeout(self, ctx: discord.ApplicationContext,
                             seconds: Option(int, "Timeout in seconds (30–3600)", required=True,
                                            min_value=30, max_value=3600),
                             code: Option(int, "Your 6-digit 2FA code", required=True)):
        allowed, err = permissions.check(self.bot, ctx, 'owner')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return

        ok, err2 = permissions.guild_required(self.bot, ctx)
        if not ok:
            await ctx.respond(err2, ephemeral=True)
            return

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        db_handler.set_announce_timeout(self.bot.CONN, ctx.guild.id, seconds)
        await ctx.respond(f"Announcement timeout set to **{seconds} seconds**.", ephemeral=True)
        await logger.log_action(
            self.bot, ctx.guild, "Announce Timeout Changed", ctx.author,
            details={"New Timeout": f"{seconds}s"},
            level='info'
        )

    # /list  (any registered user)

    @commands.guild_only()
    @commands.slash_command(description="List configured information for this server.")
    async def list(self, ctx: discord.ApplicationContext,
                   option: Option(str, "What to list",
                                  choices=["announcers", "link-managers", "whitelist", "channels", "exempt"],
                                  required=True)):
        allowed, err = permissions.check(self.bot, ctx, 'any_registered')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return

        ok, err2 = permissions.guild_required(self.bot, ctx)
        if not ok:
            await ctx.respond(err2, ephemeral=True)
            return

        if option == "announcers":
            member_ids = db_handler.get_trusted_members(self.bot.CONN, ctx.guild.id)
            if not member_ids:
                await ctx.respond("No announcers configured.", ephemeral=True)
                return
            lines = []
            for mid in member_ids:
                m = ctx.guild.get_member(mid)
                verified = db_handler.check_verified(self.bot.CONN, mid) == 1
                status = "(2FA verified)" if verified else "(2FA not set up)"
                lines.append(f"• {m.mention if m else f'Unknown ({mid})'} {status}")
            embed = discord.Embed(title="Announcers", description="\n".join(lines), color=0x3498db)
            await ctx.respond(embed=embed, ephemeral=True)

        elif option == "link-managers":
            manager_ids = db_handler.get_link_managers(self.bot.CONN, ctx.guild.id)
            if not manager_ids:
                await ctx.respond("No link managers configured.", ephemeral=True)
                return
            lines = []
            for mid in manager_ids:
                m = ctx.guild.get_member(mid)
                verified = db_handler.check_verified(self.bot.CONN, mid) == 1
                status = "(2FA verified)" if verified else "(2FA not set up)"
                lines.append(f"• {m.mention if m else f'Unknown ({mid})'} {status}")
            embed = discord.Embed(title="Link Managers", description="\n".join(lines), color=0x3498db)
            await ctx.respond(embed=embed, ephemeral=True)

        elif option == "whitelist":
            entries = db_handler.get_link_whitelist(self.bot.CONN, ctx.guild.id)
            if not entries:
                await ctx.respond("No links are whitelisted. Use `/allow-link`.", ephemeral=True)
                return
            domain_entries = [u for t, u in entries if t == "domain"]
            specific_entries = [u for t, u in entries if t == "specific"]
            embed = discord.Embed(title="Link Whitelist", color=0x2ecc71)
            if domain_entries:
                embed.add_field(
                    name=f"Domains ({len(domain_entries)})",
                    value="\n".join(f"• `{u}`" for u in domain_entries[:20]),
                    inline=False
                )
            if specific_entries:
                embed.add_field(
                    name=f"Specific URLs ({len(specific_entries)})",
                    value="\n".join(f"• `{u}`" for u in specific_entries[:20]),
                    inline=False
                )
            await ctx.respond(embed=embed, ephemeral=True)

        elif option == "channels":
            channel_ids = db_handler.get_channels(self.bot.CONN, ctx.guild.id)
            if not channel_ids:
                await ctx.respond("No announcement channels configured.", ephemeral=True)
                return
            lines = []
            for cid in channel_ids:
                ch = self.bot.get_channel(cid)
                lines.append(f"• {ch.mention if ch else f'Unknown ({cid})'}")
            embed = discord.Embed(
                title="Announcement Channels",
                description="\n".join(lines),
                color=0x9b59b6
            )
            await ctx.respond(embed=embed, ephemeral=True)

        elif option == "exempt":
            exemptions = db_handler.get_filter_exemptions(self.bot.CONN, ctx.guild.id)
            if not exemptions:
                await ctx.respond("No link filter exemptions configured.", ephemeral=True)
                return
            by_type = {}
            for entity_type, entity_id in exemptions:
                by_type.setdefault(entity_type, []).append(entity_id)
            embed = discord.Embed(title="Link Filter Exemptions", color=0xf39c12)
            for etype, ids in by_type.items():
                lines = []
                for eid in ids:
                    if etype == "channel":
                        obj = self.bot.get_channel(eid)
                        lines.append(f"• {obj.mention if obj else f'#{eid}'}")
                    elif etype == "role":
                        obj = ctx.guild.get_role(eid)
                        lines.append(f"• {obj.mention if obj else f'Role {eid}'}")
                    elif etype == "user":
                        obj = ctx.guild.get_member(eid)
                        lines.append(f"• {obj.mention if obj else f'User {eid}'}")
                    elif etype == "category":
                        obj = self.bot.get_channel(eid)
                        lines.append(f"• {obj.name if obj else f'Category {eid}'}")
                embed.add_field(
                    name=etype.title() + "s",
                    value="\n".join(lines[:15]) or "none",
                    inline=False
                )
            await ctx.respond(embed=embed, ephemeral=True)

    # /add-channel  (owner - add an announcement channel)

    @commands.guild_only()
    @commands.cooldown(1, 5, commands.BucketType.user)
    @commands.slash_command(
        name="add-channel",
        description="[Owner] Add a channel to the announcement channels list. Requires 2FA."
    )
    async def add_channel(self, ctx: discord.ApplicationContext,
                          channel: Option(discord.abc.GuildChannel, "Channel to add", required=True,
                                          channel_types=[ChannelType.text, ChannelType.news, ChannelType.forum]),
                          code: Option(int, "Your 6-digit 2FA code", required=True)):
        allowed, err = permissions.check(self.bot, ctx, 'owner')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return

        ok, err2 = permissions.guild_required(self.bot, ctx)
        if not ok:
            await ctx.respond(err2, ephemeral=True)
            return

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        existing = db_handler.get_channels(self.bot.CONN, ctx.guild.id)
        if channel.id in existing:
            await ctx.respond(f"{channel.mention} is already an announcement channel.", ephemeral=True)
            return

        db_handler.insert_channel(self.bot.CONN, (channel.id, ctx.guild.id))
        await ctx.respond(f"{channel.mention} added to announcement channels.", ephemeral=True)
        await logger.log_action(
            self.bot, ctx.guild, "Announcement Channel Added", ctx.author,
            details={"Channel": channel.mention},
            level='success'
        )

    # /remove-channel  (owner - remove an announcement channel)

    @commands.guild_only()
    @commands.cooldown(1, 5, commands.BucketType.user)
    @commands.slash_command(
        name="remove-channel",
        description="[Owner] Remove a channel from the announcement channels list. Requires 2FA."
    )
    async def remove_channel(self, ctx: discord.ApplicationContext,
                             channel: Option(discord.abc.GuildChannel, "Channel to remove", required=True,
                                             channel_types=[ChannelType.text, ChannelType.news, ChannelType.forum]),
                             code: Option(int, "Your 6-digit 2FA code", required=True)):
        allowed, err = permissions.check(self.bot, ctx, 'owner')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return

        ok, err2 = permissions.guild_required(self.bot, ctx)
        if not ok:
            await ctx.respond(err2, ephemeral=True)
            return

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        existing = db_handler.get_channels(self.bot.CONN, ctx.guild.id)
        if channel.id not in existing:
            await ctx.respond(f"{channel.mention} is not in the announcement channels list.", ephemeral=True)
            return

        db_handler.delete_channel(self.bot.CONN, channel.id)
        await ctx.respond(f"{channel.mention} removed from announcement channels.", ephemeral=True)
        await logger.log_action(
            self.bot, ctx.guild, "Announcement Channel Removed", ctx.author,
            details={"Channel": channel.mention},
            level='warning'
        )

    # /list-all  (owner - everything at once)

    @commands.guild_only()
    @commands.slash_command(
        name="list-all",
        description="[Owner] View a complete summary of all bot configuration for this server."
    )
    async def list_all(self, ctx: discord.ApplicationContext):
        allowed, err = permissions.check(self.bot, ctx, 'owner_no_2fa')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return

        ok, err2 = permissions.guild_required(self.bot, ctx)
        if not ok:
            await ctx.respond(err2, ephemeral=True)
            return

        gid = ctx.guild.id

        announcers = db_handler.get_trusted_members(self.bot.CONN, gid)
        managers = db_handler.get_link_managers(self.bot.CONN, gid)
        channels = db_handler.get_channels(self.bot.CONN, gid)
        whitelist_count = len(db_handler.get_link_whitelist(self.bot.CONN, gid))
        exempt_count = len(db_handler.get_filter_exemptions(self.bot.CONN, gid))
        filter_on = db_handler.get_link_filter_enabled(self.bot.CONN, gid)
        webhook_on = db_handler.check_webhook(self.bot.CONN, gid)
        timeout = db_handler.get_announce_timeout(self.bot.CONN, gid)
        log_id = db_handler.get_log_channel(self.bot.CONN, gid)

        def fmt_members(ids):
            if not ids:
                return "None"
            lines = []
            for mid in ids:
                m = ctx.guild.get_member(mid)
                lines.append(m.mention if m else f"Unknown ({mid})")
            return ", ".join(lines)

        def fmt_channels(ids):
            if not ids:
                return "None"
            lines = []
            for cid in ids:
                ch = self.bot.get_channel(cid)
                lines.append(ch.mention if ch else f"#{cid}")
            return ", ".join(lines)

        embed = discord.Embed(
            title=f"Server Configuration — {ctx.guild.name}",
            color=0x2ecc71,
            timestamp=discord.utils.utcnow()
        )
        embed.add_field(name="Log Channel", value=f"<#{log_id}>" if log_id else "Not set", inline=True)
        embed.add_field(name="Link Filter", value="ON" if filter_on else "OFF", inline=True)
        embed.add_field(name="Webhook Protection", value="ON" if webhook_on else "OFF", inline=True)
        embed.add_field(name="Announce Timeout", value=f"{timeout}s", inline=True)
        embed.add_field(name="Whitelist Entries", value=str(whitelist_count), inline=True)
        embed.add_field(name="Filter Exemptions", value=str(exempt_count), inline=True)
        embed.add_field(name=f"Announcers ({len(announcers)})", value=fmt_members(announcers), inline=False)
        embed.add_field(name=f"Link Managers ({len(managers)})", value=fmt_members(managers), inline=False)
        embed.add_field(name=f"Announce Channels ({len(channels)})", value=fmt_channels(channels), inline=False)

        await ctx.respond(embed=embed, ephemeral=True)


def setup(bot):
    bot.add_cog(Admin(bot))
