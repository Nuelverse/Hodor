"""
Link Filter — scans all messages for non-whitelisted links and deletes them.

Commands:
  /allow-link type:[domain|specific]     Link manager + 2FA (via modal, supports bulk)
  /remove-link url code:<2FA>            Link manager + 2FA
  /toggle-linkfilter code:<2FA>          Bot owner + 2FA
  /add-whitelist-linkfilter              Bot/server owner + 2FA (exempt entity from filter)
  /remove-whitelist-linkfilter           Bot/server owner + 2FA

The scanner runs on every message and every edit across all configured guilds.
"""

import discord
from discord.ext import commands
from discord.commands import Option
import db_handler
import two_factor_helper
import permissions
import logger
import link_scanner


# ---------------------------------------------------------------------------
# Modal: bulk URL whitelisting
# ---------------------------------------------------------------------------

class AllowLinkModal(discord.ui.Modal):
    def __init__(self, bot, guild: discord.Guild, link_type: str):
        super().__init__(title=f"Whitelist {'Domains' if link_type == 'domain' else 'Specific URLs'}")
        self.bot = bot
        self.guild = guild
        self.link_type = link_type

        self.add_item(discord.ui.InputText(
            label="Your 2FA Code",
            style=discord.InputTextStyle.short,
            placeholder="6-digit code from your authenticator app",
            min_length=6,
            max_length=6,
            required=True,
        ))
        hint = (
            "example.com\ncdn.example.com"
            if link_type == "domain"
            else "https://example.com/page\nhttps://other.com/file.pdf"
        )
        self.add_item(discord.ui.InputText(
            label="URLs to whitelist (one per line, max 10)",
            style=discord.InputTextStyle.paragraph,
            placeholder=hint,
            required=True,
            max_length=2000,
        ))

    async def callback(self, interaction: discord.Interaction):
        code_str = self.children[0].value.strip()
        urls_raw = self.children[1].value

        try:
            code = int(code_str)
        except ValueError:
            await interaction.response.send_message("Invalid 2FA code format.", ephemeral=True)
            return

        if not two_factor_helper.verify_code(self.bot.CONN, interaction.user.id, code):
            await interaction.response.send_message("Incorrect 2FA code.", ephemeral=True)
            return

        urls = [u.strip().rstrip("/") for u in urls_raw.strip().splitlines() if u.strip()][:10]
        if not urls:
            await interaction.response.send_message("No valid URLs provided.", ephemeral=True)
            return

        added, dupes = [], []
        for url in urls:
            # For domain type, strip protocol and path — keep only the domain
            if self.link_type == "domain":
                url = _extract_domain(url)
            ok = db_handler.add_link_whitelist(
                self.bot.CONN, self.guild.id, self.link_type, url, interaction.user.id
            )
            (added if ok else dupes).append(url)

        lines = []
        if added:
            scope = "and all subdomains" if self.link_type == "domain" else "(exact match)"
            lines.append(f"Whitelisted {len(added)} {'domain(s)' if self.link_type == 'domain' else 'URL(s)'} {scope}:")
            lines.extend(f"  `{u}`" for u in added)
        if dupes:
            lines.append(f"Already whitelisted ({len(dupes)}):")
            lines.extend(f"  `{u}`" for u in dupes)

        await interaction.response.send_message("\n".join(lines), ephemeral=True)

        if added:
            await logger.log_action(
                self.bot, self.guild,
                f"Link Whitelist Updated — {self.link_type.title()}",
                interaction.user,
                details={
                    "Type": self.link_type,
                    "Added": "\n".join(f"`{u}`" for u in added[:10]),
                    "Count": str(len(added)),
                },
                level='success'
            )


def _extract_domain(url: str) -> str:
    """Strip protocol/path from a URL and return just the domain."""
    url = url.strip()
    for prefix in ("https://", "http://", "www."):
        if url.lower().startswith(prefix):
            url = url[len(prefix):]
    url = url.split("/")[0].split("?")[0]
    return url


# ---------------------------------------------------------------------------
# Cog
# ---------------------------------------------------------------------------

class LinkFilter(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    # ------------------------------------------------------------------
    # Bypass check (who is exempt from the link filter)
    # ------------------------------------------------------------------

    def _is_bypassed(self, message: discord.Message) -> bool:
        uid = message.author.id
        gid = message.guild.id

        # Bot owner and server owner always bypass
        if uid == self.bot.master_user or uid == message.guild.owner_id:
            return True

        # Check user-specific exemption
        if db_handler.is_filter_exempt(self.bot.CONN, gid, 'user', uid):
            return True

        # Check channel exemption
        if db_handler.is_filter_exempt(self.bot.CONN, gid, 'channel', message.channel.id):
            return True

        # Check category exemption
        if message.channel.category_id and db_handler.is_filter_exempt(
                self.bot.CONN, gid, 'category', message.channel.category_id):
            return True

        # Check role exemptions (single efficient query)
        role_ids = [r.id for r in message.author.roles]
        if db_handler.is_filter_exempt_by_roles(self.bot.CONN, gid, role_ids):
            return True

        # Legacy config-based role bypass
        ignore_ids = self.bot.config.get("link_filter", {}).get("ignore_roles", [])
        return any(r.id in ignore_ids for r in message.author.roles)

    def _filter_active(self, guild_id: int) -> bool:
        return (
            db_handler.check_guild(self.bot.CONN, guild_id)
            and db_handler.get_link_filter_enabled(self.bot.CONN, guild_id)
        )

    # ------------------------------------------------------------------
    # on_message
    # ------------------------------------------------------------------

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        if message.author.bot or not message.guild:
            return
        if not self._filter_active(message.guild.id):
            return
        if self._is_bypassed(message):
            return

        whitelist = db_handler.get_link_whitelist(self.bot.CONN, message.guild.id)
        blocked, label = link_scanner.scan(message.content, whitelist)
        if blocked:
            self.bot.deleted_by_filter.add(message.id)
            try:
                await message.delete()
            except (discord.Forbidden, discord.HTTPException):
                pass
            await logger.log_link_deleted(
                self.bot, message.guild, message.author, message.channel, label, message.content
            )

    # ------------------------------------------------------------------
    # on_message_edit
    # ------------------------------------------------------------------

    @commands.Cog.listener()
    async def on_message_edit(self, before: discord.Message, after: discord.Message):
        if before.content == after.content:
            return
        if after.author.bot or not after.guild:
            return
        if not self._filter_active(after.guild.id):
            return
        if self._is_bypassed(after):
            return

        whitelist = db_handler.get_link_whitelist(self.bot.CONN, after.guild.id)
        blocked, label = link_scanner.scan(after.content, whitelist)
        if blocked:
            self.bot.deleted_by_filter.add(after.id)
            try:
                await after.delete()
            except (discord.Forbidden, discord.HTTPException):
                pass
            await logger.log_link_deleted(
                self.bot, after.guild, after.author, after.channel, label, after.content, edited=True
            )

    # ------------------------------------------------------------------
    # /allow-link  (link manager + 2FA via modal)
    # ------------------------------------------------------------------

    @commands.guild_only()
    @commands.slash_command(
        name="allow-link",
        description="Whitelist domain(s) or exact URL(s). Opens a modal for bulk entry. Requires 2FA."
    )
    async def allow_link(self, ctx: discord.ApplicationContext,
                         type: Option(str, "Domain (+ all subdomains) or specific URL?",
                                      choices=["domain", "specific"], required=True)):
        allowed, err = permissions.check(self.bot, ctx, 'link_manager')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return

        ok, err2 = permissions.guild_required(self.bot, ctx)
        if not ok:
            await ctx.respond(err2, ephemeral=True)
            return

        modal = AllowLinkModal(self.bot, ctx.guild, type)
        await ctx.send_modal(modal)

    # ------------------------------------------------------------------
    # /remove-link  (link manager + 2FA)
    # ------------------------------------------------------------------

    @commands.guild_only()
    @commands.slash_command(
        name="remove-link",
        description="Remove a URL or domain from the whitelist. Requires 2FA."
    )
    async def remove_link(self, ctx: discord.ApplicationContext,
                          url: Option(str, "Exact URL or domain as it was added", required=True),
                          code: Option(int, "Your 6-digit 2FA code", required=True)):
        allowed, err = permissions.check(self.bot, ctx, 'link_manager')
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

        clean = url.strip().rstrip("/")
        removed = db_handler.remove_link_whitelist(self.bot.CONN, ctx.guild.id, clean)
        if not removed:
            await ctx.respond(f"`{clean}` is not in the whitelist.", ephemeral=True)
            return

        await ctx.respond(f"Removed `{clean}` from the whitelist.", ephemeral=True)
        await logger.log_action(
            self.bot, ctx.guild, "Link Removed from Whitelist", ctx.author,
            details={"Removed": f"`{clean}`"},
            level='warning'
        )

    # ------------------------------------------------------------------
    # /toggle-linkfilter  (bot owner + 2FA)
    # ------------------------------------------------------------------

    @commands.guild_only()
    @commands.slash_command(
        name="toggle-linkfilter",
        description="[Owner] Toggle link filtering on or off for this server. Requires 2FA."
    )
    async def toggle_linkfilter(self, ctx: discord.ApplicationContext,
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

        old_state = db_handler.get_link_filter_enabled(self.bot.CONN, ctx.guild.id)
        new_state = db_handler.toggle_link_filter(self.bot.CONN, ctx.guild.id)
        old_str = "ENABLED" if old_state else "DISABLED"
        new_str = "ENABLED" if new_state else "DISABLED"
        await ctx.respond(
            f"Link filter: **{old_str}** → **{new_str}**.", ephemeral=True
        )
        await logger.log_action(
            self.bot, ctx.guild, f"Link Filter {new_str}", ctx.author,
            details={"Previous": old_str, "New State": new_str},
            level='success' if new_state else 'warning'
        )

    # ------------------------------------------------------------------
    # /add-whitelist-linkfilter  (bot/server owner + 2FA)
    # ------------------------------------------------------------------

    @commands.guild_only()
    @commands.slash_command(
        name="add-whitelist-linkfilter",
        description="[Owner] Exempt a channel, category, role, or user from link filtering. Requires 2FA."
    )
    async def add_whitelist_linkfilter(
        self, ctx: discord.ApplicationContext,
        entity_type: Option(str, "What to exempt",
                            choices=["channel", "category", "role", "user"], required=True),
        target: Option(str, "ID of the channel/category/role/user to exempt", required=True),
        code: Option(int, "Your 6-digit 2FA code", required=True)
    ):
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

        try:
            entity_id = int(target.strip().lstrip("<@&#").rstrip(">"))
        except ValueError:
            await ctx.respond("Invalid ID format. Provide the raw Discord ID or a mention.", ephemeral=True)
            return

        added = db_handler.add_filter_exempt(
            self.bot.CONN, ctx.guild.id, entity_type, entity_id, ctx.author.id
        )
        if not added:
            await ctx.respond(f"That {entity_type} (ID: {entity_id}) is already exempt.", ephemeral=True)
            return

        await ctx.respond(
            f"{entity_type.title()} (ID: `{entity_id}`) is now exempt from the link filter.",
            ephemeral=True
        )
        await logger.log_action(
            self.bot, ctx.guild, "Link Filter Exemption Added", ctx.author,
            details={"Type": entity_type, "Entity ID": str(entity_id)},
            level='info'
        )

    # ------------------------------------------------------------------
    # /remove-whitelist-linkfilter  (bot/server owner + 2FA)
    # ------------------------------------------------------------------

    @commands.guild_only()
    @commands.slash_command(
        name="remove-whitelist-linkfilter",
        description="[Owner] Remove link filter immunity from a channel, category, role, or user. Requires 2FA."
    )
    async def remove_whitelist_linkfilter(
        self, ctx: discord.ApplicationContext,
        entity_type: Option(str, "Type to remove exemption from",
                            choices=["channel", "category", "role", "user"], required=True),
        target: Option(str, "ID of the entity to remove from exemptions", required=True),
        code: Option(int, "Your 6-digit 2FA code", required=True)
    ):
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

        try:
            entity_id = int(target.strip().lstrip("<@&#").rstrip(">"))
        except ValueError:
            await ctx.respond("Invalid ID format.", ephemeral=True)
            return

        removed = db_handler.remove_filter_exempt(self.bot.CONN, ctx.guild.id, entity_type, entity_id)
        if not removed:
            await ctx.respond(f"That {entity_type} (ID: {entity_id}) was not exempt.", ephemeral=True)
            return

        await ctx.respond(
            f"Removed exemption for {entity_type} (ID: `{entity_id}`).",
            ephemeral=True
        )
        await logger.log_action(
            self.bot, ctx.guild, "Link Filter Exemption Removed", ctx.author,
            details={"Type": entity_type, "Entity ID": str(entity_id)},
            level='warning'
        )


def setup(bot):
    bot.add_cog(LinkFilter(bot))
