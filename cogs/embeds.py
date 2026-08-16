# Embeds - build and manage rich Discord embeds sent as the bot.

import discord
from discord.ext import commands
from discord.commands import Option
from discord.enums import ChannelType
import db_handler
import two_factor_helper
import permissions
import logger

BRAND_COLOR = 0x5865F2  # Default brand color (Discord blurple) - change to match your server's branding


# Helpers

def _parse_color(value: str) -> int:
    """Parse a hex color string (#rrggbb or rrggbb) to int. Falls back to BRAND_COLOR."""
    cleaned = value.strip().lstrip('#')
    try:
        parsed = int(cleaned, 16)
        if 0 <= parsed <= 0xFFFFFF:
            return parsed
    except (ValueError, AttributeError):
        pass
    return BRAND_COLOR


def _build_discord_embed(title, description, color, footer, image_url) -> discord.Embed:
    embed = discord.Embed(
        title=title or None,
        description=description,
        color=color,
        timestamp=discord.utils.utcnow(),
    )
    if footer:
        embed.set_footer(text=footer)
    if image_url:
        embed.set_image(url=image_url)
    return embed


# Modal: build or pre-filled edit

class EmbedBuilderModal(discord.ui.Modal):
    def __init__(self, bot, channel, guild, prefill: dict = None, edit_message=None):
        super().__init__(title="Build Your Embed")
        self.bot = bot
        self.channel = channel
        self.guild = guild
        self.edit_message = edit_message  # discord.Message when editing, else None

        p = prefill or {}
        is_forum = isinstance(channel, discord.ForumChannel)

        self.add_item(discord.ui.InputText(
            label="Post Title (becomes the forum thread name)" if is_forum else "Title",
            placeholder="e.g. Server announcement title" if is_forum else "Embed title (optional)",
            required=is_forum,
            max_length=100 if is_forum else 256,
            value=p.get('title') or None,
        ))
        self.add_item(discord.ui.InputText(
            label="Description",
            style=discord.InputTextStyle.paragraph,
            placeholder="Main body text…",
            required=True,
            max_length=4000,
            value=p.get('description') or None,
        ))
        self.add_item(discord.ui.InputText(
            label="Color hex (clear to use default color)",
            placeholder="#5865f2",
            required=False,
            max_length=7,
            value=p.get('color') or '#5865f2',
        ))
        self.add_item(discord.ui.InputText(
            label="Footer",
            placeholder="Footer text (optional)",
            required=False,
            max_length=2048,
            value=p.get('footer') or None,
        ))
        self.add_item(discord.ui.InputText(
            label="Image URL (type 'none' to skip)",
            placeholder="https://… (large image at bottom)",
            required=False,
            max_length=500,
            value=p.get('image_url') or 'none',
        ))

    async def callback(self, interaction: discord.Interaction):
        title       = self.children[0].value.strip() or None
        description = self.children[1].value.strip()
        color_raw   = self.children[2].value.strip()
        footer      = self.children[3].value.strip() or None
        image_raw   = self.children[4].value.strip().lower()
        image_url   = None if image_raw in ('', 'none', 'n/a', 'skip') else self.children[4].value.strip()

        color = _parse_color(color_raw) if color_raw else BRAND_COLOR
        embed = _build_discord_embed(title, description, color, footer, image_url)

        embed_data = dict(
            title=title, description=description, color=color,
            footer=footer, image_url=image_url,
        )

        if self.edit_message:
            preview_note = "**Preview** — review your changes then click **Update**."
        elif isinstance(self.channel, discord.ForumChannel):
            preview_note = (
                "**Preview** — this is how your forum post will look. "
                f"Click **Post** to create a new thread in {self.channel.mention}."
            )
        else:
            preview_note = (
                "**Preview** — this is how your embed will look. "
                f"Click **Send** to post it to {self.channel.mention}."
            )

        view = EmbedConfirmView(
            bot=self.bot,
            embed=embed,
            channel=self.channel,
            guild=self.guild,
            author=interaction.user,
            embed_data=embed_data,
            edit_message=self.edit_message,
        )
        await interaction.response.send_message(
            preview_note, embed=embed, view=view, ephemeral=True,
        )


# View: Send / Update / Cancel

class EmbedConfirmView(discord.ui.View):
    def __init__(self, bot, embed, channel, guild, author, embed_data, edit_message=None):
        super().__init__(timeout=120)
        self.bot          = bot
        self.embed        = embed
        self.channel      = channel
        self.guild        = guild
        self.author       = author
        self.embed_data   = embed_data
        self.edit_message = edit_message

        is_edit = edit_message is not None
        is_forum = isinstance(channel, discord.ForumChannel)
        btn_label = "Update" if is_edit else ("Post" if is_forum else "Send")
        btn_emoji = "✏️" if is_edit else ("📌" if is_forum else "📤")
        self.confirm_btn = discord.ui.Button(
            label=btn_label,
            style=discord.ButtonStyle.primary if is_edit else discord.ButtonStyle.success,
            emoji=btn_emoji,
        )
        self.confirm_btn.callback = self._on_confirm

        self.superseded = False
        self.edit_btn = discord.ui.Button(
            label="Edit",
            style=discord.ButtonStyle.secondary,
            emoji="📝",
        )
        self.edit_btn.callback = self._on_edit

        self.cancel_btn = discord.ui.Button(
            label="Cancel",
            style=discord.ButtonStyle.danger,
            emoji="✖",
        )
        self.cancel_btn.callback = self._on_cancel

        self.add_item(self.confirm_btn)
        self.add_item(self.edit_btn)
        self.add_item(self.cancel_btn)

    async def _on_edit(self, interaction: discord.Interaction):
        if interaction.user.id != self.author.id:
            await interaction.response.send_message(
                "This preview belongs to someone else.", ephemeral=True
            )
            return

        ed = self.embed_data
        # embed_data holds the colour as an int; the modal field wants hex text.
        prefill = {
            'title':       ed['title'],
            'description': ed['description'],
            'color':       f"#{ed['color']:06x}",
            'footer':      ed['footer'],
            'image_url':   ed['image_url'],
        }

        self.superseded = True
        await interaction.response.send_modal(EmbedBuilderModal(
            self.bot, self.channel, self.guild,
            prefill=prefill, edit_message=self.edit_message,
        ))

    async def _on_confirm(self, interaction: discord.Interaction):
        if interaction.user.id != self.author.id:
            await interaction.response.send_message(
                "This preview belongs to someone else.", ephemeral=True
            )
            return

        if self.superseded:
            await interaction.response.edit_message(
                content="You edited this after previewing it - use the newer preview below.",
                embed=None, view=None,
            )
            return

        ed = self.embed_data

        if self.edit_message:
            try:
                await self.edit_message.edit(embed=self.embed)
            except (discord.Forbidden, discord.HTTPException) as exc:
                await interaction.response.edit_message(
                    content=f"Failed to update the message: {exc}", embed=None, view=None
                )
                return

            db_handler.update_embed(
                self.bot.CONN, self.edit_message.id,
                ed['title'], ed['description'], ed['color'], ed['footer'], ed['image_url'],
            )
            await interaction.response.edit_message(
                content=f"Embed updated in {self.channel.mention}.", embed=None, view=None
            )
            await logger.log_action(
                self.bot, self.guild, "Embed Updated", self.author,
                details={
                    "Channel":    self.channel.mention,
                    "Message ID": str(self.edit_message.id),
                    "Title":      ed['title'] or "(none)",
                },
                level='info',
            )
        else:
            try:
                if isinstance(self.channel, discord.ForumChannel):
                    thread = await self.channel.create_thread(
                        name=ed['title'],
                        embed=self.embed,
                    )
                    stored_id = thread.id
                    location = f"new thread in {self.channel.mention}"
                else:
                    msg = await self.channel.send(embed=self.embed)
                    stored_id = msg.id
                    location = self.channel.mention
            except (discord.Forbidden, discord.HTTPException) as exc:
                await interaction.response.edit_message(
                    content=f"Failed to send: {exc}", embed=None, view=None
                )
                return

            db_handler.insert_embed(
                self.bot.CONN, self.guild.id, self.channel.id, stored_id, self.author.id,
                ed['title'], ed['description'], ed['color'], ed['footer'], ed['image_url'],
            )
            await interaction.response.edit_message(
                content=f"Embed posted to {location}.", embed=None, view=None
            )
            await logger.log_action(
                self.bot, self.guild,
                "Forum Post Created" if isinstance(self.channel, discord.ForumChannel) else "Embed Sent",
                self.author,
                details={
                    "Channel":    self.channel.mention,
                    "Message ID": str(stored_id),
                    "Title":      ed['title'] or "(none)",
                },
                level='success',
            )

        self.stop()

    async def _on_cancel(self, interaction: discord.Interaction):
        if interaction.user.id != self.author.id:
            await interaction.response.send_message(
                "This preview belongs to someone else.", ephemeral=True
            )
            return
        await interaction.response.edit_message(content="Cancelled.", embed=None, view=None)
        self.stop()


# Cog

class Embeds(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    embed = discord.SlashCommandGroup(
        "embed",
        "Build and manage bot embeds",
    )

    # /embed send

    @embed.command(
        name="send",
        description="Build and send an embed to an announcement channel. Announcers/owners. Requires 2FA.",
    )
    @commands.cooldown(1, 10, commands.BucketType.user)
    async def embed_send(
        self,
        ctx: discord.ApplicationContext,
        channel: Option(
            discord.abc.GuildChannel,
            "Channel to post in",
            required=True,
            channel_types=[ChannelType.text, ChannelType.news, ChannelType.forum],
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

        configured = db_handler.get_channels(self.bot.CONN, ctx.guild.id)
        if channel.id not in configured:
            await ctx.respond(
                f"{channel.mention} is not an announcement channel. "
                "Add it with `/add-channel` first.",
                ephemeral=True,
            )
            return

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        await ctx.send_modal(
            EmbedBuilderModal(bot=self.bot, channel=channel, guild=ctx.guild)
        )

    # /embed edit

    @embed.command(
        name="edit",
        description="Edit a previously sent bot embed. Requires 2FA.",
    )
    @commands.cooldown(1, 5, commands.BucketType.user)
    async def embed_edit(
        self,
        ctx: discord.ApplicationContext,
        message_id: Option(str, "Message ID of the embed to edit", required=True),
        channel: Option(
            discord.abc.GuildChannel,
            "Channel that contains the embed",
            required=True,
            channel_types=[ChannelType.text, ChannelType.news, ChannelType.forum],
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

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        try:
            mid = int(message_id)
        except ValueError:
            await ctx.respond("Invalid message ID — must be a number.", ephemeral=True)
            return

        record = db_handler.get_embed(self.bot.CONN, ctx.guild.id, mid)
        if not record:
            await ctx.respond(
                "No tracked embed found with that ID in this server. "
                "Use `/embed list` to see available embeds.",
                ephemeral=True,
            )
            return

        try:
            if isinstance(channel, discord.ForumChannel):
                # For forum posts, mid is the thread ID; starter message has the same ID
                thread = await ctx.guild.fetch_channel(mid)
                msg = await thread.fetch_message(mid)
            else:
                msg = await channel.fetch_message(mid)
        except discord.NotFound:
            await ctx.respond(
                "That message no longer exists in Discord. "
                "It may have been manually deleted.",
                ephemeral=True,
            )
            return
        except (discord.Forbidden, discord.HTTPException):
            await ctx.respond(
                "Could not fetch that message — I may lack access to that channel.",
                ephemeral=True,
            )
            return

        # Pre-fill modal from stored record
        prefill = {
            'title':     record['title'] or '',
            'description': record['description'] or '',
            'color':     f"#{record['color']:06x}" if record['color'] else '',
            'footer':    record['footer'] or '',
            'image_url': record['image_url'] or '',
        }

        await ctx.send_modal(
            EmbedBuilderModal(
                bot=self.bot, channel=channel, guild=ctx.guild,
                prefill=prefill, edit_message=msg,
            )
        )

    # /embed delete

    @embed.command(
        name="delete",
        description="Delete a bot-sent embed and remove its record. Requires 2FA.",
    )
    @commands.cooldown(1, 5, commands.BucketType.user)
    async def embed_delete(
        self,
        ctx: discord.ApplicationContext,
        message_id: Option(str, "Message ID of the embed to delete", required=True),
        channel: Option(
            discord.abc.GuildChannel,
            "Channel that contains the embed",
            required=True,
            channel_types=[ChannelType.text, ChannelType.news, ChannelType.forum],
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

        if not two_factor_helper.verify_code(self.bot.CONN, ctx.author.id, code):
            await ctx.respond("Incorrect 2FA code.", ephemeral=True)
            return

        try:
            mid = int(message_id)
        except ValueError:
            await ctx.respond("Invalid message ID — must be a number.", ephemeral=True)
            return

        record = db_handler.get_embed(self.bot.CONN, ctx.guild.id, mid)
        if not record:
            await ctx.respond(
                "No tracked embed found with that ID in this server.",
                ephemeral=True,
            )
            return

        try:
            if isinstance(channel, discord.ForumChannel):
                # For forum posts, mid is the thread ID - delete the whole thread
                thread = await ctx.guild.fetch_channel(mid)
                await thread.delete()
            else:
                msg = await channel.fetch_message(mid)
                await msg.delete()
        except discord.NotFound:
            pass  # Already gone from Discord - still clean up DB
        except (discord.Forbidden, discord.HTTPException) as exc:
            await ctx.respond(f"Failed to delete: {exc}", ephemeral=True)
            return

        db_handler.delete_embed(self.bot.CONN, mid)
        await ctx.respond(
            f"Embed `{mid}` deleted from {channel.mention}.",
            ephemeral=True,
        )
        await logger.log_action(
            self.bot, ctx.guild, "Embed Deleted", ctx.author,
            details={
                "Channel":    channel.mention,
                "Message ID": str(mid),
                "Title":      record.get('title') or "(none)",
            },
            level='warning',
        )

    # /embed list

    @embed.command(
        name="list",
        description="List the 10 most recent bot-sent embeds in this server.",
    )
    async def embed_list(
        self,
        ctx: discord.ApplicationContext,
        channel: Option(
            discord.abc.GuildChannel,
            "Filter to a specific channel (optional)",
            required=False,
            channel_types=[ChannelType.text, ChannelType.news],
        ),
    ):
        allowed, err = permissions.check(self.bot, ctx, 'any_registered')
        if not allowed:
            await ctx.respond(err, ephemeral=True)
            return

        ok, err2 = permissions.guild_required(self.bot, ctx)
        if not ok:
            await ctx.respond(err2, ephemeral=True)
            return

        records = db_handler.get_recent_embeds(
            self.bot.CONN, ctx.guild.id,
            channel_id=channel.id if channel else None,
            limit=10,
        )

        if not records:
            scope = f"in {channel.mention}" if channel else "in this server"
            await ctx.respond(f"No bot embeds found {scope}.", ephemeral=True)
            return

        scope_title = f"#{channel.name}" if channel else ctx.guild.name
        list_embed = discord.Embed(
            title=f"Recent Bot Embeds — {scope_title}",
            color=BRAND_COLOR,
            timestamp=discord.utils.utcnow(),
        )
        list_embed.set_footer(text="Use the Message ID with /embed edit or /embed delete")

        for r in records:
            ch_obj = self.bot.get_channel(r['channel_id'])
            ch_display = ch_obj.mention if ch_obj else f"<#{r['channel_id']}>"
            title_display = r['title'] or "*(no title)*"
            sent_ts = f"<t:{r['created_ts']}:R>" if r['created_ts'] else "unknown"
            list_embed.add_field(
                name=f"`{r['message_id']}`",
                value=f"**{title_display}**\n{ch_display} • {sent_ts}",
                inline=False,
            )

        await ctx.respond(embed=list_embed, ephemeral=True)


def setup(bot):
    bot.add_cog(Embeds(bot))
