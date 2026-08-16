import discord
from datetime import datetime, timezone, timedelta
import db_handler


_COLORS = {
    'info':     0x3498db,  # Blue
    'success':  0x2ecc71,  # Green
    'warning':  0xf39c12,  # Orange
    'error':    0xe74c3c,  # Red
    'critical': 0x8b0000,  # Dark red
}


# Timestamp helpers

def fmt_timestamp(dt: datetime = None) -> str:
    if dt is None:
        dt = datetime.now(timezone.utc)
    return f"<t:{int(dt.timestamp())}:F>"


def fmt_timestamp_offset(seconds: int) -> str:
    """Return a Discord timestamp tag for now + `seconds` in the future."""
    return fmt_timestamp(datetime.now(timezone.utc) + timedelta(seconds=seconds))


# Helpers

async def safe_send(channel, **kwargs):
    """Send a message, silently ignoring permission errors."""
    if channel is None:
        return
    try:
        await channel.send(**kwargs)
    except (discord.Forbidden, discord.HTTPException):
        pass


def get_log_channel(bot, guild):
    """Return the configured log channel object, or None."""
    if isinstance(guild, int):
        guild_id = guild
    else:
        guild_id = guild.id
    log_id = db_handler.get_log_channel(bot.CONN, guild_id)
    return bot.get_channel(log_id) if log_id else None


async def log_action(
    bot,
    guild: discord.Guild,
    title: str,
    actor: discord.Member | discord.User,
    details: dict = None,
    level: str = 'info',
    channel=None,
):
    log_ch = channel or get_log_channel(bot, guild)
    if not log_ch:
        return

    now = datetime.now(timezone.utc)
    color = _COLORS.get(level, _COLORS['info'])
    embed = discord.Embed(title=title, color=color, timestamp=now)

    avatar = actor.display_avatar.url if actor.display_avatar else None
    embed.set_author(name=str(actor), icon_url=avatar)

    if details:
        for name, value in details.items():
            embed.add_field(name=name, value=str(value)[:1024], inline=True)

    # Time field renders in each viewer's local timezone
    embed.add_field(name="Time", value=fmt_timestamp(now), inline=True)
    embed.set_footer(text=f"Actor ID: {actor.id} | {guild.name}")
    await safe_send(log_ch, embed=embed)


async def log_link_deleted(bot, guild: discord.Guild, author, channel, blocked_url: str, content: str, edited: bool = False):
    """Specialized log for link filter deletions - shows full message context."""
    log_ch = get_log_channel(bot, guild)
    if not log_ch:
        return

    now = datetime.now(timezone.utc)
    action = "Message Edited — Link Removed" if edited else "Message Deleted — Link Blocked"
    embed = discord.Embed(title=action, color=_COLORS['warning'], timestamp=now)
    embed.set_author(name=str(author), icon_url=author.display_avatar.url if author.display_avatar else None)
    embed.add_field(name="Channel", value=channel.mention, inline=True)
    embed.add_field(name="Author", value=f"{author.mention} ({author.id})", inline=True)
    embed.add_field(name="Blocked URL", value=f"`{blocked_url[:300]}`", inline=False)

    display_content = content[:800]
    if len(content) > 800:
        display_content += f"\n… ({len(content) - 800} chars truncated)"
    embed.add_field(name="Message Content", value=f"```{display_content}```", inline=False)
    embed.add_field(name="Time", value=fmt_timestamp(now), inline=True)
    embed.set_footer(text=f"Guild: {guild.name}")
    await safe_send(log_ch, embed=embed)
