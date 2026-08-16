import re
from urllib.parse import urlparse, unquote


# Compiled patterns

_INVISIBLE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e]")
_LOOKALIKE_DOTS = re.compile(r"[。．｡·•․‧⋅∘°﹒・]")
_LOOKALIKE_SLASHES = re.compile(r"[⁄∕⧸╱／᜵୵]")
_LOOKALIKE_COLONS = re.compile(r"[⁏⁚ː˸：꡼]")
_MD_FORMAT_CHARS = re.compile(r"[*_~`|§]")
_BLOCKQUOTE_PREFIX = re.compile(r"(?m)^>+\s?")

_URL = re.compile(r"(?:https?://|www\.)\S{2,}", re.IGNORECASE)

_BARE_DOMAIN = re.compile(
    r"(?<![a-zA-Z0-9@])(?:"
    r"discord\.gg"
    r"|discord\.com"
    r"|discordapp\.com"
    r"|t\.me"
    r"|telegram\.me"
    r"|bit\.ly"
    r"|tinyurl\.com"
    r"|goo\.gl"
    r"|ow\.ly"
    r"|is\.gd"
    r"|da\.gd"
    r"|rb\.gy"
    r"|cutt\.ly"
    r")/\S*",
    re.IGNORECASE,
)

_NON_HTTP_URL = re.compile(
    r"(?<![a-zA-Z0-9])(?!https?://)([a-zA-Z][a-zA-Z0-9+\-.]{1,20})://\S{2,}",
    re.IGNORECASE,
)

_BAD_PROTOCOLS = {
    "mailto", "javascript", "data", "vbscript",
    "ftp", "ftps", "sftp",
    "discord", "discordapp",
    "sms", "tel", "callto",
    "skype", "steam", "spotify", "tg", "slack",
}

_PROTO_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+\-.]{1,20})\s*:", re.IGNORECASE)
_ANGLE = re.compile(r"<([^>]{3,})>", re.DOTALL)
_MD_URL = re.compile(r"\[[^\]]*\]\(([^)]{2,})\)", re.DOTALL)


# Normalization helpers

def _base_normalize(text: str) -> str:
    """Light normalization: remove invisibles, replace lookalike dots."""
    text = _INVISIBLE.sub("", text)
    text = _LOOKALIKE_DOTS.sub(".", text)
    return text


def _proto_normalize(text: str) -> str:
    """
    Normalize for protocol detection - like _deep_normalize but preserves whitespace.
    This prevents false positives such as 'Check https://' collapsing to 'Checkhttps://'
    which would incorrectly match as a non-http scheme.
    """
    text = _base_normalize(text)
    text = _BLOCKQUOTE_PREFIX.sub(" ", text)
    text = _MD_FORMAT_CHARS.sub("", text)
    text = _LOOKALIKE_SLASHES.sub("/", text)
    text = _LOOKALIKE_COLONS.sub(":", text)
    text = text.replace("\\", "/")
    text = re.sub(r"([a-zA-Z][a-zA-Z0-9+\-.]{0,20}:)/{3,}", r"\1//", text, flags=re.IGNORECASE)
    for _ in range(3):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    return text


def _deep_normalize(text: str) -> str:
    """
    Strip every obfuscation trick before matching: invisibles, lookalike
    dots/slashes/colons, blockquote prefixes, markdown, all whitespace,
    backslashes, repeated slashes, and up to 3 rounds of percent-decoding.
    """
    text = _base_normalize(text)
    text = _BLOCKQUOTE_PREFIX.sub("", text)
    text = _MD_FORMAT_CHARS.sub("", text)
    text = _LOOKALIKE_SLASHES.sub("/", text)
    text = _LOOKALIKE_COLONS.sub(":", text)
    text = re.sub(r"\s+", "", text)
    text = text.replace("\\", "/")
    text = re.sub(r"([a-zA-Z][a-zA-Z0-9+\-.]{0,20}:)/{3,}", r"\1//", text, flags=re.IGNORECASE)
    for _ in range(3):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    return text


# URL extraction + whitelist check

def find_urls(text: str) -> list[str]:
    """Find all URL candidates in already-normalized text."""
    found = list(_URL.findall(text))
    found += [m.group(0) for m in _BARE_DOMAIN.finditer(text)]
    return found


def _normalize_url(url: str) -> str:
    if not url.lower().startswith(("http://", "https://")):
        return "https://" + url
    return url


def _strip_www(host: str) -> str:
    return host[4:] if host.lower().startswith("www.") else host


def is_allowed(url: str, whitelist: list[tuple[str, str]]) -> bool:
    norm = _normalize_url(url)
    try:
        parsed = urlparse(norm)
    except Exception:
        return False

    netloc = parsed.netloc
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    netloc = netloc.split(":")[0]

    for entry_type, entry_url in whitelist:
        entry_norm = _normalize_url(entry_url)
        try:
            entry_parsed = urlparse(entry_norm)
        except Exception as e:
            print(f"[link_scanner] Ignoring malformed whitelist entry {entry_url!r}: {e}")
            continue

        entry_host = _strip_www(entry_parsed.netloc.split(":")[0]).lower()
        incoming_host = _strip_www(netloc).lower()

        if not entry_host:
            continue

        if entry_type == "domain":
            if incoming_host == entry_host or incoming_host.endswith("." + entry_host):
                return True
        elif entry_type == "specific":
            if norm.rstrip("/") == entry_norm.rstrip("/"):
                return True

    return False


def has_bad_protocol(text: str) -> bool:
    """Check for known-bad protocols or any non-http protocol:// in text."""
    if _NON_HTTP_URL.search(text):
        return True
    return any(m.group(1).lower() in _BAD_PROTOCOLS for m in _PROTO_RE.finditer(text))


# Main scanner

def scan(content: str, whitelist: list) -> tuple[bool, str]:
    # Pass 1 - standard URLs on base-normalized text
    basic = _base_normalize(content)
    for url in find_urls(basic):
        if not is_allowed(url, whitelist):
            return True, url

    # Pass 2 - angle bracket contents  <...>
    for inner in _ANGLE.findall(content):
        cleaned = _deep_normalize(inner)
        if has_bad_protocol(cleaned):
            return True, "abnormal protocol in angle brackets"
        for url in find_urls(cleaned):
            if not is_allowed(url, whitelist):
                return True, f"link in angle brackets: {url[:100]}"

    # Pass 3 - markdown link URLs  [text](url)
    for md_url in _MD_URL.findall(content):
        md_url = md_url.strip().strip("<>")
        cleaned = _deep_normalize(md_url)
        if has_bad_protocol(cleaned):
            return True, "abnormal protocol in markdown link"
        for url in find_urls(cleaned):
            if not is_allowed(url, whitelist):
                return True, f"link in markdown: {url[:100]}"

    # Pass 4 - full-message deep scan (catches everything else)
    deep = _deep_normalize(content)
    # Check protocols on space-preserving normalization to avoid false positives
    # from whitespace collapse (e.g. "Check https://" → "Checkhttps://")
    if has_bad_protocol(_proto_normalize(content)):
        return True, "abnormal protocol detected"

    basic_urls = set(find_urls(basic))
    for url in find_urls(deep):
        if url not in basic_urls and not is_allowed(url, whitelist):
            label = (
                "obfuscated link detected (multi-line split)"
                if "\n" in content
                else "obfuscated link detected"
            )
            return True, label

    return False, ""
