"""
Tests for link_scanner.py

Covers all 5 detection passes and every documented evasion technique:
  Pass 1 - Standard URLs on base-normalized text
  Pass 2 - Angle bracket content
  Pass 3 - Markdown link URLs
  Pass 4 - Full-message deep scan (obfuscation, split lines, encoding)
  Pass 5 - Non-http protocol:// detection

Evasion techniques:
  - Split URLs across newlines / blockquote lines
  - Markdown formatting injected into URL
  - Extra/mixed slashes and backslashes
  - Percent-encoded (single and double) domains
  - Unicode lookalike dots, slashes, colons
  - Zero-width / invisible characters
  - Alternative and mixed-case protocols
  - @-prefixed URLs
  - Angle-bracket wrapped links
  - Markdown hyperlinks
  - Bare known-risky domains (discord.gg, t.me, bit.ly, etc.)
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from link_scanner import scan, find_urls, is_allowed, has_bad_protocol, _base_normalize, _deep_normalize


# Whitelist helper - a small set of allowed entries for "clean" message tests
_ALLOW_EXAMPLE = [("domain", "example.com"), ("specific", "https://allowed.org/page")]
_EMPTY_WL = []


# Utility: clean messages must not be flagged

class TestCleanMessages:
    def test_plain_text_allowed(self):
        blocked, _ = scan("Hello world, no links here.", _EMPTY_WL)
        assert blocked is False

    def test_whitelisted_domain_allowed(self):
        blocked, _ = scan("Check https://example.com/path for details.", _ALLOW_EXAMPLE)
        assert blocked is False

    def test_whitelisted_subdomain_allowed(self):
        blocked, _ = scan("Visit https://sub.example.com", _ALLOW_EXAMPLE)
        assert blocked is False

    def test_whitelisted_specific_url_allowed(self):
        blocked, _ = scan("See https://allowed.org/page", _ALLOW_EXAMPLE)
        assert blocked is False

    def test_empty_string(self):
        blocked, _ = scan("", _EMPTY_WL)
        assert blocked is False


# Pass 1 - Standard URL detection

class TestPass1StandardURLs:
    def test_http_url_blocked(self):
        blocked, label = scan("Go to http://evil.com now", _EMPTY_WL)
        assert blocked is True

    def test_https_url_blocked(self):
        blocked, label = scan("Go to https://evil.com now", _EMPTY_WL)
        assert blocked is True

    def test_www_url_blocked(self):
        blocked, label = scan("Visit www.evil.com right now", _EMPTY_WL)
        assert blocked is True

    def test_bare_discord_gg_blocked(self):
        blocked, label = scan("Join discord.gg/someinvite", _EMPTY_WL)
        assert blocked is True

    def test_bare_t_me_blocked(self):
        blocked, label = scan("Join t.me/somechannel", _EMPTY_WL)
        assert blocked is True

    def test_bare_bit_ly_blocked(self):
        blocked, label = scan("Visit bit.ly/shortlink", _EMPTY_WL)
        assert blocked is True

    def test_bare_tinyurl_blocked(self):
        blocked, label = scan("See tinyurl.com/abc123", _EMPTY_WL)
        assert blocked is True

    def test_at_prefixed_url_blocked(self):
        """https://@evil.com is a URL with empty username - still a URL."""
        blocked, _ = scan("link https://@evil.com/page", _EMPTY_WL)
        assert blocked is True

    def test_unicode_invisible_around_url(self):
        """Zero-width character inside URL shouldn't hide it from pass 1."""
        url = "https://evil\u200b.com/page"
        blocked, _ = scan(url, _EMPTY_WL)
        assert blocked is True

    def test_lookalike_dot_in_www(self):
        """Unicode full-stop lookalike should be normalized to '.'"""
        url = "www\u3002evil\u3002com/path"
        blocked, _ = scan(url, _EMPTY_WL)
        assert blocked is True


# Pass 2 - Angle bracket content

class TestPass2AngleBrackets:
    def test_plain_url_in_angle_brackets(self):
        blocked, label = scan("<https://evil.com>", _EMPTY_WL)
        assert blocked is True

    def test_bad_proto_in_angle_brackets(self):
        blocked, label = scan("<javascript:alert(1)>", _EMPTY_WL)
        assert blocked is True
        assert "angle" in label

    def test_discord_proto_in_angle_brackets(self):
        blocked, label = scan("<discord://evil.server/channel>", _EMPTY_WL)
        assert blocked is True

    def test_clean_angle_bracket_text(self):
        """<role mentions> and <#channel> are clean."""
        blocked, _ = scan("<@123456789> mentioned <#987654321>", _EMPTY_WL)
        assert blocked is False


# Pass 3 - Markdown link URLs

class TestPass3MarkdownLinks:
    def test_markdown_link_blocked(self):
        blocked, label = scan("[Click here](https://evil.com)", _EMPTY_WL)
        assert blocked is True

    def test_markdown_link_bad_proto(self):
        blocked, label = scan("[Click](javascript:void(0))", _EMPTY_WL)
        assert blocked is True

    def test_markdown_link_whitelisted(self):
        blocked, _ = scan("[Visit](https://example.com/page)", _ALLOW_EXAMPLE)
        assert blocked is False

    def test_markdown_link_with_angle_brackets_in_url(self):
        """[text](<url>) - Discord strips <> in markdown."""
        blocked, label = scan("[link](<https://evil.com>)", _EMPTY_WL)
        assert blocked is True


# Pass 4 - Deep scan / obfuscation bypass

class TestPass4DeepScan:
    def test_split_url_across_newlines(self):
        """ht\ntp://evil.com should be caught after whitespace collapse."""
        content = "ht\ntp://evil.com"
        blocked, label = scan(content, _EMPTY_WL)
        assert blocked is True

    def test_split_url_blockquote_lines(self):
        """> ht\n> tp\n> ://evil.com - Discord blockquote multi-line."""
        content = "> ht\n> tp\n> ://evil.com"
        blocked, label = scan(content, _EMPTY_WL)
        assert blocked is True

    def test_markdown_asterisks_in_url(self):
        """https*://*evil.com - asterisks injected in URL."""
        content = "https*://*evil.com"
        blocked, _ = scan(content, _EMPTY_WL)
        assert blocked is True

    def test_bold_markdown_split_url(self):
        """**https://**evil.com - bold wrapping scheme."""
        content = "**https://**evil.com"
        blocked, _ = scan(content, _EMPTY_WL)
        assert blocked is True

    def test_extra_slashes_in_url(self):
        """https:////\\\\evil.com - excess slashes collapsed."""
        content = "https:////\\\\evil.com"
        blocked, _ = scan(content, _EMPTY_WL)
        assert blocked is True

    def test_percent_encoded_domain(self):
        """%68%74%74%70%73://evil.com - single percent-encoded scheme."""
        # https:// in percent encoding
        content = "%68%74%74%70%73://%65%76%69%6c.%63%6f%6d"
        blocked, _ = scan(content, _EMPTY_WL)
        assert blocked is True

    def test_double_percent_encoded_domain(self):
        """%2568%2574%2574%2570%2573:// - double-encoded."""
        # Double-encode 'h' → %25 + '68' = '%2568'
        content = "%2568%2574%2574%2570%2573://%2565%2576%2569%256c.%2563%256f%256d"
        blocked, _ = scan(content, _EMPTY_WL)
        assert blocked is True

    def test_unicode_lookalike_slashes(self):
        """⁄ and ∕ are lookalike slashes - should normalize to /."""
        content = "https:⁄⁄evil.com⁄path"
        blocked, _ = scan(content, _EMPTY_WL)
        assert blocked is True

    def test_unicode_lookalike_colons(self):
        """： (fullwidth colon) should normalize to :"""
        content = "https：//evil.com"
        blocked, _ = scan(content, _EMPTY_WL)
        assert blocked is True

    def test_zero_width_chars_in_url(self):
        """Zero-width chars scattered through URL."""
        content = "https://e\u200bv\u200cil\u200d.com/p\u2060a\ufeffge"
        blocked, _ = scan(content, _EMPTY_WL)
        assert blocked is True

    def test_backslashes_as_slashes(self):
        """https:\\\\evil.com - backslashes treated as forward slashes."""
        content = "https:\\\\evil.com"
        blocked, _ = scan(content, _EMPTY_WL)
        assert blocked is True


# Pass 5 - Non-http protocol detection

class TestPass5NonHttpProtocols:
    def test_ftp_protocol_blocked(self):
        blocked, label = scan("ftp://files.evil.com/payload", _EMPTY_WL)
        assert blocked is True

    def test_mailto_protocol_blocked(self):
        blocked, label = scan("mailto:user@evil.com", _EMPTY_WL)
        assert blocked is True

    def test_javascript_protocol_blocked(self):
        blocked, label = scan("javascript:alert('xss')", _EMPTY_WL)
        assert blocked is True

    def test_discord_protocol_blocked(self):
        blocked, label = scan("discord://discord.com/channels/123", _EMPTY_WL)
        assert blocked is True

    def test_telegram_tg_protocol_blocked(self):
        blocked, label = scan("tg://resolve?domain=something", _EMPTY_WL)
        assert blocked is True

    def test_mixed_case_protocol_blocked(self):
        """dIsCoRd:// - mixed case must still be caught."""
        blocked, _ = scan("dIsCoRd://evil.server", _EMPTY_WL)
        assert blocked is True

    def test_mailto_mixed_case(self):
        blocked, _ = scan("mAiLtO:user@evil.com", _EMPTY_WL)
        assert blocked is True


# is_allowed - whitelist matching

class TestIsAllowed:
    def test_domain_exact_match(self):
        wl = [("domain", "example.com")]
        assert is_allowed("https://example.com", wl) is True

    def test_domain_subdomain_match(self):
        wl = [("domain", "example.com")]
        assert is_allowed("https://sub.example.com/path", wl) is True

    def test_domain_www_stripped(self):
        wl = [("domain", "example.com")]
        assert is_allowed("https://www.example.com", wl) is True

    def test_domain_does_not_match_different_tld(self):
        wl = [("domain", "example.com")]
        assert is_allowed("https://example.org", wl) is False

    def test_specific_exact_match(self):
        wl = [("specific", "https://example.com/page")]
        assert is_allowed("https://example.com/page", wl) is True

    def test_specific_trailing_slash_ignored(self):
        wl = [("specific", "https://example.com/page/")]
        assert is_allowed("https://example.com/page", wl) is True

    def test_specific_no_match_different_path(self):
        wl = [("specific", "https://example.com/page")]
        assert is_allowed("https://example.com/other", wl) is False

    def test_empty_whitelist_blocks_all(self):
        assert is_allowed("https://example.com", []) is False

    def test_url_without_scheme_normalized(self):
        wl = [("domain", "example.com")]
        assert is_allowed("example.com/path", wl) is True

    def test_at_user_in_url_netloc_stripped(self):
        """https://user@example.com - the @user should be stripped from netloc."""
        wl = [("domain", "example.com")]
        assert is_allowed("https://user@example.com/path", wl) is True


# has_bad_protocol

class TestHasBadProtocol:
    def test_javascript(self):
        assert has_bad_protocol("javascript:alert(1)") is True

    def test_mailto(self):
        assert has_bad_protocol("mailto:x@y.com") is True

    def test_ftp(self):
        assert has_bad_protocol("ftp://files.x.com") is True

    def test_discord_proto(self):
        assert has_bad_protocol("discord://x.com") is True

    def test_http_is_not_bad(self):
        assert has_bad_protocol("https://example.com") is False

    def test_non_http_generic_scheme(self):
        """Any non-http scheme:// triggers _NON_HTTP_URL."""
        assert has_bad_protocol("steam://rungame/123") is True


# _deep_normalize - unit tests for normalization helpers

class TestDeepNormalize:
    def test_strips_invisible_chars(self):
        result = _deep_normalize("he\u200bllo")
        assert "\u200b" not in result

    def test_blockquote_prefix_removed(self):
        result = _deep_normalize("> line1\n> line2")
        assert ">" not in result

    def test_markdown_chars_stripped(self):
        result = _deep_normalize("**bold** _italic_")
        assert "*" not in result
        assert "_" not in result

    def test_lookalike_slash_normalized(self):
        result = _deep_normalize("https:⁄⁄x.com")
        assert "⁄" not in result
        assert "https://x.com" == result

    def test_lookalike_colon_normalized(self):
        result = _deep_normalize("https：//x.com")
        assert "：" not in result

    def test_whitespace_collapsed(self):
        result = _deep_normalize("a b\tc\nd")
        assert " " not in result
        assert "\t" not in result
        assert "\n" not in result

    def test_percent_decoded(self):
        result = _deep_normalize("%68%65%6c%6c%6f")
        assert result == "hello"

    def test_double_percent_decoded(self):
        """Double-encoded: %2568 → %68 → h"""
        result = _deep_normalize("%2568")
        assert result == "h"

    def test_excess_slashes_collapsed(self):
        result = _deep_normalize("https:////x.com")
        assert result == "https://x.com"
