"""
Captcha generation — pure logic, no Discord dependencies, so it can be tested
on its own.

DESIGN NOTE
-----------
The challenge is rendered ONLY into the image. The accompanying message never
contains the problems in text.

That distinction is the entire point. A verification bot that prints
"1. 7 - 7 = ?  2. 4 + two = ?" into the message body is trivially defeated by a
script that reads message content and does the arithmetic — the image is then
decoration, not a test. Forcing the answer to come out of pixels means an
attacker needs OCR, which is a materially higher bar.

The captcha is still only one signal. cogs/verification.py layers it with
account-age, response-timing, and attempt limits, because most raid traffic is
throwaway accounts rather than clever solvers.
"""

import io
import random
import secrets

from PIL import Image, ImageDraw, ImageFilter, ImageFont


# Each problem resolves to a single digit 0-9, so N problems produce an N-digit
# answer string that maps cleanly onto a numeric keypad.
DEFAULT_PROBLEM_COUNT = 6

_WORD_NUMBERS = {
    0: "zero", 1: "one", 2: "two", 3: "three", 4: "four",
    5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine",
}

_WIDTH = 460
_ROW_HEIGHT = 46
_PADDING = 22

_BG = (30, 33, 36)
_FG = (235, 237, 240)
_NOISE = (110, 116, 124)


def _load_font(size: int):
    """
    Try a few common system fonts, falling back to PIL's bitmap default.

    The default font is small and fixed-size, which makes for an uglier but
    still perfectly valid challenge — worth degrading rather than crashing on
    a host with no fonts installed (Railway containers are minimal).
    """
    for name in ("DejaVuSans-Bold.ttf", "arialbd.ttf", "Arial_Bold.ttf",
                 "DejaVuSans.ttf", "arial.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def _below(n: int) -> int:
    """Cryptographically secure randbelow, used for anything answer-determining."""
    return secrets.randbelow(n)


def _pick(seq):
    return seq[_below(len(seq))]


def _make_problem() -> tuple[str, int]:
    """
    Build one arithmetic problem whose answer is a single digit 0-9.

    Uses `secrets` rather than `random`: the answer is the thing an attacker
    would want to predict, so it must not come from a seedable PRNG whose
    state could in principle be reconstructed from observed output.

    Mixes digits and spelled-out numbers ("4 + two") so a naive solver cannot
    just regex out the numerals.
    """
    style = _pick(("add", "add", "sub", "sub", "add_zero"))

    if style == "add":
        answer = 2 + _below(8)              # 2..9
        left = 1 + _below(answer - 1)       # 1..answer-1
        right = answer - left
        op = "+"
    elif style == "sub":
        left = 1 + _below(9)                # 1..9
        right = _below(left + 1)            # 0..left
        answer = left - right
        op = "-"
    else:
        answer = _below(10)                 # 0..9
        left, right = answer, 0
        op = "+"

    # Spell out roughly one operand in three
    left_s = _WORD_NUMBERS[left] if _below(3) == 0 else str(left)
    right_s = _WORD_NUMBERS[right] if _below(3) == 0 else str(right)

    return f"{left_s} {op} {right_s} = ?", answer


def _apply_noise(img: Image.Image, draw: ImageDraw.ImageDraw, rng: random.Random):
    """Speckles and stray lines — cheap disruption of naive OCR segmentation."""
    w, h = img.size
    for _ in range(w * h // 260):
        draw.point((rng.randrange(w), rng.randrange(h)), fill=_NOISE)
    for _ in range(7):
        draw.line(
            (rng.randrange(w), rng.randrange(h), rng.randrange(w), rng.randrange(h)),
            fill=_NOISE, width=1,
        )


def generate(problem_count: int = DEFAULT_PROBLEM_COUNT) -> tuple[io.BytesIO, str]:
    """
    Render a captcha image and return (png_buffer, answer_string).

    answer_string is the concatenated digits in order, e.g. "140891".
    Seeded from `secrets` so challenges are not predictable from timing.
    """
    # Cosmetic-only PRNG: glyph jitter and pixel noise. The answers come from
    # `secrets` in _make_problem, so nothing security-relevant depends on this.
    rng = random.Random(secrets.randbits(64))  # noqa: S311  # nosec B311

    problems = [_make_problem() for _ in range(problem_count)]
    answer = "".join(str(a) for _, a in problems)

    height = _PADDING * 2 + _ROW_HEIGHT * problem_count
    img = Image.new("RGB", (_WIDTH, height), _BG)
    draw = ImageDraw.Draw(img)
    font = _load_font(30)

    for idx, (text, _) in enumerate(problems):
        y = _PADDING + idx * _ROW_HEIGHT
        # Jitter each row so the glyph grid is not uniform
        x = _PADDING + rng.randint(0, 26)
        y += rng.randint(-4, 4)
        draw.text((x, y), f"{idx + 1}.  {text}", font=font, fill=_FG)

    _apply_noise(img, draw, rng)
    # Slight blur softens glyph edges without hurting human legibility
    img = img.filter(ImageFilter.GaussianBlur(radius=0.6))

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    return buffer, answer
