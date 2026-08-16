import io
import random
import secrets

from PIL import Image, ImageDraw, ImageFilter, ImageFont

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
    """Try common system fonts, else PIL's bitmap default (ugly but valid - Railway ships none)."""
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

    style = _pick(("add", "add", "sub", "sub", "add_zero"))

    if style == "add":
        answer = 2 + _below(8)             
        left = 1 + _below(answer - 1)       
        right = answer - left
        op = "+"
    elif style == "sub":
        left = 1 + _below(9)                
        right = _below(left + 1)           
        answer = left - right
        op = "-"
    else:
        answer = _below(10)                
        left, right = answer, 0
        op = "+"

    left_s = _WORD_NUMBERS[left] if _below(3) == 0 else str(left)
    right_s = _WORD_NUMBERS[right] if _below(3) == 0 else str(right)

    return f"{left_s} {op} {right_s} = ?", answer


def _apply_noise(img: Image.Image, draw: ImageDraw.ImageDraw, rng: random.Random):
    """Speckles and stray lines - cheap disruption of naive OCR segmentation."""
    w, h = img.size
    for _ in range(w * h // 260):
        draw.point((rng.randrange(w), rng.randrange(h)), fill=_NOISE)
    for _ in range(7):
        draw.line(
            (rng.randrange(w), rng.randrange(h), rng.randrange(w), rng.randrange(h)),
            fill=_NOISE, width=1,
        )


def generate(problem_count: int = DEFAULT_PROBLEM_COUNT) -> tuple[io.BytesIO, str]:

    rng = random.Random(secrets.randbits(64))

    problems = [_make_problem() for _ in range(problem_count)]
    answer = "".join(str(a) for _, a in problems)

    height = _PADDING * 2 + _ROW_HEIGHT * problem_count
    img = Image.new("RGB", (_WIDTH, height), _BG)
    draw = ImageDraw.Draw(img)
    font = _load_font(30)

    for idx, (text, _) in enumerate(problems):
        y = _PADDING + idx * _ROW_HEIGHT
        x = _PADDING + rng.randint(0, 26)
        y += rng.randint(-4, 4)
        draw.text((x, y), f"{idx + 1}.  {text}", font=font, fill=_FG)

    _apply_noise(img, draw, rng)
    img = img.filter(ImageFilter.GaussianBlur(radius=0.6))

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    return buffer, answer
