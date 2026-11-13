"""Render docs/assets/social-preview.png (1280x640), the image for the repository's social preview.

    python scripts/render_social_preview.py              render the PNG with headless Chromium (Playwright)
    python scripts/render_social_preview.py --html F     only write the HTML card to F (render it any other way)

The subtitle is the `description` in pyproject.toml, so the card says what the package metadata says. The command
and exit line are the real last lines of `scripts/demo.sh`. Rendering needs Node.js with the `playwright` package
and its Chromium (`npm install playwright && npx playwright install chromium`), and the fonts Inter and DejaVu Sans
Mono; other fonts change the look but not the text. This is a maintainer tool: MintMap itself stays standard
library only. After rendering, upload the PNG in the repository settings (Settings > General > Social preview);
GitHub does not read it from the repository.
"""
import html
import os
import subprocess
import sys
import tempfile
import tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "assets", "social-preview.png")
WIDTH, HEIGHT = 1280, 640

TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><style>
  html, body {{ margin: 0; width: {width}px; height: {height}px; overflow: hidden; background: #0d1117; }}
  body {{ position: relative; font-family: Inter, "DejaVu Sans", sans-serif; color: #c9d1d9; }}
  .bar {{ position: absolute; left: 0; top: 0; width: 100%; height: 11px; background: #3fb950; }}
  .title {{ position: absolute; left: 96px; top: 92px; display: flex; align-items: center; gap: 30px; }}
  h1 {{ margin: 0; font-size: 111px; font-weight: 700; letter-spacing: -3px; color: #f0f6fc; line-height: 1.15; }}
  .badge {{ font-size: 24px; color: #d29922; border: 2px solid #d29922; border-radius: 24px; padding: 7px 17px;
            margin-top: -10px; }}
  .subtitle {{ position: absolute; left: 96px; top: 226px; width: 1010px; font-size: 36px; line-height: 48px; }}
  .code {{ position: absolute; left: 96px; top: 372px; width: 1029px; height: 91px; padding: 16px 28px 18px;
           background: #161b22; border: 2px solid #30363d; border-radius: 12px;
           font-family: "DejaVu Sans Mono", Menlo, Consolas, monospace; font-weight: 700; font-size: 24px;
           line-height: 44px; }}
  .cmd {{ color: #79c0ff; }}
  .bad {{ color: #ff7b72; }}
  .footer {{ position: absolute; left: 96px; top: 561px; font-size: 24px; color: #8b949e; word-spacing: 1px; }}
  .dot {{ padding: 0 12px; }}
</style></head><body>
  <div class="bar"></div>
  <div class="title"><h1>MintMap</h1><span class="badge">experimental</span></div>
  <div class="subtitle">{subtitle}</div>
  <div class="code"><div class="cmd">$ mintmap diff .</div>
    <div class="bad">exit 12 (fingerprint_changed, evidence_downgraded)</div></div>
  <div class="footer">Django<span class="dot">&middot;</span>static analysis<span class="dot">&middot;</span>GitHub
    Action<span class="dot">&middot;</span>Python standard library only</div>
</body></html>
"""

SHOT = """
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: %d, height: %d }, deviceScaleFactor: 1 });
  await page.goto('file://' + process.argv[1]);
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({ path: process.argv[2], omitBackground: false });
  await browser.close();
})().catch((err) => { console.error(err); process.exit(1); });
"""


def card() -> str:
    with open(os.path.join(ROOT, "pyproject.toml"), "rb") as fh:
        subtitle = tomllib.load(fh)["project"]["description"]
    return TEMPLATE.format(width=WIDTH, height=HEIGHT, subtitle=html.escape(subtitle))


def main(argv) -> int:
    if argv[:1] == ["--html"] and len(argv) == 2:
        with open(argv[1], "w", encoding="utf-8") as fh:
            fh.write(card())
        return 0
    if argv:
        sys.stderr.write(__doc__)
        return 2
    with tempfile.TemporaryDirectory() as tmp:
        page = os.path.join(tmp, "card.html")
        with open(page, "w", encoding="utf-8") as fh:
            fh.write(card())
        run = subprocess.run(["node", "-e", SHOT % (WIDTH, HEIGHT), "--", page, OUT], cwd=tmp)
    if run.returncode != 0:
        sys.stderr.write("render_social_preview: rendering failed (needs Node.js with playwright and Chromium)\n")
        return 1
    print(f"wrote {os.path.relpath(OUT, ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
