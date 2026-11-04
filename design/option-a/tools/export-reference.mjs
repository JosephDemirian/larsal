// Exports the Option A reference set for the build and verify fleet:
//   reference/light/<frame-id>.png, reference/dark/<frame-id>.png and manifest.json
// (every frame's size, visible strings, accessible names and placeholders).
// Runs headless Chrome offscreen; never opens a window (AGENTS.md rule 10).
// Usage: node design/option-a/tools/export-reference.mjs
// Needs Node 22+, Google Chrome, and the browser driver from the design-taste-frontend skill.
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const { Browser } = await import(`${process.env.HOME}/.claude/skills/design-taste-frontend/scripts/lib/cdp.mjs`);
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const browser = await Browser.launch({ width: 1500, height: 1000 });
let manifest;
try {
  for (const theme of ['light', 'dark']) {
    const out = join(root, 'reference', theme);
    mkdirSync(out, { recursive: true });
    const page = await browser.newPage({ width: 1500, height: 1000, dsf: 2 });
    await page.goto(`file://${join(root, 'mockup.html')}?theme=${theme}&zoom=1&t=1793088610000`, { settleMs: 2000 });
    const frames = await page.eval(() => [...document.querySelectorAll('.frame')].map((f) => {
      const w = f.querySelector('.win'), el = w.classList.contains('cardwin') ? w.firstElementChild : w, r = el.getBoundingClientRect();
      return { id: f.id, x: r.x + scrollX, y: r.y + scrollY, w: r.width, h: r.height };
    }));
    for (const f of frames) {
      const shot = await page.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { x: f.x, y: f.y, width: f.w, height: f.h, scale: 1 } });
      writeFileSync(join(out, `${f.id}.png`), Buffer.from(shot.data, 'base64'));
    }
    if (theme === 'light') manifest = await page.eval(() => window.MOCKUP_MANIFEST());
    console.log(`${theme}: ${frames.length} frames`);
    await page.close();
  }
  writeFileSync(join(root, 'manifest.json'), JSON.stringify({ source: 'design/option-a/mockup.html', frames: manifest.length, list: manifest }, null, 2) + '\n');
  console.log(`manifest.json: ${manifest.length} frames`);
} finally {
  await browser.close();
}
