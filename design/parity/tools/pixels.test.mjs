// node --test design/parity/tools/pixels.test.mjs
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { pixelText } from './pixels.mjs';

test('image sizes differ: a clear message with both sizes, never undefined %', () => {
  const text = pixelText({ present: true, sizeOk: false, sizes: { ref: [920, 424], app: [920, 440] } });
  assert.equal(text, 'not compared: image sizes differ (mockup 920 × 424 px, app 920 × 440 px)');
  assert.ok(!text.includes('undefined'));
});

test('equal sizes: the changed share and what is left outside accepted areas', () => {
  assert.equal(pixelText({ present: true, sizeOk: true, pixels: 1.25, residual: 0.5 }), '1.25 % (0.5 % outside accepted areas)');
});

test('no snapshot: missing', () => {
  assert.equal(pixelText({ present: false }), 'missing');
});

test('compare.mjs prints every pixel result through pixelText', async () => {
  const { readFileSync } = await import('node:fs');
  const source = readFileSync(new URL('./compare.mjs', import.meta.url), 'utf8');
  assert.ok(!/themes\.(light|dark)\.pixels/.test(source), 'a summary cell prints .pixels unguarded');
});
