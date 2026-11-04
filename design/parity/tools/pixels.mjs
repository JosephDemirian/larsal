// The pixel result of one frame and theme as the parity reports print it
// (compare.mjs). When the mockup image and the app snapshot differ in size,
// pixelmatch cannot compare them: the reports say so and give both sizes,
// never 'undefined %'. Test: node --test design/parity/tools/pixels.test.mjs

/** `t`: one theme's result (present, sizeOk, sizes, pixels, residual). */
export function pixelText(t) {
  if (!t.present) return 'missing';
  if (!t.sizeOk) return `not compared: image sizes differ (mockup ${t.sizes.ref.join(' × ')} px, app ${t.sizes.app.join(' × ')} px)`;
  return `${t.pixels} % (${t.residual} % outside accepted areas)`;
}
