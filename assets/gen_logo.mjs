// Generates the vio logo. Deterministic: there is no random number generator
// here, so regeneration is byte-identical.
// Usage: node gen_logo.mjs <outdir>
//
// THE MARK. A "v" -- for vio -- built out of packets, with the two arms reading
// as the two halves of the name: in on one side, out on the other. The colour
// runs the length of the stroke, from deep indigo where the first byte arrived
// to cyan at the head, so the mark is one pass of data through the loop and the
// bright end is where it has got to.
//
// Why a letter rather than a ring. Every ring drawn for this library came out a
// loading spinner: async I/O's most obvious image is also its most worn one,
// and a broken circle with a bright arc is what half the JavaScript ecosystem
// already ships. A "v" is the project's own initial, it is still legible at
// sixteen pixels where a stippled ring turns to grey mush, and the two arms
// happen to say the true thing about an I/O library without being asked to.
//
// Why cells rather than a solid stroke. The same reason dewfall's drop is made
// of points: the mark should be made of the thing the library moves. These are
// discrete and evenly spaced because that is what packets on a connection are,
// and the gaps are deliberate -- a solid V is a letter, a spaced one is a
// sequence.

const outdir = process.argv[2] ?? '.';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

const lerp = (a, b, t) => a + (b - a) * t;
function hex(r, g, b) {
  return '#' + [r, g, b].map((v) => Math.round(Math.max(0, Math.min(255, v))).toString(16).padStart(2, '0')).join('');
}
const mix = (a, b, t) => hex(lerp(a[0], b[0], t), lerp(a[1], b[1], t), lerp(a[2], b[2], t));

const DEEP = [67, 26, 133];
const MID = [124, 58, 237];
const BRIGHT = [167, 139, 250];
const HEAD = [34, 211, 238];

// Per arm, not counting the vertex, which the two arms share.
const PER_ARM = 6;
const SPAN = 0.740; // tip to tip
const RISE = 0.660; // vertex to tip
const FILL = 0.90;  // of the tightest gap between neighbouring cells

// The cell size is derived, not chosen, and that is worth the four lines. Two
// different gaps have to stay open: the step along an arm, and the distance
// between the two cells either side of the vertex, which is smaller because the
// arms converge there. Setting the size by eye satisfies the first and quietly
// violates the second, and the mark grows a blob at the point.
const ARM = Math.hypot(SPAN / 2, RISE);
const STEP = ARM / PER_ARM;
const VERTEX_GAP = 2 * STEP * Math.sin(Math.atan((SPAN / 2) / RISE));
const CELL = Math.min(STEP, VERTEX_GAP) * FILL;

// Colour along the whole stroke: u = 0 at the incoming tip, 1 at the head. The
// cyan is held back to the last sixth so it reads as one mark with a live end,
// rather than as a wash from one hue to another.
function colourAt(u) {
  if (u < 0.46) return mix(DEEP, MID, u / 0.46);
  if (u < 0.84) return mix(MID, BRIGHT, (u - 0.46) / 0.38);
  return mix(BRIGHT, HEAD, (u - 0.84) / 0.16);
}

function makeCells() {
  const cells = [];
  const vy = 0.5 + RISE / 2;
  const total = PER_ARM * 2; // tip to tip, with the vertex at the midpoint
  for (let k = 0; k <= total; k++) {
    const side = k < PER_ARM ? -1 : k > PER_ARM ? 1 : 0;
    const t = Math.abs(k - PER_ARM) / PER_ARM; // 1 at a tip, 0 at the vertex
    cells.push({ x: 0.5 + side * t * (SPAN / 2), y: vy - t * RISE, c: colourAt(k / total) });
  }
  return cells;
}

function markSvg(cells, size, pad) {
  const s = size - 2 * pad;
  return cells
    .map((d) => {
      const w = CELL * s;
      const x = pad + d.x * s - w / 2;
      const y = pad + d.y * s - w / 2;
      return `<rect x="${x.toFixed(2)}" y="${y.toFixed(2)}" width="${w.toFixed(2)}" height="${w.toFixed(2)}" rx="${(w * 0.30).toFixed(2)}" fill="${d.c}"/>`;
    })
    .join('\n    ');
}

const cells = makeCells();

const ICON = 512, PAD = 40;
const icon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${ICON} ${ICON}" width="${ICON}" height="${ICON}">
  <title>vio</title>
  <g>
    ${markSvg(cells, ICON, PAD)}
  </g>
</svg>
`;
writeFileSync(join(outdir, 'logo.svg'), icon);

const BH = 240, BW = 720, DS = 196, DPAD = 4;
const banner = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${BW} ${BH}" width="${BW}" height="${BH}">
  <title>vio — async I/O, awaited</title>
  <g transform="translate(40, 22)">
    ${markSvg(cells, DS, DPAD)}
  </g>
  <g font-family="ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif">
    <text x="264" y="135" font-size="100" font-weight="650" letter-spacing="-2" fill="#2e1065">v<tspan fill="#7c3aed">io</tspan></text>
    <text x="268" y="184" font-size="28" fill="#64748b">async I/O, awaited.</text>
  </g>
</svg>
`;
writeFileSync(join(outdir, 'banner.svg'), banner);
console.log(`wrote logo.svg (${cells.length} cells) and banner.svg to ${outdir}`);
