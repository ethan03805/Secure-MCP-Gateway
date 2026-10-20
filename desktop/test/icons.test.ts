// The application icon set (docs/design/visual.md, Application icon):
// every file tauri.conf.json bundles exists with the size its name states,
// the .icns and .ico hold PNG images of the expected sizes, and the SVG
// source uses flat fills only. CI also runs scripts/make-icons.py --check,
// which regenerates every file and compares bytes.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const icons = new URL("../src-tauri/icons/", import.meta.url);
const read = (f: string) => readFileSync(new URL(f, icons));

function pngSize(b: Buffer): [number, number] {
  assert.equal(b.subarray(1, 4).toString("latin1"), "PNG");
  return [b.readUInt32BE(16), b.readUInt32BE(20)];
}

test("every bundled icon exists with the size its name states", () => {
  const conf = JSON.parse(readFileSync(new URL("../src-tauri/tauri.conf.json", import.meta.url), "utf8")) as { bundle: { icon: string[] } };
  const want: Record<string, number> = { "icons/32x32.png": 32, "icons/128x128.png": 128, "icons/128x128@2x.png": 256 };
  for (const f of conf.bundle.icon) {
    const b = readFileSync(new URL(`../src-tauri/${f}`, import.meta.url));
    if (want[f]) assert.deepEqual(pngSize(b), [want[f], want[f]], f);
  }
  assert.deepEqual(pngSize(read("icon.png")), [512, 512]);
});

test("icon.icns holds PNG images from 16 to 1024 pixels", () => {
  const b = read("icon.icns");
  assert.equal(b.subarray(0, 4).toString("latin1"), "icns");
  assert.equal(b.readUInt32BE(4), b.length);
  const sizes = new Set<number>();
  for (let i = 8; i < b.length; ) {
    const len = b.readUInt32BE(i + 4);
    sizes.add(pngSize(b.subarray(i + 8, i + len))[0]);
    i += len;
  }
  assert.deepEqual([...sizes].sort((x, y) => x - y), [16, 32, 64, 128, 256, 512, 1024]);
});

test("icon.ico holds PNG images from 16 to 256 pixels", () => {
  const b = read("icon.ico");
  assert.deepEqual([b.readUInt16LE(0), b.readUInt16LE(2)], [0, 1]);
  const n = b.readUInt16LE(4);
  const sizes: number[] = [];
  for (let k = 0; k < n; k++) {
    const e = 6 + 16 * k;
    const len = b.readUInt32LE(e + 8);
    const off = b.readUInt32LE(e + 12);
    const [w] = pngSize(b.subarray(off, off + len));
    assert.equal(b[e] || 256, w);
    sizes.push(w);
  }
  assert.deepEqual(sizes, [16, 24, 32, 48, 64, 256]);
});

test("the SVG source is flat: two colors, no gradient, filter, text or image", () => {
  const svg = read("app-icon.svg").toString("utf8");
  assert.doesNotMatch(svg, /gradient|filter|<text|<image|opacity|blur|shadow/i);
  const colors = new Set(svg.match(/#[0-9a-f]{6}/gi) ?? []);
  assert.deepEqual([...colors].sort(), ["#2c5a46", "#f4f5f0"]);
});
