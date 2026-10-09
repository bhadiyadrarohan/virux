# Virux logo assets

Extracted from the supplied artwork (white logo on a black background with a
decorative word cloud). The word cloud is removed by brightness threshold; the
logo's own anti-aliased edges are preserved and traced with potrace, so the
result is a real vector with smooth edges.

## Files

| File | What it is |
|---|---|
| `virux-mark.svg` | The V mark alone, `currentColor`, transparent background. Use this for UI/icons. |
| `virux-mark-white-on-black.svg` | V mark, white on black. |
| `virux-mark-black-on-white.svg` | V mark, black on white. |
| `virux-logo.svg` | V mark + VIRUX wordmark, `currentColor`, transparent. |
| `virux-logo-white-on-black.svg` | Full logo, white on black. |
| `virux-logo-black-on-white.svg` | Full logo, black on white. |
| `png/*.png` | Raster exports of the above (transparent where applicable). |
| `source/logo-source.png` | The input artwork used by the generator. |

The `currentColor` files inherit the CSS `color` (so in HTML:
`<img src="virux-mark.svg">` keeps its own colour, but inlined as `<svg>` it
takes the surrounding text colour).

## Menu-bar icon

The app ships `Sources/ViruxMenuBar/Resources/MenuBarIcon.png` (+ `@2x`) as a
macOS **template image** (monochrome + alpha), so the system tints it for light
and dark menu bars automatically. The colour status dot (green/yellow/red) is
drawn as a separate attributed character next to the mark.

## Regenerating

```
python3 -m pip install --user potracer pillow numpy
python3 scripts/make-logo-assets.py
```

The script prints the vector fidelity (IoU) against the source. Current output:
V mark IoU 0.98, logo IoU 0.98.

To adjust smoothing, edit `BLUR`, `ALPHAMAX`, `OPTTOLERANCE` at the top of the
script. To change the threshold that separates the logo from the word cloud,
edit `THRESHOLD`.
