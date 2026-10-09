#!/usr/bin/env python3
"""Regenerate Virux logo assets (SVG + PNG + macOS menu-bar icons).

Source: assets/logo/source/logo-source.png  (white logo on a black background,
with a decorative word cloud that this script removes by brightness threshold).

Pipeline:
  1. threshold the white logo (drops the grey word cloud)
  2. split into the V mark (top) and the VIRUX wordmark (bottom)
  3. keep the logo's own anti-aliased greyscale, blur, and feed it to potrace
     (dark = foreground) so contour fitting is sub-pixel and edges are smooth
  4. emit SVG (currentColor / white-on-black / black-on-white), PNG exports,
     and macOS menu-bar template icons (monochrome + alpha)

Requires:  python3 -m pip install --user potracer pillow numpy
Usage:     python3 scripts/make-logo-assets.py
"""
import os
import sys
import numpy as np
from PIL import Image, ImageDraw, ImageFilter
import potrace

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = sys.argv[1] if len(sys.argv) > 1 else os.path.join(REPO, "assets/logo/source/logo-source.png")
OUT = os.path.join(REPO, "assets/logo")
PNG = os.path.join(OUT, "png")
RES = os.path.join(REPO, "Sources/ViruxMenuBar/Resources")
S = 4          # supersample factor for tracing
PAD = 16       # viewBox margin in source pixels
THRESHOLD = 200
BLUR = 3.0
ALPHAMAX = 1.334
OPTTOLERANCE = 2.0

for d in (OUT, PNG, RES):
    os.makedirs(d, exist_ok=True)


def svg(w, h, d, fill="currentColor", bg=None, title="Virux", desc=""):
    W2, H2 = w + 2 * PAD, h + 2 * PAD
    bgr = f'<rect width="{W2}" height="{H2}" fill="{bg}"/>' if bg else ''
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W2} {H2}" width="{W2}" height="{H2}" '
            f'role="img" aria-label="{title}"><title>{title}</title><desc>{desc}</desc>{bgr}'
            f'<g transform="translate({PAD},{PAD})"><path d="{d}" fill="{fill}" fill-rule="evenodd"/>'
            f'</g></svg>\n')


def path_d(p, sc):
    out = []
    for c in p.curves:
        sp = c.start_point
        out.append(f"M{sp.x*sc:.2f} {sp.y*sc:.2f}")
        for s in c.segments:
            e = s.end_point
            if s.is_corner:
                out.append(f"L{e.x*sc:.2f} {e.y*sc:.2f}")
            else:
                out.append(f"C{s.c1.x*sc:.2f} {s.c1.y*sc:.2f} {s.c2.x*sc:.2f} {s.c2.y*sc:.2f} "
                           f"{e.x*sc:.2f} {e.y*sc:.2f}")
        out.append("Z")
    return " ".join(out)


def curve_pts(c, steps=24):
    pts = [(c.start_point.x, c.start_point.y)]
    cur = pts[0]
    for s in c.segments:
        e = (s.end_point.x, s.end_point.y)
        if s.is_corner:
            pts.append(e)
        else:
            c1, c2 = (s.c1.x, s.c1.y), (s.c2.x, s.c2.y)
            for i in range(1, steps + 1):
                t = i / steps
                u = 1 - t
                pts.append((u**3 * cur[0] + 3*u*u*t*c1[0] + 3*u*t*t*c2[0] + t**3 * e[0],
                            u**3 * cur[1] + 3*u*u*t*c1[1] + 3*u*t*t*c2[1] + t**3 * e[1]))
        cur = e
    return pts


def trace(iso, w, h):
    up = Image.fromarray(iso.astype('uint8')).resize((w * S, h * S), Image.LANCZOS)
    up = up.filter(ImageFilter.GaussianBlur(BLUR))
    inv = (255 - np.array(up)).astype(np.uint8)     # potrace: dark = foreground
    return potrace.Bitmap(inv, blacklevel=0.5).trace(turdsize=40, alphamax=ALPHAMAX,
                                                     opttolerance=OPTTOLERANCE)


def raster_k(p, w, h, k):
    acc = np.zeros((h * k, w * k), dtype=np.uint8)
    for c in p.curves:
        img = Image.new("1", (w * k, h * k), 0)
        ImageDraw.Draw(img).polygon([(x * k, y * k) for (x, y) in curve_pts(c)], fill=1)
        acc ^= np.array(img, dtype=np.uint8)
    return acc.astype(bool)


def iou(p, ref_mask, w, h):
    ref = np.array(Image.fromarray((ref_mask * 255).astype('uint8'))
                   .resize((w * S, h * S), Image.NEAREST)) > 127
    r = raster_k(p, w * S, h * S, 1)
    return (r & ref).sum() / max((r | ref).sum(), 1)


def render(p, w, h, fg, bg, k=4):
    m = raster_k(p, w * S, h * S, 2)
    img = Image.fromarray((m * 255).astype('uint8')).resize((w * k, h * k), Image.LANCZOS)
    base = Image.new("RGBA", (w * k, h * k), bg if bg else (0, 0, 0, 0))
    base.paste(Image.new("RGBA", (w * k, h * k), fg), (0, 0), img)
    return base


def main():
    gray = np.array(Image.open(SRC).convert("L"))
    mask = gray >= THRESHOLD
    mask[:55, :] = False          # strip stray specks above/below the logo
    mask[362:, :] = False
    ys, xs = np.where(mask)
    y0, y1, x0, x1 = ys.min(), ys.max(), xs.min(), xs.max()
    iso_full = np.where(mask, gray, 0)[y0:y1 + 1, x0:x1 + 1]
    msk_full = mask[y0:y1 + 1, x0:x1 + 1]
    gap = 240 - y0
    iso_emb, msk_emb = iso_full[:gap], msk_full[:gap]
    ey, ex = np.where(msk_emb)
    iso_emb = iso_emb[ey.min():ey.max() + 1, ex.min():ex.max() + 1]
    msk_emb = msk_emb[ey.min():ey.max() + 1, ex.min():ex.max() + 1]
    H, W = iso_full.shape
    eH, eW = iso_emb.shape

    pm = trace(iso_emb, eW, eH)
    pl = trace(iso_full, W, H)
    print(f"V mark:  {eW}x{eH}  curves={len(pm.curves)}  IoU={iou(pm, msk_emb, eW, eH):.3f}")
    print(f"logo:    {W}x{H}  curves={len(pl.curves)}  IoU={iou(pl, msk_full, W, H):.3f}")

    d_mark, d_logo = path_d(pm, 1 / S), path_d(pl, 1 / S)
    files = {
        "virux-mark.svg":                svg(eW, eH, d_mark, "currentColor", None, "Virux V mark", "Monochrome V mark, transparent background"),
        "virux-mark-white-on-black.svg": svg(eW, eH, d_mark, "#FFFFFF", "#000000", "Virux V mark (white on black)", "White V mark on black"),
        "virux-mark-black-on-white.svg": svg(eW, eH, d_mark, "#000000", "#FFFFFF", "Virux V mark (black on white)", "Black V mark on white"),
        "virux-logo.svg":                svg(W, H, d_logo, "currentColor", None, "Virux logo", "Monochrome V mark + VIRUX wordmark, transparent"),
        "virux-logo-white-on-black.svg": svg(W, H, d_logo, "#FFFFFF", "#000000", "Virux logo (white on black)", "White logo on black"),
        "virux-logo-black-on-white.svg": svg(W, H, d_logo, "#000000", "#FFFFFF", "Virux logo (black on white)", "Black logo on white"),
    }
    for n, c in files.items():
        open(os.path.join(OUT, n), "w").write(c)

    render(pm, eW, eH, (255, 255, 255, 255), None).save(os.path.join(PNG, "virux-mark-transparent.png"))
    render(pm, eW, eH, (255, 255, 255, 255), (0, 0, 0, 255)).save(os.path.join(PNG, "virux-mark-white-on-black.png"))
    render(pm, eW, eH, (0, 0, 0, 255), (255, 255, 255, 255)).save(os.path.join(PNG, "virux-mark-black-on-white.png"))
    render(pl, W, H, (255, 255, 255, 255), (0, 0, 0, 255), k=3).save(os.path.join(PNG, "virux-logo-white-on-black.png"))
    render(pl, W, H, (0, 0, 0, 255), (255, 255, 255, 255), k=3).save(os.path.join(PNG, "virux-logo-black-on-white.png"))
    render(pl, W, H, (255, 255, 255, 255), None, k=3).save(os.path.join(PNG, "virux-logo-transparent.png"))

    def icon(h):
        w = max(1, round(h * eW / eH))
        m = raster_k(pm, eW * S, eH * S, 1)
        small = Image.fromarray((m * 255).astype('uint8')).resize((w, h), Image.LANCZOS)
        img = Image.new("RGBA", (w, h), (0, 0, 0, 0))
        img.paste(Image.new("RGBA", (w, h), (0, 0, 0, 255)), (0, 0), small)
        return img, w, h
    i1, w1, h1 = icon(12)
    i1.save(os.path.join(RES, "MenuBarIcon.png"))
    i2, w2, h2 = icon(24)
    i2.save(os.path.join(RES, "MenuBarIcon@2x.png"))
    print(f"wrote 6 SVGs, 6 PNGs, menu-bar icons {w1}x{h1} @1x / {w2}x{h2} @2x")


if __name__ == "__main__":
    main()
