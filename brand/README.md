# Brand assets (source)

Source for the README banner (`/NPG_banner.png` light, `/NPG_banner_dark.png` dark). Mascot kept; layout modernized.

- `fav-0.png` — sloth + N mascot (extracted from `ui/public/favicon.ico`), the lockup logomark.
- `banner.html` — light banner (dark wordmark, gradient "Guard").
- `banner-dark.html` — dark banner (light wordmark) for GitHub dark mode.

## Regenerate

ImageMagick's SVG/gradient rendering is unreliable, so the banners are rendered in a real browser.

```bash
cd brand
python3 -m http.server 8901 --bind 127.0.0.1 &
# Open http://localhost:8901/banner.html (and banner-dark.html) in a browser,
# screenshot the #banner element, then floodfill the background transparent:
#   light: magick raw.png -alpha set -bordercolor white  -border 1 -fill none -fuzz 12% -draw "alpha 0,0 floodfill" -shave 1x1 ../NPG_banner.png
#   dark : magick raw.png -alpha set -bordercolor '#0b1220' -border 1 -fill none -fuzz 12% -draw "alpha 0,0 floodfill" -shave 1x1 ../NPG_banner_dark.png
```

README references both via `<picture>` with `prefers-color-scheme`.
