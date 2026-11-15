package report

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"strings"
)

// RenderDonutPNG draws a donut chart for the given slices.
func RenderDonutPNG(slices []ChartSlice, size int) ([]byte, error) {
	if size < 64 {
		size = 220
	}
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	bg := color.RGBA{R: 0xf7, G: 0xf4, B: 0xef, A: 0xff}
	draw.Draw(img, img.Bounds(), &image.Uniform{C: bg}, image.Point{}, draw.Src)

	total := 0
	for _, s := range slices {
		total += s.Count
	}
	cx, cy := float64(size)/2, float64(size)/2
	outer := float64(size)*0.42
	inner := outer * 0.58

	if total == 0 {
		fillCircle(img, cx, cy, outer, color.RGBA{R: 0xd5, G: 0xdc, B: 0xe4, A: 0xff})
		fillCircle(img, cx, cy, inner, bg)
		return encodePNG(img)
	}

	start := -math.Pi / 2
	for _, s := range slices {
		if s.Count <= 0 {
			continue
		}
		span := (float64(s.Count) / float64(total)) * 2 * math.Pi
		fillArc(img, cx, cy, outer, start, start+span, parseHex(s.Color))
		start += span
	}
	fillCircle(img, cx, cy, inner, bg)
	return encodePNG(img)
}

// RenderBarsPNG draws a horizontal bar chart.
func RenderBarsPNG(slices []ChartSlice, width, height int) ([]byte, error) {
	if width < 100 {
		width = 480
	}
	if height < 80 {
		height = 180
	}
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	bg := color.RGBA{R: 0xf7, G: 0xf4, B: 0xef, A: 0xff}
	draw.Draw(img, img.Bounds(), &image.Uniform{C: bg}, image.Point{}, draw.Src)

	max := 0
	active := 0
	for _, s := range slices {
		if s.Count > max {
			max = s.Count
		}
		if s.Count > 0 {
			active++
		}
	}
	if max == 0 || active == 0 {
		return encodePNG(img)
	}

	padL, padR, padT, padB := 90, 24, 16, 16
	rowH := (height - padT - padB) / active
	barMax := width - padL - padR
	i := 0
	for _, s := range slices {
		if s.Count <= 0 {
			continue
		}
		y := padT + i*rowH
		bw := int(float64(barMax) * (float64(s.Count) / float64(max)))
		if bw < 2 {
			bw = 2
		}
		barTop := y + rowH/4
		barH := rowH / 2
		fillRect(img, padL, barTop, bw, barH, parseHex(s.Color))
		drawLabel(img, 8, barTop+barH/2-3, s.Label)
		i++
	}
	return encodePNG(img)
}

// RenderBrandMarkPNG draws a simple shield mark for report headers.
func RenderBrandMarkPNG(size int) ([]byte, error) {
	if size < 48 {
		size = 96
	}
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	bg := color.RGBA{0, 0, 0, 0}
	draw.Draw(img, img.Bounds(), &image.Uniform{C: bg}, image.Point{}, draw.Src)

	cx := float64(size) / 2
	top := float64(size) * 0.12
	bottom := float64(size) * 0.90
	halfW := float64(size) * 0.34
	midY := float64(size) * 0.55

	fill := color.RGBA{R: 0x0d, G: 0x5c, B: 0x42, A: 0xff}
	accent := color.RGBA{R: 0x3e, G: 0xcf, B: 0x8e, A: 0xff}

	// Shield body via scanlines between left/right edges.
	for y := int(top); y < int(bottom); y++ {
		yf := float64(y)
		var half float64
		if yf <= midY {
			t := (yf - top) / (midY - top)
			half = halfW * (0.92 + 0.08*t)
		} else {
			t := (yf - midY) / (bottom - midY)
			half = halfW * (1 - t*t)
		}
		x0 := int(cx - half)
		x1 := int(cx + half)
		for x := x0; x <= x1; x++ {
			if x >= 0 && x < size && y >= 0 && y < size {
				img.Set(x, y, fill)
			}
		}
	}

	// Check mark.
	thick := size / 14
	if thick < 2 {
		thick = 2
	}
	points := [][2]float64{
		{cx - float64(size)*0.16, midY - float64(size)*0.02},
		{cx - float64(size)*0.02, midY + float64(size)*0.14},
		{cx + float64(size)*0.20, midY - float64(size)*0.16},
	}
	strokePolyline(img, points, thick, accent)
	return encodePNG(img)
}

func encodePNG(img image.Image) ([]byte, error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parseHex(hex string) color.RGBA {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) != 6 {
		return color.RGBA{R: 0x88, G: 0x88, B: 0x88, A: 0xff}
	}
	var r, g, b int
	_, _ = fmt.Sscanf(hex, "%02x%02x%02x", &r, &g, &b)
	return color.RGBA{R: uint8(r), G: uint8(g), B: uint8(b), A: 0xff}
}

func fillCircle(img *image.RGBA, cx, cy, radius float64, c color.RGBA) {
	r2 := radius * radius
	minX := int(cx - radius - 1)
	maxX := int(cx + radius + 1)
	minY := int(cy - radius - 1)
	maxY := int(cy + radius + 1)
	b := img.Bounds()
	for y := minY; y <= maxY; y++ {
		for x := minX; x <= maxX; x++ {
			if x < b.Min.X || x >= b.Max.X || y < b.Min.Y || y >= b.Max.Y {
				continue
			}
			dx := float64(x) + 0.5 - cx
			dy := float64(y) + 0.5 - cy
			if dx*dx+dy*dy <= r2 {
				img.Set(x, y, c)
			}
		}
	}
}

func fillArc(img *image.RGBA, cx, cy, radius, start, end float64, c color.RGBA) {
	for end < start {
		end += 2 * math.Pi
	}
	r2 := radius * radius
	minX := int(cx - radius - 1)
	maxX := int(cx + radius + 1)
	minY := int(cy - radius - 1)
	maxY := int(cy + radius + 1)
	b := img.Bounds()
	for y := minY; y <= maxY; y++ {
		for x := minX; x <= maxX; x++ {
			if x < b.Min.X || x >= b.Max.X || y < b.Min.Y || y >= b.Max.Y {
				continue
			}
			dx := float64(x) + 0.5 - cx
			dy := float64(y) + 0.5 - cy
			if dx*dx+dy*dy > r2 {
				continue
			}
			ang := math.Atan2(dy, dx)
			for ang < start {
				ang += 2 * math.Pi
			}
			if ang >= start && ang <= end {
				img.Set(x, y, c)
			}
		}
	}
}

func fillRect(img *image.RGBA, x, y, w, h int, c color.RGBA) {
	b := img.Bounds()
	for yy := y; yy < y+h; yy++ {
		for xx := x; xx < x+w; xx++ {
			if xx >= b.Min.X && xx < b.Max.X && yy >= b.Min.Y && yy < b.Max.Y {
				img.Set(xx, yy, c)
			}
		}
	}
}

func drawLabel(img *image.RGBA, x, y int, text string) {
	// Tiny 3x5 bitmap font for chart labels (A-Z, a-z, 0-9, space, -).
	ink := color.RGBA{R: 0x2a, G: 0x33, B: 0x3c, A: 0xff}
	cx := x
	for _, ch := range strings.ToUpper(text) {
		glyph, ok := tinyFont[ch]
		if !ok {
			cx += 4
			continue
		}
		for row := 0; row < 5; row++ {
			for col := 0; col < 3; col++ {
				if glyph[row]&(1<<(2-col)) != 0 {
					px, py := cx+col, y+row
					if px >= 0 && px < img.Bounds().Max.X && py >= 0 && py < img.Bounds().Max.Y {
						img.Set(px, py, ink)
					}
				}
			}
		}
		cx += 4
	}
}

func strokePolyline(img *image.RGBA, pts [][2]float64, thick int, c color.RGBA) {
	for i := 0; i < len(pts)-1; i++ {
		strokeSegment(img, pts[i][0], pts[i][1], pts[i+1][0], pts[i+1][1], thick, c)
	}
}

func strokeSegment(img *image.RGBA, x0, y0, x1, y1 float64, thick int, c color.RGBA) {
	steps := int(math.Hypot(x1-x0, y1-y0)) + 1
	r := float64(thick) / 2
	for i := 0; i <= steps; i++ {
		t := float64(i) / float64(steps)
		x := x0 + (x1-x0)*t
		y := y0 + (y1-y0)*t
		fillCircle(img, x, y, r, c)
	}
}

// 3x5 glyphs packed as 3-bit rows.
var tinyFont = map[rune][5]uint8{
	' ': {0, 0, 0, 0, 0},
	'-': {0, 0, 7, 0, 0},
	'0': {7, 5, 5, 5, 7},
	'1': {2, 6, 2, 2, 7},
	'2': {7, 1, 7, 4, 7},
	'3': {7, 1, 7, 1, 7},
	'4': {5, 5, 7, 1, 1},
	'5': {7, 4, 7, 1, 7},
	'6': {7, 4, 7, 5, 7},
	'7': {7, 1, 2, 2, 2},
	'8': {7, 5, 7, 5, 7},
	'9': {7, 5, 7, 1, 7},
	'A': {2, 5, 7, 5, 5},
	'B': {6, 5, 6, 5, 6},
	'C': {3, 4, 4, 4, 3},
	'D': {6, 5, 5, 5, 6},
	'E': {7, 4, 6, 4, 7},
	'F': {7, 4, 6, 4, 4},
	'G': {3, 4, 5, 5, 3},
	'H': {5, 5, 7, 5, 5},
	'I': {7, 2, 2, 2, 7},
	'J': {1, 1, 1, 5, 2},
	'K': {5, 5, 6, 5, 5},
	'L': {4, 4, 4, 4, 7},
	'M': {5, 7, 7, 5, 5},
	'N': {5, 7, 7, 7, 5},
	'O': {2, 5, 5, 5, 2},
	'P': {6, 5, 6, 4, 4},
	'Q': {2, 5, 5, 7, 3},
	'R': {6, 5, 6, 5, 5},
	'S': {3, 4, 2, 1, 6},
	'T': {7, 2, 2, 2, 2},
	'U': {5, 5, 5, 5, 7},
	'V': {5, 5, 5, 5, 2},
	'W': {5, 5, 7, 7, 5},
	'X': {5, 5, 2, 5, 5},
	'Y': {5, 5, 2, 2, 2},
	'Z': {7, 1, 2, 4, 7},
}
