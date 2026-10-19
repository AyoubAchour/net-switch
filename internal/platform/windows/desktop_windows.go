package winplatform

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/png"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/apps"
	"golang.org/x/sys/windows"
)

var versionDLL = windows.NewLazySystemDLL("version.dll")
var shell32 = windows.NewLazySystemDLL("shell32.dll")
var user32 = windows.NewLazySystemDLL("user32.dll")
var gdi32 = windows.NewLazySystemDLL("gdi32.dll")

func versionName(path string) string {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	n, _, _ := versionDLL.NewProc("GetFileVersionInfoSizeW").Call(uintptr(unsafe.Pointer(p)), 0)
	if n == 0 || n > 16*1024*1024 {
		return ""
	}
	b := make([]byte, n)
	ok, _, _ := versionDLL.NewProc("GetFileVersionInfoW").Call(uintptr(unsafe.Pointer(p)), 0, n, uintptr(unsafe.Pointer(&b[0])))
	if ok == 0 {
		return ""
	}
	query := func(key string) (unsafe.Pointer, uint32) {
		k, _ := windows.UTF16PtrFromString(key)
		var out unsafe.Pointer
		var size uint32
		r, _, _ := versionDLL.NewProc("VerQueryValueW").Call(uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(k)), uintptr(unsafe.Pointer(&out)), uintptr(unsafe.Pointer(&size)))
		if r == 0 {
			return nil, 0
		}
		return out, size
	}
	translation, translationSize := query(`\VarFileInfo\Translation`)
	pairs := [][2]uint16{}
	if translation != nil && translationSize >= 4 {
		words := unsafe.Slice((*uint16)(translation), int(translationSize/2))
		for i := 0; i+1 < len(words); i += 2 {
			pairs = append(pairs, [2]uint16{words[i], words[i+1]})
		}
	}
	pairs = append(pairs, [2]uint16{0x409, 0x4b0}, [2]uint16{0x409, 0x4e4})
	for _, field := range []string{"FileDescription", "ProductName"} {
		for _, pair := range pairs {
			p, n := query(fmt.Sprintf(`\StringFileInfo\%04x%04x\%s`, pair[0], pair[1], field))
			if p == nil || n == 0 {
				continue
			}
			text := strings.TrimSpace(windows.UTF16ToString(unsafe.Slice((*uint16)(p), int(n))))
			if text != "" && len([]rune(text)) <= 60 {
				return text
			}
		}
	}
	return ""
}

type shellFileInfo struct {
	Icon        windows.Handle
	Index       int32
	Attributes  uint32
	DisplayName [260]uint16
	TypeName    [80]uint16
}
type iconInfo struct {
	IsIcon      int32
	X, Y        uint32
	Mask, Color windows.Handle
}
type bitmap struct {
	Type, Width, Height, WidthBytes int32
	Planes, BitsPixel               uint16
	Bits                            unsafe.Pointer
}
type bitmapInfoHeader struct {
	Size                   uint32
	Width, Height          int32
	Planes, BitCount       uint16
	Compression, SizeImage uint32
	XPels, YPels           int32
	Used, Important        uint32
}
type bitmapInfo struct {
	Header bitmapInfoHeader
	Colors [2]uint32
}

func iconPNG(path string) ([]byte, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var info shellFileInfo
	r, _, _ := shell32.NewProc("SHGetFileInfoW").Call(uintptr(unsafe.Pointer(p)), 0, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info), 0x100)
	if r == 0 || info.Icon == 0 {
		return nil, fmt.Errorf("no associated icon")
	}
	defer user32.NewProc("DestroyIcon").Call(uintptr(info.Icon))
	var ii iconInfo
	r, _, _ = user32.NewProc("GetIconInfo").Call(uintptr(info.Icon), uintptr(unsafe.Pointer(&ii)))
	if r == 0 {
		return nil, fmt.Errorf("read icon")
	}
	if ii.Mask != 0 {
		defer gdi32.NewProc("DeleteObject").Call(uintptr(ii.Mask))
	}
	if ii.Color != 0 {
		defer gdi32.NewProc("DeleteObject").Call(uintptr(ii.Color))
	}
	var bm bitmap
	handle := ii.Color
	if handle == 0 {
		handle = ii.Mask
	}
	r, _, _ = gdi32.NewProc("GetObjectW").Call(uintptr(handle), unsafe.Sizeof(bm), uintptr(unsafe.Pointer(&bm)))
	if r == 0 {
		return nil, fmt.Errorf("read icon bitmap")
	}
	w, h := int(bm.Width), int(bm.Height)
	if ii.Color == 0 {
		h /= 2
	}
	if w < 1 || h < 1 || w > 1024 || h > 1024 {
		return nil, fmt.Errorf("invalid icon dimensions")
	}
	dc, _, _ := gdi32.NewProc("CreateCompatibleDC").Call(0)
	if dc == 0 {
		return nil, fmt.Errorf("create icon DC")
	}
	defer gdi32.NewProc("DeleteDC").Call(dc)
	bi := bitmapInfo{Header: bitmapInfoHeader{Size: 40, Width: int32(w), Height: -int32(h), Planes: 1, BitCount: 32}}
	pixels := make([]byte, w*h*4)
	if ii.Color != 0 {
		r, _, _ = gdi32.NewProc("GetDIBits").Call(dc, uintptr(ii.Color), 0, uintptr(h), uintptr(unsafe.Pointer(&pixels[0])), uintptr(unsafe.Pointer(&bi)), 0)
		if r == 0 {
			return nil, fmt.Errorf("read icon pixels")
		}
	}
	alpha := false
	for i := 3; i < len(pixels); i += 4 {
		alpha = alpha || pixels[i] != 0
	}
	maskStride := (w + 31) / 32 * 4
	mask := make([]byte, maskStride*h)
	if !alpha && ii.Mask != 0 {
		mi := bitmapInfo{Header: bitmapInfoHeader{Size: 40, Width: int32(w), Height: -int32(h), Planes: 1, BitCount: 1}}
		r, _, _ = gdi32.NewProc("GetDIBits").Call(dc, uintptr(ii.Mask), 0, uintptr(h), uintptr(unsafe.Pointer(&mask[0])), uintptr(unsafe.Pointer(&mi)), 0)
		if r == 0 {
			return nil, fmt.Errorf("read icon transparency mask")
		}
	}
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			i := (y*w + x) * 4
			a := pixels[i+3]
			if !alpha {
				a = 255
				if mask[y*maskStride+x/8]&(0x80>>uint(x%8)) != 0 {
					a = 0
				}
			}
			img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = pixels[i+2], pixels[i+1], pixels[i], a
		}
	}
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
func appInformation(paths []string) []map[string]any {
	out := []map[string]any{}
	for _, p := range paths {
		var name, icon any
		if n := versionName(p); n != "" {
			name = n
		}
		if b, err := iconPNG(p); err == nil {
			icon = base64.StdEncoding.EncodeToString(b)
		}
		out = append(out, map[string]any{"path": p, "name": name, "icon": icon})
	}
	return out
}

var iidShellLink = windows.GUID{Data1: 0x000214f9, Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}
var iidPersistFile = windows.GUID{Data1: 0x0000010b, Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}

func resolveShortcut(path string) (string, string, error) {
	link, err := comCreate("{00021401-0000-0000-c000-000000000046}", &iidShellLink)
	if err != nil {
		return "", "", err
	}
	defer link.release()
	var file *comObject
	if _, err := link.invokeSlot(0, uintptr(unsafe.Pointer(&iidPersistFile)), uintptr(unsafe.Pointer(&file))); err != nil {
		return "", "", err
	}
	defer file.release()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", "", err
	}
	if _, err := file.invokeSlot(5, uintptr(unsafe.Pointer(p)), 0); err != nil {
		return "", "", err
	}
	target, args := make([]uint16, 32768), make([]uint16, 32768)
	if _, err := link.invokeSlot(3, uintptr(unsafe.Pointer(&target[0])), uintptr(len(target)), 0, 0); err != nil {
		return "", "", err
	}
	if _, err := link.invokeSlot(10, uintptr(unsafe.Pointer(&args[0])), uintptr(len(args))); err != nil {
		return "", "", err
	}
	return windows.UTF16ToString(target), windows.UTF16ToString(args), nil
}

var maintenanceName = regexp.MustCompile(`(?i)(?:^|[\s._-])(?:uninstall(?:er)?|unins\d*|setup|installer)(?:$|[\s._-])`)
var maintenanceExe = regexp.MustCompile(`(?i)(?:unins(?:tall(?:er)?)?\d*|setup|installer)\.exe$`)
var maintenanceArgs = regexp.MustCompile(`(?i)(?:^|\s)[/-]+(?:uninstall|setup)(?:\s|$)`)
var versionDir = regexp.MustCompile(`(?i)^app-\d+(?:\.\d+)+$`)
var processStart = regexp.MustCompile(`(?i)(?:^|\s)--processStart(?:\s+|=)(?:"([^"\\/]+\.exe)"|([^\s"\\/]+\.exe))(?:\s|$)`)

func newestVersion(dir, exe string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	names := []string{}
	for _, e := range entries {
		if e.IsDir() && versionDir.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Slice(names, func(i, j int) bool {
		a, b := strings.Split(names[i][4:], "."), strings.Split(names[j][4:], ".")
		for k := 0; k < max(len(a), len(b)); k++ {
			x, y := 0, 0
			if k < len(a) {
				x, _ = strconv.Atoi(a[k])
			}
			if k < len(b) {
				y, _ = strconv.Atoi(b[k])
			}
			if x != y {
				return x > y
			}
		}
		return names[i] > names[j]
	})
	for _, n := range names {
		p := filepath.Join(dir, n, exe)
		if s, err := os.Stat(p); err == nil && s.Mode().IsRegular() {
			return p
		}
	}
	return ""
}
func installedApps() (any, error) {
	return comThread(func() (any, error) {
		type shortcut struct{ name, path, args string }
		links := []shortcut{}
		for _, root := range []string{filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs`), filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs`)} {
			err := filepath.WalkDir(root, func(p string, d fs.DirEntry, e error) error {
				if errorsIsMissing(e) {
					return nil
				}
				if e != nil {
					return e
				}
				if d.IsDir() || !strings.EqualFold(filepath.Ext(p), ".lnk") {
					return nil
				}
				target, args, err := resolveShortcut(p)
				if err == nil {
					links = append(links, shortcut{strings.TrimSuffix(d.Name(), filepath.Ext(d.Name())), target, args})
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
		sort.SliceStable(links, func(i, j int) bool {
			a, b := strings.ToLower(links[i].name), strings.ToLower(links[j].name)
			if a != b {
				return a < b
			}
			return strings.ToLower(links[i].path) < strings.ToLower(links[j].path)
		})
		seen := map[string]bool{}
		result := []map[string]any{}
		for _, s := range links {
			if strings.TrimSpace(s.name) == "" || maintenanceName.MatchString(s.name) || maintenanceArgs.MatchString(s.args) || !strings.EqualFold(filepath.Ext(s.path), ".exe") {
				continue
			}
			dir := filepath.Dir(s.path)
			target := s.path
			if strings.EqualFold(filepath.Base(target), "Update.exe") {
				m := processStart.FindStringSubmatch(s.args)
				if m == nil {
					continue
				}
				exe := m[1]
				if exe == "" {
					exe = m[2]
				}
				target = newestVersion(dir, exe)
			} else if latest := newestVersion(dir, filepath.Base(target)); latest != "" {
				target = latest
			}
			if target == "" || maintenanceExe.MatchString(filepath.Base(target)) {
				continue
			}
			if info, err := os.Stat(target); err != nil || !info.Mode().IsRegular() {
				continue
			}
			key := apps.AppKey(target)
			if seen[key] {
				continue
			}
			seen[key] = true
			result = append(result, map[string]any{"name": strings.TrimSpace(s.name), "path": target, "hasIcon": false})
		}
		return result, nil
	})
}
func errorsIsMissing(err error) bool { return err != nil && os.IsNotExist(err) }
