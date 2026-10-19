package winplatform

// Minimal COM Automation support for the OS's Task Scheduler and persistent
// IP-interface provider. It is not a general scripting host and runs only in
// bounded workers. All interfaces and BSTRs are released on the creating thread.
import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ole32 = windows.NewLazySystemDLL("ole32.dll")
var oleaut = windows.NewLazySystemDLL("oleaut32.dll")
var iidDispatch = windows.GUID{Data1: 0x00020400, Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}
var iidNull windows.GUID

type comObject struct{ vt *[32]uintptr }
type variant struct {
	vt       uint16
	reserved [3]uint16
	data     uintptr
	extra    uintptr
}

type comError struct{ Code uint32 }

func (e *comError) Error() string { return fmt.Sprintf("COM HRESULT 0x%08x", e.Code) }
func missingCOM(err error) bool {
	var e *comError
	return errors.As(err, &e) && (e.Code == 0x80070002 || e.Code == 0x80070003)
}
func hresult(hr uintptr) error {
	if int32(uint32(hr)) < 0 {
		return &comError{Code: uint32(hr)}
	}
	return nil
}

//go:uintptrescapes
func (o *comObject) invokeSlot(slot int, args ...uintptr) (uintptr, error) {
	all := append([]uintptr{uintptr(unsafe.Pointer(o))}, args...)
	r, _, _ := syscall.SyscallN(o.vt[slot], all...)
	return r, hresult(r)
}
func (o *comObject) release() {
	if o != nil {
		_, _ = o.invokeSlot(2)
	}
}
func comThread(run func() (any, error)) (any, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	r, _, _ := ole32.NewProc("CoInitializeEx").Call(0, 2)
	if err := hresult(r); err != nil {
		return nil, err
	}
	defer ole32.NewProc("CoUninitialize").Call()
	return run()
}
func comCreate(class string, iid *windows.GUID) (*comObject, error) {
	var id windows.GUID
	if strings.HasPrefix(class, "{") {
		var err error
		id, err = windows.GUIDFromString(class)
		if err != nil {
			return nil, err
		}
	} else {
		name, err := windows.UTF16PtrFromString(class)
		if err != nil {
			return nil, err
		}
		r, _, _ := ole32.NewProc("CLSIDFromProgID").Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&id)))
		if err := hresult(r); err != nil {
			return nil, err
		}
	}
	var o *comObject
	r, _, _ := ole32.NewProc("CoCreateInstance").Call(uintptr(unsafe.Pointer(&id)), 0, 1|4, uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&o)))
	if err := hresult(r); err != nil {
		return nil, err
	}
	return o, nil
}
func bstr(s string) (uintptr, error) {
	v, err := windows.UTF16FromString(s)
	if err != nil {
		return 0, err
	}
	p, _, _ := oleaut.NewProc("SysAllocStringLen").Call(uintptr(unsafe.Pointer(&v[0])), uintptr(len(v)-1))
	if p == 0 {
		return 0, fmt.Errorf("allocate COM string")
	}
	return p, nil
}
func bstrText(p *uint16) string {
	if p == nil {
		return ""
	}
	n, _, _ := oleaut.NewProc("SysStringLen").Call(uintptr(unsafe.Pointer(p)))
	return windows.UTF16ToString(unsafe.Slice(p, int(n)))
}
func (v *variant) clear() {
	oleaut.NewProc("VariantClear").Call(uintptr(unsafe.Pointer(v)))
	*v = variant{}
}
func makeVariant(v any) (variant, error) {
	switch x := v.(type) {
	case nil:
		return variant{vt: 1}, nil
	case string:
		p, err := bstr(x)
		return variant{vt: 8, data: p}, err
	case int:
		return variant{vt: 3, data: uintptr(int64(x))}, nil
	case uint32:
		return variant{vt: 19, data: uintptr(x)}, nil
	case bool:
		var n uintptr
		if x {
			n = 0xffff
		}
		return variant{vt: 11, data: n}, nil
	case *comObject:
		_, _ = x.invokeSlot(1)
		return variant{vt: 9, data: uintptr(unsafe.Pointer(x))}, nil
	}
	return variant{}, fmt.Errorf("unsupported COM argument %T", v)
}

type dispatchParams struct {
	args              *variant
	named             *int32
	count, namedCount uint32
}
type exceptionInfo struct {
	code, reserved            uint16
	source, description, help *uint16
	helpContext               uint32
	reservedPtr, deferred     uintptr
	scode                     int32
}

func (o *comObject) call(name string, flags uint16, args ...any) (variant, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return variant{}, err
	}
	var id int32
	if _, err := o.invokeSlot(5, uintptr(unsafe.Pointer(&iidNull)), uintptr(unsafe.Pointer(&p)), 1, 0, uintptr(unsafe.Pointer(&id))); err != nil {
		return variant{}, fmt.Errorf("COM member %s: %w", name, err)
	}
	values := make([]variant, len(args))
	defer func() {
		for i := range values {
			values[i].clear()
		}
	}()
	for i, v := range args {
		values[len(args)-1-i], err = makeVariant(v)
		if err != nil {
			return variant{}, err
		}
	}
	params := dispatchParams{count: uint32(len(values))}
	if len(values) > 0 {
		params.args = &values[0]
	}
	putID := int32(-3)
	if flags&4 != 0 {
		params.named = &putID
		params.namedCount = 1
	}
	var result variant
	var exception exceptionInfo
	defer func() {
		for _, p := range []*uint16{exception.source, exception.description, exception.help} {
			if p != nil {
				oleaut.NewProc("SysFreeString").Call(uintptr(unsafe.Pointer(p)))
			}
		}
	}()
	_, err = o.invokeSlot(6, uintptr(id), uintptr(unsafe.Pointer(&iidNull)), 0, uintptr(flags), uintptr(unsafe.Pointer(&params)), uintptr(unsafe.Pointer(&result)), uintptr(unsafe.Pointer(&exception)), 0)
	if err != nil {
		if exception.deferred != 0 {
			_, _, _ = syscall.SyscallN(exception.deferred, uintptr(unsafe.Pointer(&exception)))
		}
		detail := bstrText(exception.description)
		result.clear()
		return variant{}, dispatchError(name, err, exception.scode, exception.code, detail)
	}
	return result, nil
}

func dispatchError(member string, outer error, scode int32, code uint16, detail string) error {
	if scode < 0 {
		return fmt.Errorf("%s: %w (%v); %s", member, &comError{Code: uint32(scode)}, outer, detail)
	}
	if code != 0 {
		return fmt.Errorf("%s: %w; exception code %d; %s", member, outer, code, detail)
	}
	return fmt.Errorf("%s: %w %s", member, outer, detail)
}
func (o *comObject) object(name string, flags uint16, args ...any) (*comObject, error) {
	v, err := o.call(name, flags, args...)
	if err != nil {
		return nil, err
	}
	if v.vt != 9 || v.data == 0 {
		v.clear()
		return nil, fmt.Errorf("%s did not return a COM object", name)
	}
	// VARIANT's native union contains an interface pointer when vt=VT_DISPATCH.
	return *(**comObject)(unsafe.Pointer(&v.data)), nil
}
func (o *comObject) discard(name string, flags uint16, args ...any) error {
	v, err := o.call(name, flags, args...)
	v.clear()
	return err
}
func (o *comObject) text(name string) (string, error) {
	v, err := o.call(name, 2)
	if err != nil {
		return "", err
	}
	defer v.clear()
	if v.vt != 8 {
		return "", fmt.Errorf("%s is not text", name)
	}
	return bstrText(*(**uint16)(unsafe.Pointer(&v.data))), nil
}
func (o *comObject) number(name string) (int, error) {
	v, err := o.call(name, 2)
	if err != nil {
		return 0, err
	}
	defer v.clear()
	switch v.vt {
	case 2, 3, 17, 18, 19, 22, 23:
		return int(v.data), nil
	}
	return 0, fmt.Errorf("%s is not a number", name)
}

// SetIpInterfaceEntry changes ActiveStore only. The documented NetTCPIP COM
// provider supplies PersistentStore (Store=0), the same store PowerShell writes.
// https://learn.microsoft.com/powershell/module/nettcpip/set-netipinterface
func persistMetric(index uint32, family uint16, automatic bool, metric uint32) error {
	_, err := comThread(func() (any, error) {
		locator, err := comCreate("{76a64158-cb41-11d1-8b02-00600806d9b6}", &iidDispatch)
		if err != nil {
			return nil, err
		}
		defer locator.release()
		service, err := locator.object("ConnectServer", 1, ".", `root\StandardCimv2`)
		if err != nil {
			return nil, err
		}
		defer service.release()
		options, err := comCreate("WbemScripting.SWbemNamedValueSet", &iidDispatch)
		if err != nil {
			return nil, err
		}
		defer options.release()
		// PolicyStore is a provider query option, not a WQL property filter;
		// see Microsoft's MSFT_NetIPInterface.cdxml QueryOptions declaration.
		if err := options.discard("Add", 1, "PolicyStore", "PersistentStore"); err != nil {
			return nil, err
		}
		set, err := service.object("ExecQuery", 1, fmt.Sprintf("SELECT * FROM MSFT_NetIPInterface WHERE InterfaceIndex=%d AND AddressFamily=%d", index, family), "WQL", 0, options)
		if err != nil {
			return nil, err
		}
		defer set.release()
		count, err := set.number("Count")
		if err != nil {
			return nil, err
		}
		if count != 1 {
			return nil, fmt.Errorf("persistent interface %d/%d: got %d records", index, family, count)
		}
		item, err := set.object("ItemIndex", 1, 0)
		if err != nil {
			return nil, err
		}
		defer item.release()
		auto := 0
		if automatic {
			auto = 1
		}
		if err := item.discard("AutomaticMetric", 4, auto); err != nil {
			return nil, err
		}
		if !automatic {
			if err := item.discard("InterfaceMetric", 4, metric); err != nil {
				return nil, err
			}
		}
		return nil, item.discard("Put_", 1, 1, options)
	})
	return err
}
