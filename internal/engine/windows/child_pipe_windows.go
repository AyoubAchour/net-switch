package winengine

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/AyoubAchour/net-switch/internal/winhandle"
	"golang.org/x/sys/windows"
)

func DialChildPipe(ctx context.Context, nonce string, pid uint32) (io.ReadWriteCloser, error) {
	if b, err := hex.DecodeString(nonce); err != nil || len(b) != 16 || pid == 0 {
		return nil, errors.New("invalid private child identity")
	}
	name := EnginePipe + ".child." + nonce
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	for {
		h, err := windows.CreateFile(path, windows.FILE_READ_DATA|windows.FILE_WRITE_DATA|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if errors.Is(err, windows.ERROR_PIPE_BUSY) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(10 * time.Millisecond):
				continue
			}
		}
		if err != nil {
			return nil, err
		}
		owner := winhandle.Open(h, "private child pipe client")
		var actual uint32
		if err := windows.GetNamedPipeServerProcessId(h, &actual); err != nil || actual != pid {
			return nil, errors.Join(fmt.Errorf("private child pipe PID=%d expected=%d error=%v", actual, pid, err), owner.HandleClose("private child pipe identity failure"))
		}
		return newPipeConn(owner, name)
	}
}
