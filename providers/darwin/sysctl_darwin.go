//go:build darwin

package darwin

import (
	"bytes"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func sysctlRaw(name string, args ...int) ([]byte, error) {
	if !isBuggyXNUKernel() {
		return unix.SysctlRaw(name, args...)
	}

	// Workaround for https://github.com/golang/go/issues/60047.
	// If Go drops support for macOS 10.x then this workaround can
	// be removed, and it can revert to using unix.SysctlRaw for all
	// cases.
	return _sysctlRaw(name, args...)
}

var (
	// fixedXNUKernelVersion specifies the first known XNU kernel version
	// that has the fixed procargs2 implementation. xnu-7195 was first used
	// in macOS Big Sur 11.0.1.
	// https://github.com/apple-oss-distributions/xnu/blob/xnu-7195.50.7.100.1/bsd/kern/kern_sysctl.c#L1552-#L1592
	fixedXNUKernelVersion = 7195
	buggyXNUKernel        bool
	isBuggyXNUKernelOnce  sync.Once
)

// isBuggyXNUKernel return true if the kernel version is affected by
// a procargs2 implementation bug.
func isBuggyXNUKernel() bool {
	isBuggyXNUKernelOnce.Do(func() {
		var v unix.Utsname
		if err := unix.Uname(&v); err != nil {
			return
		}

		major := xnuMajor(v.Version[:])
		if major == -1 {
			return
		}

		if major >= fixedXNUKernelVersion {
			return
		}

		buggyXNUKernel = true
	})
	return buggyXNUKernel
}

// xnuMajor extracts the XNU major version from the 'uname -v' value. It
// returns -1 on failure. An example value is
//
//	Darwin Kernel Version 22.4.0: Mon Mar  6 20:59:28 PST 2023; root:xnu-8796.101.5~3/RELEASE_ARM64_T6000
func xnuMajor(version []byte) int {
	idx := bytes.Index(version, []byte("xnu-"))
	if idx == -1 {
		return -1
	}
	version = version[idx+len("xnu-"):]

	idx = bytes.IndexByte(version, '.')
	if idx == -1 {
		return -1
	}
	version = version[:idx]

	major, err := strconv.Atoi(string(version))
	if err != nil {
		return -1
	}
	return major
}

// Buffer Pool

var bufferPool = sync.Pool{
	New: func() interface{} {
		return &poolMem{
			buf: make([]byte, argMax),
		}
	},
}

type poolMem struct {
	buf  []byte
	pool *sync.Pool
}

func getPoolMem() *poolMem {
	pm := bufferPool.Get().(*poolMem)
	pm.buf = pm.buf[0:cap(pm.buf)]
	pm.pool = &bufferPool
	return pm
}

func (m *poolMem) Release() { m.pool.Put(m) }

// sysctl implementation (mostly copied from golang.org/x/sys/unix)

type (
	_C_int int32
)

const (
	_CTL_MAXNAME = 0xc
)

// Single-word zero for use when we need a valid pointer to 0 bytes.
var _zero uintptr

// Do the interface allocations only once for common
// Errno values.
var (
	_errEAGAIN error = syscall.EAGAIN
	_errEINVAL error = syscall.EINVAL
	_errENOENT error = syscall.ENOENT
)

func _sysctlRaw(name string, args ...int) ([]byte, error) {
	mib, err := _sysctlmib(name, args...)
	if err != nil {
		return nil, err
	}

	// NOTE: This is what differs from the stdlib implementation.
	// It passes in a buffer that is max size which is larger than
	// what is needed to hold the response.
	mem := getPoolMem()
	defer mem.Release()

	size := uintptr(len(mem.buf))
	if err := _sysctl(mib, &mem.buf[0], &size, nil, 0); err != nil {
		return nil, err
	}
	data := mem.buf[0:size]

	// Don't return a slice into the buffer pool.
	out := make([]byte, len(data))
	copy(out, data)
	return out, nil
}

// _sysctlmib translates name to mib number and appends any additional args.
func _sysctlmib(name string, args ...int) ([]_C_int, error) {
	// Translate name to mib number.
	mib, err := _nametomib(name)
	if err != nil {
		return nil, err
	}

	for _, a := range args {
		mib = append(mib, _C_int(a))
	}

	return mib, nil
}

// Translate "kern.hostname" to []_C_int{0,1,2,3}.
func _nametomib(name string) (mib []_C_int, err error) {
	const siz = unsafe.Sizeof(mib[0])

	// NOTE(rsc): It seems strange to set the buffer to have
	// size CTL_MAXNAME+2 but use only CTL_MAXNAME
	// as the size. I don't know why the +2 is here, but the
	// kernel uses +2 for its own implementation of this function.
	// I am scared that if we don't include the +2 here, the kernel
	// will silently write 2 words farther than we specify
	// and we'll get memory corruption.
	var buf [_CTL_MAXNAME + 2]_C_int
	n := uintptr(_CTL_MAXNAME) * siz

	p := (*byte)(unsafe.Pointer(&buf[0]))
	bytes, err := unix.ByteSliceFromString(name)
	if err != nil {
		return nil, err
	}

	// Magic sysctl: "setting" 0.3 to a string name
	// lets you read back the array of integers form.
	if err = _sysctl([]_C_int{0, 3}, p, &n, &bytes[0], uintptr(len(name))); err != nil {
		return nil, err
	}
	return buf[0 : n/siz], nil
}

func _sysctl(mib []_C_int, old *byte, oldlen *uintptr, new *byte, newlen uintptr) (err error) {
	var _p0 unsafe.Pointer
	if len(mib) > 0 {
		_p0 = unsafe.Pointer(&mib[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	_, _, e1 := syscall.Syscall6(syscall.SYS___SYSCTL, uintptr(_p0), uintptr(len(mib)), uintptr(unsafe.Pointer(old)), uintptr(unsafe.Pointer(oldlen)), uintptr(unsafe.Pointer(new)), uintptr(newlen))
	if e1 != 0 {
		err = _errnoErr(e1)
	}
	return
}

// _errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func _errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case syscall.EAGAIN:
		return _errEAGAIN
	case syscall.EINVAL:
		return _errEINVAL
	case syscall.ENOENT:
		return _errENOENT
	}
	return e
}
