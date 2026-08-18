//go:build darwin

package cmd

import (
	"syscall"
	"time"
	"unsafe"
)

// bootTime returns the system boot time using kern.boottime sysctl.
func bootTime() (time.Time, error) {
	var tv syscall.Timeval
	mib := [2]int32{1, 21} // CTL_KERN=1, KERN_BOOTTIME=21
	n := uintptr(unsafe.Sizeof(tv))
	if _, _, errno := syscall.Syscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		2,
		uintptr(unsafe.Pointer(&tv)),
		uintptr(unsafe.Pointer(&n)),
		0, 0,
	); errno != 0 {
		return time.Time{}, errno
	}
	return time.Unix(int64(tv.Sec), int64(tv.Usec)*1000), nil
}
