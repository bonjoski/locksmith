//go:build darwin

package native

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <libproc.h>
#include <sys/proc_info.h>

int get_ppid(int pid) {
	struct proc_bsdinfo sinfo;
	if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &sinfo, sizeof(sinfo)) > 0) {
		return sinfo.pbi_ppid;
	}
	return -1;
}

int get_path(int pid, char *buf, int bufsize) {
	return proc_pidpath(pid, buf, bufsize);
}

int get_signing_info(int pid, char *id_buf, int id_len, char *team_buf, int team_len) {
	CFNumberRef pid_num = CFNumberCreate(NULL, kCFNumberIntType, &pid);
	const void *keys[] = { kSecGuestAttributePid };
	const void *values[] = { pid_num };
	CFDictionaryRef attr = CFDictionaryCreate(NULL, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFRelease(pid_num);

	SecCodeRef code = NULL;
	OSStatus status = SecCodeCopyGuestWithAttributes(NULL, attr, kSecCSDefaultFlags, &code);
	CFRelease(attr);
	if (status != errSecSuccess) {
		return status;
	}

	CFDictionaryRef info = NULL;
	status = SecCodeCopySigningInformation(code, kSecCSDefaultFlags, &info);
	CFRelease(code);
	if (status != errSecSuccess) {
		return status;
	}

	// Get identifier
	CFStringRef identifier = (CFStringRef)CFDictionaryGetValue(info, kSecCodeInfoIdentifier);
	if (identifier) {
		CFStringGetCString(identifier, id_buf, id_len, kCFStringEncodingUTF8);
	}

	// Get team identifier
	CFStringRef team = (CFStringRef)CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier);
	if (team) {
		CFStringGetCString(team, team_buf, team_len, kCFStringEncodingUTF8);
	}

	CFRelease(info);
	return 0;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func getProcessInfo(pid int) (*ProcessInfo, error) {
	buf := make([]byte, 2048)
	idBuf := make([]byte, 256)
	teamBuf := make([]byte, 256)

	defer func() {
		for i := range buf {
			buf[i] = 0
		}
		for i := range idBuf {
			idBuf[i] = 0
		}
		for i := range teamBuf {
			teamBuf[i] = 0
		}
	}()

	pathRes := C.get_path(C.int(pid), (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf)))
	if pathRes <= 0 {
		return nil, fmt.Errorf("failed to get path for PID %d", pid)
	}
	path := C.GoString((*C.char)(unsafe.Pointer(&buf[0])))

	C.get_signing_info(
		C.int(pid),
		(*C.char)(unsafe.Pointer(&idBuf[0])), C.int(len(idBuf)),
		(*C.char)(unsafe.Pointer(&teamBuf[0])), C.int(len(teamBuf)),
	)

	idStr := C.GoString((*C.char)(unsafe.Pointer(&idBuf[0])))
	teamStr := C.GoString((*C.char)(unsafe.Pointer(&teamBuf[0])))

	return &ProcessInfo{
		Path:       path,
		Identifier: idStr,
		TeamID:     teamStr,
	}, nil
}

func getParentPID(pid int) (int, error) {
	ppid := int(C.get_ppid(C.int(pid)))
	if ppid < 0 {
		return -1, fmt.Errorf("failed to get parent PID for PID %d", pid)
	}
	return ppid, nil
}
