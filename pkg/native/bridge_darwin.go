//go:build darwin
// +build darwin

package native

/*
#cgo LDFLAGS: -framework Foundation -framework Security -framework LocalAuthentication
#include <stdlib.h>
#include "keychain.h"
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func Set(service, account string, data []byte, requireBiometrics bool) error {
	cService := C.CString(service)
	cAccount := C.CString(account)
	cData := C.CBytes(data)
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cAccount))
	defer C.free(cData)

	res := C.keychain_set(cService, cAccount, (*C.char)(cData), C.size_t(len(data)), C.bool(requireBiometrics))
	defer C.free_keychain_result(res)

	if res.error != nil {
		return fmt.Errorf("%s", C.GoString(res.error))
	}
	return nil
}

func Get(service, account string, useBiometrics bool, prompt string) ([]byte, error) {
	cService := C.CString(service)
	cAccount := C.CString(account)
	cPrompt := C.CString(prompt)
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cAccount))
	defer C.free(unsafe.Pointer(cPrompt))

	res := C.keychain_get(cService, cAccount, C.bool(useBiometrics), cPrompt)
	defer C.free_keychain_result(res)

	if res.error != nil {
		return nil, fmt.Errorf("%s", C.GoString(res.error))
	}

	return C.GoBytes(unsafe.Pointer(res.data), C.int(res.length)), nil
}

func Delete(service, account string, useBiometrics bool, prompt string) error {
	cService := C.CString(service)
	cAccount := C.CString(account)
	cPrompt := C.CString(prompt)
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cAccount))
	defer C.free(unsafe.Pointer(cPrompt))

	res := C.keychain_delete(cService, cAccount, C.bool(useBiometrics), cPrompt)
	defer C.free_keychain_result(res)

	if res.error != nil {
		return fmt.Errorf("%s", C.GoString(res.error))
	}
	return nil
}

func List(service string, useBiometrics bool, prompt string) ([]string, error) {
	cService := C.CString(service)
	cPrompt := C.CString(prompt)
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cPrompt))

	res := C.keychain_list(cService, C.bool(useBiometrics), cPrompt)
	defer C.free_keychain_list_result(res)

	if res.error != nil {
		return nil, fmt.Errorf("%s", C.GoString(res.error))
	}

	count := int(res.count)
	if count <= 0 || res.keys == nil {
		return []string{}, nil
	}
	keys := make([]string, count)

	// Convert C array of strings to Go slice of strings
	cKeys := (*[1 << 30]*C.char)(unsafe.Pointer(res.keys))[:count:count]
	for i := 0; i < count; i++ {
		keys[i] = C.GoString(cKeys[i])
	}

	return keys, nil
}
