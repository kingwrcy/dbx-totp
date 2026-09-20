//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	crypt32                = syscall.NewLazyDLL("crypt32.dll")
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procCryptProtectData   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	procLocalFree          = kernel32.NewProc("LocalFree")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(data []byte) *dataBlob {
	if len(data) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{
		cbData: uint32(len(data)),
		pbData: &data[0],
	}
}

func (blob *dataBlob) bytes() []byte {
	if blob == nil || blob.cbData == 0 || blob.pbData == nil {
		return nil
	}
	return unsafe.Slice(blob.pbData, int(blob.cbData))
}

func protectBytes(data []byte) ([]byte, error) {
	input := newBlob(data)
	var output dataBlob
	ok, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(input)),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&output)),
	)
	if ok == 0 {
		return nil, fmt.Errorf("加密仓库失败: %v", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(output.pbData)))
	return append([]byte(nil), output.bytes()...), nil
}

func unprotectBytes(data []byte) ([]byte, error) {
	input := newBlob(data)
	var output dataBlob
	ok, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(input)),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&output)),
	)
	if ok == 0 {
		return nil, fmt.Errorf("解密仓库失败: %v", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(output.pbData)))
	return append([]byte(nil), output.bytes()...), nil
}
