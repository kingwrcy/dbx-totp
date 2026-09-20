//go:build !windows

package main

func protectBytes(data []byte) ([]byte, error) {
	return append([]byte(nil), data...), nil
}

func unprotectBytes(data []byte) ([]byte, error) {
	return append([]byte(nil), data...), nil
}
