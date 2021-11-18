package iohelper

import (
	"io"
	"runtime"
)

// ReadInputLine read a line from user input stream (usually the stdin)
// copied from golang.org/x/term/terminal.go#readPasswordLine
func ReadInputLine(r io.Reader) ([]byte, error) {
	var buf [1]byte
	var ret []byte

	for {
		n, err := r.Read(buf[:])
		if n > 0 {
			switch buf[0] {
			case '\b':
				if len(ret) > 0 {
					ret = ret[:len(ret)-1]
				}
			case '\n':
				if runtime.GOOS != "windows" {
					return ret, nil
				}
				// otherwise ignore \n
			case '\r':
				if runtime.GOOS == "windows" {
					return ret, nil
				}
				// otherwise ignore \r
			default:
				ret = append(ret, buf[0])
			}
			continue
		}
		if err != nil {
			if err == io.EOF && len(ret) > 0 {
				return ret, nil
			}
			return ret, err
		}
	}
}
