// Package netutil holds small networking helpers shared across tessera.
package netutil

import (
	"io"
	"net"
	"time"
)

type Dialer func() (net.Conn, error)

func Pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	<-done
	a.Close()
	b.Close()
	<-done
}

func PipeIdle(a, b net.Conn, idle time.Duration) {
	done := make(chan struct{}, 2)
	go func() { _ = copyIdle(a, b, idle); done <- struct{}{} }()
	go func() { _ = copyIdle(b, a, idle); done <- struct{}{} }()
	<-done
	a.Close()
	b.Close()
	<-done
}

func copyIdle(dst, src net.Conn, idle time.Duration) error {
	buf := make([]byte, 32*1024)
	for {
		_ = src.SetReadDeadline(time.Now().Add(idle))
		n, err := src.Read(buf)
		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(idle))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			return err
		}
	}
}
