package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// watchRecordings polls recordDir for new .log files created at or after
// startedAt and spawns a followFile goroutine for each. It exits when ctx
// is cancelled. The function itself is blocking; callers run it in a
// goroutine.
func watchRecordings(ctx context.Context, recordDir string, startedAt time.Time) {
	if recordDir == "" {
		return
	}
	var seen sync.Map
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		entries, err := os.ReadDir(recordDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
				continue
			}
			path := filepath.Join(recordDir, e.Name())
			if _, ok := seen.Load(path); ok {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			if info.ModTime().Before(startedAt) {
				continue
			}
			seen.Store(path, struct{}{})
			go followFile(ctx, path)
		}
	}
}

// followFile opens path and pumps its contents to stdout as bytes appear,
// re-trying on EOF every 100ms. Exits when ctx is cancelled.
func followFile(ctx context.Context, path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	buf := make([]byte, 32*1024)
	for {
		if ctx.Err() != nil {
			return
		}
		n, err := f.Read(buf)
		if n > 0 {
			_, _ = os.Stdout.Write(buf[:n])
		}
		if err == nil {
			continue
		}
		if err != io.EOF {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}
