// Package agent runs on the host's side and serves approved streams to allowed local targets.
package agent

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"time"

	"github.com/creack/pty"

	"github.com/emmayusufu/tessera/internal/netutil"
	"github.com/emmayusufu/tessera/internal/proto"
)

const handshakeTimeout = 15 * time.Second

type Agent struct {
	ShareID string
	Dial    netutil.Dialer
	Allowed []string
	Inner   *tls.Config
	Logger  *slog.Logger

	// ShellMode makes every incoming stream a PTY-backed shell on the host
	// instead of a TCP dial to Target. Allowed and Target are ignored.
	ShellMode bool
	// RecordPath, when non-empty in shell mode, is a directory where session
	// transcripts are written as <session-id>.log. The directory must already
	// exist; the agent doesn't create it.
	RecordPath string
}

// RunWithBackoff calls Run in a loop until ctx is cancelled, sleeping with
// exponential backoff (1s, 2s, 4s, 8s, capped at 30s) plus light jitter
// between attempts. Recovers from Wi-Fi flaps and short coordinator hiccups.
func RunWithBackoff(ctx context.Context, a *Agent) {
	delay := time.Second
	for ctx.Err() == nil {
		err := a.Run(ctx)
		if err == nil || ctx.Err() != nil {
			return
		}
		jitter := time.Duration(rand.Int63n(int64(delay)/4+1)) - delay/8
		wait := delay + jitter
		if wait < 0 {
			wait = time.Second
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return
		}
		delay *= 2
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
	}
}

func (a *Agent) Run(ctx context.Context) error {
	log := a.Logger
	if log == nil {
		log = slog.Default()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ctl, err := a.Dial()
	if err != nil {
		return err
	}
	defer ctl.Close()

	if err := proto.WriteMsg(ctl, proto.Msg{Kind: proto.KindRegister, ShareID: a.ShareID}); err != nil {
		return err
	}
	log.Info("registered with coordinator", "share_id", a.ShareID)

	go func() {
		<-ctx.Done()
		ctl.Close()
	}()

	for {
		m, err := proto.ReadMsg(ctl)
		if err != nil {
			return err
		}
		if m.Kind == proto.KindOpenData {
			go a.serveStream(ctx, m, log)
		}
	}
}

func (a *Agent) serveStream(ctx context.Context, m proto.Msg, log *slog.Logger) {
	if !a.ShellMode && !slices.Contains(a.Allowed, m.Target) {
		log.Warn("refused target not on allowlist", "target", m.Target)
		return
	}
	if a.Inner == nil {
		log.Error("no inner TLS config; refusing to serve unencrypted stream")
		return
	}

	data, err := a.Dial()
	if err != nil {
		log.Error("data dial to coordinator failed", "err", err)
		return
	}
	if err := proto.WriteMsg(data, proto.Msg{Kind: proto.KindDataHello, Role: "agent", ConnID: m.ConnID}); err != nil {
		data.Close()
		return
	}

	hsCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	inner := tls.Server(data, a.Inner)
	if err := inner.HandshakeContext(hsCtx); err != nil {
		log.Error("inner TLS handshake failed", "err", err)
		inner.Close()
		return
	}

	if a.ShellMode {
		a.serveShell(inner, m, log)
		return
	}

	target, err := net.Dial("tcp", m.Target)
	if err != nil {
		log.Error("dial target failed", "target", m.Target, "err", err)
		inner.Close()
		return
	}
	log.Info("stream open", "target", m.Target)
	netutil.Pipe(inner, target)
	log.Info("stream closed", "target", m.Target)
}

func (a *Agent) serveShell(stream net.Conn, m proto.Msg, log *slog.Logger) {
	defer stream.Close()

	rows, cols, err := readSize(stream)
	if err != nil {
		log.Error("shell: read initial size failed", "err", err)
		return
	}
	if rows == 0 {
		rows = 24
	}
	if cols == 0 {
		cols = 80
	}

	cmd := exec.Command(shellPath(), "-l", "-i")
	env := os.Environ()
	if !hasEnv(env, "TERM") {
		env = append(env, "TERM=xterm-256color")
	}
	if !hasEnv(env, "COLORTERM") {
		env = append(env, "COLORTERM=truecolor")
	}
	cmd.Env = env

	ptmx, err := pty.Start(cmd)
	if err != nil {
		log.Error("shell: pty start failed", "err", err)
		return
	}
	defer func() {
		_ = ptmx.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	_ = pty.Setsize(ptmx, &pty.Winsize{Rows: rows, Cols: cols})

	var out io.Writer = stream
	if a.RecordPath != "" && m.ConnID != "" {
		path := filepath.Join(a.RecordPath, m.ConnID+".log")
		f, ferr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if ferr == nil {
			defer f.Close()
			out = io.MultiWriter(stream, f)
			log.Info("shell session recording", "path", path)
		} else {
			log.Warn("shell: could not open recording file", "err", ferr)
		}
	}

	log.Info("shell stream open", "rows", rows, "cols", cols)
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(ptmx, stream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(out, ptmx)
		done <- struct{}{}
	}()
	<-done
	log.Info("shell stream closed")
}

func shellPath() string {
	if s := os.Getenv("SHELL"); s != "" {
		return s
	}
	return "/bin/bash"
}

func hasEnv(env []string, key string) bool {
	prefix := key + "="
	for _, kv := range env {
		if len(kv) >= len(prefix) && kv[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// readSize reads the 8-byte size header sent by the guest as the very first
// bytes of the stream: rows uint32 big-endian, then cols uint32 big-endian.
// Values are clamped to maxDim before the uint16 downcast pty.Winsize wants,
// so a malicious guest sending rows=70000 can't wrap to 4464 or otherwise
// confuse the host's terminal.
func readSize(r io.Reader) (rows, cols uint16, err error) {
	const maxDim = 9999
	var hdr [8]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return 0, 0, err
	}
	rowsRaw := binary.BigEndian.Uint32(hdr[0:4])
	colsRaw := binary.BigEndian.Uint32(hdr[4:8])
	if rowsRaw > maxDim {
		rowsRaw = maxDim
	}
	if colsRaw > maxDim {
		colsRaw = maxDim
	}
	return uint16(rowsRaw), uint16(colsRaw), nil
}
