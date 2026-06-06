# Recording a Tessera demo cast

A short asciinema cast is the cheapest, most credible way to show
what Tessera looks like in motion. About 30 seconds is the sweet spot.

## What you'll demo

Two terminals side by side: host on the left, guest on the right.
The host shares a local port, the guest joins, the host approves
in their terminal, the tunnel opens, the guest reaches the service.

## One-time setup

```bash
make build                # produces ./bin/{coordinator,agent,tessera}
brew install asciinema    # macOS; on Linux: pipx install asciinema
mkdir -p /tmp/tessera-demo && cd /tmp/tessera-demo
./../path/to/bin/tessera ca -coordinator-name localhost
```

This mints a CA and matching coordinator/agent/guest certs in
`/tmp/tessera-demo`.

## Set up three terminals before recording

**Terminal 1 (coordinator, runs in background):**

```bash
cd /tmp/tessera-demo
./../path/to/bin/coordinator \
  -listen 127.0.0.1:18443 -http 127.0.0.1:18080 \
  -ca ca.crt -cert coordinator.crt -key coordinator.key \
  -audit audit.jsonl
```

**Terminal 2 (the "host" side, what the viewer will see on the left):**

```bash
tessera link -mtls 127.0.0.1:18443 -base-url http://127.0.0.1:18080
# Optional: have a fake service for the guest to hit
python3 -m http.server 19000 &
```

**Terminal 3 (the "guest" side, what the viewer will see on the right):**

Nothing yet. Will run `tessera join CODE` when recording.

## Record

Two windows side by side fits a 1280-wide cast cleanly. Or use
tmux split. Start the recording in whatever terminal you want
asciinema to capture (it'll capture the whole pane):

```bash
asciinema rec demo.cast --idle-time-limit 2
```

Then drive the demo:

1. **Host pane**: `tessera share -port 19000 -reason "show alice the dev server"`
2. The code box prints. Pause about a second so it's readable.
3. **Guest pane**: `tessera join CODE` (copy the code).
4. Guest is prompted for their name; type `alice` and Enter.
5. **Host pane**: approval prompt appears. Pause a second, type `y`, Enter.
6. **Guest pane**: prints "approved. forwarding 127.0.0.1:13000 -> ...".
7. **Guest pane**: `curl http://127.0.0.1:13000/` to prove the tunnel works.
8. Ctrl-C on the guest. Both sides clean up.

Press Ctrl-D in the recording terminal to stop asciinema.

## Publish

```bash
asciinema upload demo.cast
```

Returns a URL like `https://asciinema.org/a/<id>`. Drop it in the
README under the live-demo line:

```markdown
**Live coordinator:** [tessera.jengahq.com](https://tessera.jengahq.com/healthz)
**Demo cast:** [<30s on asciinema.org>](https://asciinema.org/a/<id>)
```

Or, if you want to keep the cast in the repo without uploading,
embed via asciinema-player from JSDelivr:

```html
<script src="https://cdn.jsdelivr.net/npm/asciinema-player/dist/bundle/asciinema-player.min.js"></script>
<asciinema-player src="demo/demo.cast"></asciinema-player>
```

Most HN readers click through to asciinema.org's player, so the
upload path is the lower friction one.

## Tips

- `--idle-time-limit 2` collapses pauses longer than 2s, so you can
  type slowly while recording without bloating the cast.
- Run a clean shell with a known prompt (`PS1='$ '`) so the recording
  doesn't show your personal aliases or terminal weirdness.
- Use a font and color scheme that reads well at the default
  asciinema-player size. Solarized Dark and Monokai both work.
- Keep it under 45 seconds. HN viewers don't watch long casts.
