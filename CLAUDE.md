# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Development setup
uv venv && source .venv/bin/activate
uv pip install -e .

# Run directly (without reinstalling)
python -m scorchd --dry-run
python -m scorchd --scan
python -m scorchd --verbose photo.jpg

# Install as tool (required to test systemd service changes)
uv tool install . --force --no-cache   # --no-cache is required; --force alone serves stale wheels
```

There are no tests or linter configs in this repo.

## Architecture

The entire implementation lives in `scorchd/__main__.py`. There are two operating modes:

**Direct mode** — when no daemon socket exists: the CLI connects to the printer via BLE directly, renders content, transmits raw bytes, and disconnects.

**Daemon mode** (`--daemon`) — a persistent asyncio server that:
- Maintains a live BLE connection through `_connection_loop()`, auto-reconnecting on drop
- Sends periodic heartbeats via `_heartbeat_loop()` to keep the connection alive
- Listens on a Unix socket (`$XDG_RUNTIME_DIR/scorchd.sock`) for JSON commands
- Serializes print jobs with an `asyncio.Lock` (one job at a time)

The CLI auto-detects which mode to use: if the socket file exists, it routes through the daemon; otherwise it connects directly.

### BLE protocol

The printer uses a custom framing format:
```
[0x51, 0x78, CMD, 0x00, DATA_LEN, 0x00, ...DATA..., CRC8(DATA), 0xFF]
```
CRC-8 uses a custom lookup table reverse-engineered from the vendor APK. Print data is sent as row commands — either run-length encoded (`0xBF`) when the RLE is shorter than the raw representation, or raw 1-bit-per-pixel (`0xA2`). Print width is always 384px (48 bytes/row, 200 DPI).

### Image pipeline

Content → pixel rows → BLE commands:
- Images are resized to 384px wide, then dithered to 1-bit using Floyd-Steinberg (default), Atkinson, threshold, or none
- Text is rendered on the host using a system font (DejaVu Sans / Liberation Sans / Helvetica) into a 384px-wide bitmap — the printer has no text rendering
- `build_print_commands()` wraps rows with init/teardown commands and prefixes each job with `lattice_end + get_dev_state` to clear stuck state from aborted jobs

### Socket protocol

Length-prefixed JSON, one request per connection: `[4-byte big-endian uint32 length][JSON payload]`. Commands: `status`, `print` (with `content_type`: `image`/`text`/`black`), `reset`. See `PROTOCOL.md` for full spec.

### Daemon connection state

The `state` dict is shared across the connection loop and socket handlers:
- `state["client"]` — the live `BleakClient`, or `None` when disconnected
- `state["done_event"]` — an `asyncio.Event` set by the RX notification handler when the printer signals ready
- `state["job_state"]` — `"idle"` or `"printing"`

Mid-print client disconnects are handled by racing `_transmit` against a `reader.read(1)` watch task; on disconnect, the transmit is cancelled and a fire-and-forget cleanup task sends `lattice_end + get_dev_state` outside the lock.
