# scorchd

BLE daemon and CLI for iPrint thermal printers (GT01, GB01, GB02, GB03).

## Install

```bash
uv tool install .
```

This installs the `scorchd` binary to `~/.local/bin`, which is where the systemd service looks for it.

## Usage

```bash
scorchd photo.jpg
scorchd "Hello!" --text
scorchd --black 20
scorchd note.png --device GT01 --energy 0x8000
scorchd --scan
scorchd --status
scorchd --daemon
```

## Systemd service (persistent daemon)

```bash
cp scorchd.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now scorchd.service
```

Check status:

```bash
systemctl --user status scorchd.service
journalctl --user -u scorchd.service -f
```

## Development

To iterate locally without reinstalling the tool each time, run directly from the repo:

```bash
uv venv
source .venv/bin/activate
uv pip install -e .
python -m scorchd --dry-run
```

**Important:** `uv pip install -e .` (editable install) does **not** update the `scorchd` binary in `~/.local/bin` — that's managed separately by `uv tool install`. If you're testing changes that will run via systemd, you must reinstall after each change:

```bash
uv tool install . --force --no-cache
```

The `--no-cache` flag is required because `uv tool install` caches built wheels and will silently serve stale code otherwise. Plain `--force` alone is not sufficient.
