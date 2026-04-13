# scorchd Socket Protocol

The `scorchd` daemon exposes a Unix socket at `$XDG_RUNTIME_DIR/scorchd.sock`
(typically `/run/user/1000/scorchd.sock`). Any application can submit print jobs or query
printer status by opening a connection to this socket.

## Transport

Each request/response is length-prefixed:

```
[4 bytes: payload length, big-endian uint32] [N bytes: JSON payload]
```

One request per connection. The client sends a request, receives a response, and closes.

## Commands

### `status` — Check printer connection

Ask the daemon whether it currently has an active BLE connection to the printer.

**Request:**
```json
{"cmd": "status"}
```

**Response:**
```json
{"connected": true, "state": "idle"}
```

`state` is one of `"idle"` or `"printing"`.

---

### `reset` — Recover from a stuck print job

Sends a `lattice_end` + `get_dev_state` sequence to the printer to clear any state left
behind by an aborted job (e.g. a paper jam where the client disconnected mid-print). Also
resets the daemon's internal job state to `"idle"`.

The daemon serializes this with the print lock, so it is safe to call while another job is
finishing.

**Request:**
```json
{"cmd": "reset"}
```

**Response (success):**
```json
{"ok": true}
```

**Response (printer not connected):**
```json
{"ok": false, "error": "Printer not connected"}
```

---

### `print` — Send a print job

Submit content to print. The daemon renders the content and transmits it to the printer
over the live BLE connection. The response is returned once the printer signals it is done
(or after a 30-second timeout).

All print requests share this base structure:

```json
{
  "cmd": "print",
  "content_type": "<type>",
  "energy": 65535
}
```

`energy` is optional (default `65535`). Range is `0` (faint) to `65535` (darkest).

**On success:**
```json
{"ok": true}
```

**On failure:**
```json
{"ok": false, "error": "Printer not connected"}
```

---

#### `content_type: "text"` — Render and print a string

The daemon renders the text to a bitmap on the host using a system font (DejaVu Sans,
Liberation Sans, or Helvetica depending on what is installed), then sends the result to
the printer as raw pixel rows. The printer receives only image data — it has no text or
font rendering capability of its own. The output is centered on the 384px-wide paper.

```json
{
  "cmd": "print",
  "content_type": "text",
  "text": "Hello, world!",
  "font_size": 24,
  "energy": 65535
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `text` | string | yes | The string to print |
| `font_size` | int | no | Font size in points (default: `24`) |
| `energy` | int | no | Thermal energy, `0`–`65535` (default: `65535`) |

---

#### `content_type: "image"` — Print an image file

The daemon loads the image, scales it to 384px wide, dithers it to 1-bit, and prints it.
The path must be accessible to the daemon process.

```json
{
  "cmd": "print",
  "content_type": "image",
  "path": "/home/cael/photos/receipt.png",
  "algo": "floyd-steinberg",
  "energy": 65535
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `path` | string | yes | Absolute path to the image file |
| `algo` | string | no | Dithering algorithm (default: `"floyd-steinberg"`) |
| `energy` | int | no | Thermal energy, `0`–`65535` (default: `65535`) |

Supported dithering algorithms:

| Value | Description |
|---|---|
| `floyd-steinberg` | Classic error-diffusion dither, good for photos |
| `atkinson` | Slightly lighter dither, good for illustrations |
| `threshold` | Simple threshold at mean brightness, high contrast |
| `none` | Raw threshold at 127, no diffusion |

---

#### `content_type: "black"` — Print a solid black block

Prints a filled black rectangle. Useful for separators or testing the connection.

```json
{
  "cmd": "print",
  "content_type": "black",
  "mm": 10.0,
  "energy": 65535
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `mm` | float | yes | Height of the block in millimeters |
| `energy` | int | no | Thermal energy, `0`–`65535` (default: `65535`) |

---

## Example (Python)

```python
import asyncio, json

async def daemon_send(req):
    reader, writer = await asyncio.open_unix_connection("/run/user/1000/scorchd.sock")
    payload = json.dumps(req).encode()
    writer.write(len(payload).to_bytes(4, "big") + payload)
    await writer.drain()
    length = int.from_bytes(await reader.readexactly(4), "big")
    resp = json.loads(await reader.readexactly(length))
    writer.close()
    return resp

asyncio.run(daemon_send({"cmd": "print", "content_type": "text", "text": "Hello!"}))
```

## Notes

- Jobs are serialized — the daemon processes one print at a time.
- If the printer is not connected when a job arrives, the job is rejected immediately with
  `{"ok": false, "error": "Printer not connected"}`. The daemon will reconnect
  automatically; retry after a moment.
- Print jobs can take several seconds depending on image size. Keep the connection open
  until the response arrives.
