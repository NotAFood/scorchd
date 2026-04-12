"""
iPrint Thermal Printer — Python client
Reverse-engineered from com.frogtosea.iprint (Shenzhen Frog To Sea Technology).

Protocol packet format:
  [0x51, 0x78, CMD, 0x00, DATA_LEN, 0x00, ...DATA..., CRC8(DATA), 0xFF]

BLE UUIDs:
  Service  : 0000ae30-0000-1000-8000-00805f9b34fb  (0000af30-... on some macOS)
  TX (Write): 0000ae01-0000-1000-8000-00805f9b34fb
  RX (Notify): 0000ae02-0000-1000-8000-00805f9b34fb

Print width : 384 px (48 bytes per row, 200 DPI)
Known names : GT01, GB01, GB02, GB03

Usage:
  scorchd photo.jpg
  scorchd "Hello!" --text
  scorchd note.png --device GT01 --energy 0x8000
  scorchd --scan
"""

import argparse
import asyncio
import contextlib
import json
import logging
import os
import signal
import sys
import uuid as _uuid_mod
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
log = logging.getLogger("iprint")

POSSIBLE_SERVICE_UUIDS = [
    "0000ae30-0000-1000-8000-00805f9b34fb",
    "0000af30-0000-1000-8000-00805f9b34fb",  # macOS Bluetooth stack sometimes advertises this variant
]
TX_CHARACTERISTIC_UUID = "0000ae01-0000-1000-8000-00805f9b34fb"
RX_CHARACTERISTIC_UUID = "0000ae02-0000-1000-8000-00805f9b34fb"
PRINTER_READY_NOTIFICATION = bytes(
    [0x51, 0x78, 0xAE, 0x01, 0x01, 0x00, 0x00, 0x00, 0xFF]
)

SCAN_TIMEOUT_S = 10
WAIT_AFTER_CHUNK_S = 0.02
WAIT_FOR_DONE_TIMEOUT_S = 30

PRINT_WIDTH = 384
SOCKET_PATH = os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/tmp"), "scorchd.sock")

# Lookup table for the custom CRC-8 variant used by this protocol.
# Values extracted from BluetoothOrder.calcCrc8() in the decompiled APK (Java signed → Python unsigned).
_CRC8_TABLE = bytearray(
    [
        0,
        7,
        14,
        9,
        28,
        27,
        18,
        21,
        56,
        63,
        54,
        49,
        36,
        35,
        42,
        45,
        112,
        119,
        126,
        121,
        108,
        107,
        98,
        101,
        72,
        79,
        70,
        65,
        84,
        83,
        90,
        93,
        224,
        231,
        238,
        233,
        252,
        251,
        242,
        245,
        216,
        223,
        214,
        209,
        196,
        195,
        202,
        205,
        144,
        151,
        158,
        153,
        140,
        139,
        130,
        133,
        168,
        175,
        166,
        161,
        180,
        179,
        186,
        189,
        199,
        192,
        201,
        206,
        219,
        220,
        213,
        210,
        255,
        248,
        241,
        246,
        227,
        228,
        237,
        234,
        183,
        176,
        185,
        190,
        171,
        172,
        165,
        162,
        143,
        136,
        129,
        134,
        147,
        148,
        157,
        154,
        39,
        32,
        41,
        46,
        59,
        60,
        53,
        50,
        31,
        24,
        17,
        22,
        3,
        4,
        13,
        10,
        87,
        80,
        89,
        94,
        75,
        76,
        69,
        66,
        111,
        104,
        97,
        102,
        115,
        116,
        125,
        122,
        137,
        142,
        135,
        128,
        149,
        146,
        155,
        156,
        177,
        182,
        191,
        184,
        173,
        170,
        163,
        164,
        249,
        254,
        247,
        240,
        229,
        226,
        235,
        236,
        193,
        198,
        207,
        200,
        221,
        218,
        211,
        212,
        105,
        110,
        103,
        96,
        117,
        114,
        123,
        124,
        81,
        86,
        95,
        88,
        77,
        74,
        67,
        68,
        25,
        30,
        23,
        16,
        5,
        2,
        11,
        12,
        33,
        38,
        47,
        40,
        61,
        58,
        51,
        52,
        78,
        73,
        64,
        71,
        82,
        85,
        92,
        91,
        118,
        113,
        120,
        127,
        106,
        109,
        100,
        99,
        62,
        57,
        48,
        55,
        34,
        37,
        44,
        43,
        6,
        1,
        8,
        15,
        26,
        29,
        20,
        19,
        174,
        169,
        160,
        167,
        178,
        181,
        188,
        187,
        150,
        145,
        152,
        159,
        138,
        141,
        132,
        131,
        222,
        217,
        208,
        215,
        194,
        197,
        204,
        203,
        230,
        225,
        232,
        239,
        250,
        253,
        244,
        243,
    ]
)


def _crc8(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc = _CRC8_TABLE[(crc ^ byte) & 0xFF]
    return crc & 0xFF


def _packet(cmd: int, data: bytes) -> bytes:
    header = bytes([0x51, 0x78, cmd, 0x00, len(data) & 0xFF, 0x00])
    return header + data + bytes([_crc8(data), 0xFF])


def cmd_get_dev_state() -> bytes:
    return _packet(0xA3, bytes([0x00]))


def cmd_set_quality_200dpi() -> bytes:
    return _packet(0xA4, bytes([0x32]))


def cmd_set_energy(val: int) -> bytes:
    """val: 0x0000 (faint) … 0xFFFF (darkest, default)"""
    return _packet(0xAF, bytes([(val >> 8) & 0xFF, val & 0xFF]))


def cmd_apply_energy() -> bytes:
    return _packet(0xBE, bytes([0x01]))


def cmd_lattice_start() -> bytes:
    return _packet(
        0xA6, bytes([0xAA, 0x55, 0x17, 0x38, 0x44, 0x5F, 0x5F, 0x5F, 0x44, 0x38, 0x2C])
    )


def cmd_lattice_end() -> bytes:
    return _packet(
        0xA6, bytes([0xAA, 0x55, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17])
    )


def cmd_set_paper() -> bytes:
    return _packet(0xA1, bytes([0x30, 0x00]))


def cmd_feed_paper(amount: int = 25) -> bytes:
    return _packet(0xBD, bytes([amount & 0xFF]))


def _run_length_encode(row: list) -> list:
    result, count, last_val = [], 0, -1
    for val in row:
        if val == last_val:
            count += 1
        else:
            while count > 0x7F:
                result.append(0x7F | (last_val << 7))
                count -= 0x7F
            if count > 0:
                result.append((last_val << 7) | count)
            count = 1
        last_val = val
    while count > 0x7F:
        result.append(0x7F | (last_val << 7))
        count -= 0x7F
    if count > 0:
        result.append((last_val << 7) | count)
    return result


def _byte_encode(row: list) -> list:
    result = []
    for chunk_start in range(0, len(row), 8):
        byte = 0
        for bit in range(8):
            if row[chunk_start + bit]:
                byte |= 1 << bit
        result.append(byte)
    return result


def cmd_print_row(row: list) -> bytes:
    rle = _run_length_encode(row)
    if len(rle) <= PRINT_WIDTH // 8:
        return _packet(0xBF, bytes(rle))  # run-length compressed row
    return _packet(0xA2, bytes(_byte_encode(row)))  # raw 1-bit-per-pixel row


def build_print_commands(img_rows: list, energy: int = 0xFFFF) -> bytes:
    data = bytearray()
    data += cmd_get_dev_state()
    data += cmd_set_quality_200dpi()
    data += cmd_set_energy(energy)
    data += cmd_apply_energy()
    data += cmd_lattice_start()
    for row in img_rows:
        data += cmd_print_row(row)
    data += cmd_feed_paper(25)
    data += cmd_set_paper()
    data += cmd_set_paper()
    data += cmd_set_paper()
    data += cmd_lattice_end()
    data += cmd_get_dev_state()
    return bytes(data)


def _floyd_steinberg(img):
    import numpy as np

    h, w = img.shape
    for y in range(h):
        for x in range(w):
            old = img[y, x]
            new = 255.0 if old > 127 else 0.0
            err = old - new
            img[y, x] = new
            if x + 1 < w:
                img[y, x + 1] = np.clip(img[y, x + 1] + err * 7 / 16, 0, 255)
            if y + 1 < h:
                if x - 1 >= 0:
                    img[y + 1, x - 1] = np.clip(
                        img[y + 1, x - 1] + err * 3 / 16, 0, 255
                    )
                img[y + 1, x] = np.clip(img[y + 1, x] + err * 5 / 16, 0, 255)
                if x + 1 < w:
                    img[y + 1, x + 1] = np.clip(
                        img[y + 1, x + 1] + err * 1 / 16, 0, 255
                    )
    return img


def _atkinson(img):
    import numpy as np

    h, w = img.shape
    for y in range(h):
        for x in range(w):
            old = img[y, x]
            new = 255.0 if old > 127 else 0.0
            err = (old - new) / 8
            img[y, x] = new
            for dy, dx in [(0, 1), (0, 2), (1, -1), (1, 0), (1, 1), (2, 0)]:
                ny, nx = y + dy, x + dx
                if 0 <= ny < h and 0 <= nx < w:
                    img[ny, nx] = np.clip(img[ny, nx] + err, 0, 255)
    return img


def load_image(path: str, algo: str = "floyd-steinberg") -> list:
    try:
        from PIL import Image
        import numpy as np
    except ImportError:
        log.error("🛑 Pillow and numpy are required. Run: uv pip install Pillow numpy")
        sys.exit(1)

    img = Image.open(path).convert("L")
    w, h = img.size
    img = img.resize((PRINT_WIDTH, int(h * PRINT_WIDTH / w)), Image.LANCZOS)
    arr = np.array(img, dtype=np.float32)

    if algo == "floyd-steinberg":
        arr = _floyd_steinberg(arr)
        binary = arr > 127
    elif algo == "atkinson":
        arr = _atkinson(arr)
        binary = arr > 127
    elif algo == "threshold":
        binary = arr > arr.mean()
    elif algo == "none":
        binary = arr > 127
    else:
        raise ValueError(f"Unknown algorithm: {algo}")

    # Thermal paper burns dark: True = print this dot (inverted from image lightness)
    return (~binary).tolist()


def text_to_image(text: str, font_size: int = 24) -> list:
    try:
        from PIL import Image, ImageDraw, ImageFont
        import numpy as np
    except ImportError:
        log.error("🛑 Pillow is required. Run: uv pip install Pillow")
        sys.exit(1)

    font = None
    for fp in [
        "/System/Library/Fonts/Helvetica.ttc",
        "/System/Library/Fonts/Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    ]:
        try:
            font = ImageFont.truetype(fp, font_size)
            break
        except (OSError, IOError):
            continue
    if font is None:
        font = ImageFont.load_default()

    dummy_draw = ImageDraw.Draw(Image.new("L", (PRINT_WIDTH, 1), 255))
    bbox = dummy_draw.textbbox((0, 0), text, font=font)
    text_w, text_h = bbox[2] - bbox[0], bbox[3] - bbox[1]

    padding = 8
    img = Image.new("L", (PRINT_WIDTH, text_h + padding * 2), 255)
    draw = ImageDraw.Draw(img)
    draw.text((max(0, (PRINT_WIDTH - text_w) // 2), padding), text, font=font, fill=0)

    arr = np.array(img, dtype=np.float32)
    return (~(arr > 127)).tolist()


def make_solid_black_rows(mm: float) -> list:
    # 200 DPI -> ~8 dots per mm
    n_rows = int(mm * 8)
    return [[1] * PRINT_WIDTH for _ in range(n_rows)]


async def _scan_for_printer(name: Optional[str], timeout: int):
    from bleak import BleakScanner
    from bleak.backends.scanner import AdvertisementData
    from bleak.backends.device import BLEDevice

    if name:
        log.info(f"⏳ Scanning for BLE device named '{name}'...")
    else:
        log.info("⏳ Auto-scanning for printer by service UUID...")

    def _filter(device: BLEDevice, adv: AdvertisementData) -> bool:
        if name:
            return device.name == name
        return any(u in adv.service_uuids for u in POSSIBLE_SERVICE_UUIDS)

    device = await BleakScanner.find_device_by_filter(_filter, timeout=timeout)
    if device is None:
        raise RuntimeError("Printer not found. Make sure it's powered on and in range.")
    log.info(f"✅ Found: {device}")
    return device


async def _resolve_address(device_arg: Optional[str]):
    if device_arg:
        # Accept a raw UUID (macOS format) or colon-separated MAC (Linux format) directly
        with contextlib.suppress(ValueError):
            return str(_uuid_mod.UUID(device_arg))
        if device_arg.count(":") == 5 and device_arg.replace(":", "").isalnum():
            return device_arg
    return await _scan_for_printer(device_arg or None, timeout=SCAN_TIMEOUT_S)


def _notify_factory(event: asyncio.Event):
    def _on_notify(sender, data):
        log.debug(f"📡 Notification {sender}: {data.hex()}")
        if bytes(data) == PRINTER_READY_NOTIFICATION:
            log.info("✅ Printer ready.")
            event.set()

    return _on_notify


async def _maybe_acquire_mtu(client) -> None:
    """BlueZ mis-reports MTU as 23; force negotiation to get the real value."""
    try:
        from bleak.backends.bluezdbus.client import BleakClientBlueZDBus

        if isinstance(client, BleakClientBlueZDBus):
            await client._acquire_mtu()
    except ImportError:
        pass


async def _transmit(client, data: bytes, done_event: asyncio.Event) -> None:
    chunk_size = client.mtu_size - 3
    chunks = [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]
    log.info(f"⏳ Sending {len(data)} bytes in {len(chunks)} chunks of {chunk_size}...")
    for chunk in chunks:
        await client.write_gatt_char(TX_CHARACTERISTIC_UUID, chunk, response=False)
        await asyncio.sleep(WAIT_AFTER_CHUNK_S)
    log.info("⏳ Waiting for printer to finish...")
    try:
        await asyncio.wait_for(done_event.wait(), timeout=WAIT_FOR_DONE_TIMEOUT_S)
    except asyncio.TimeoutError:
        log.warning("⚠️  Timed out waiting for printer-ready signal. Print may still have succeeded.")


async def printer_daemon(
    device_arg: Optional[str] = None,
    interval: int = 30,
    socket_path: str = SOCKET_PATH,
):
    from bleak import BleakClient

    state: dict = {"client": None, "done_event": asyncio.Event()}
    lock = asyncio.Lock()

    async def _connection_loop():
        address = await _resolve_address(device_arg)
        while True:
            try:
                client = BleakClient(address)
                await client.connect()
                await _maybe_acquire_mtu(client)
                log.info(f"✅ Connected  |  MTU: {client.mtu_size}")
                state["client"] = client

                def _on_notify(_sender, data):
                    log.debug(f"📡 Notification: {data.hex()}")
                    if bytes(data) == PRINTER_READY_NOTIFICATION:
                        log.info("✅ Printer ready.")
                        state["done_event"].set()

                await client.start_notify(RX_CHARACTERISTIC_UUID, _on_notify)

                while client.is_connected:
                    await asyncio.sleep(1)

                state["client"] = None
                with contextlib.suppress(Exception):
                    await client.disconnect()
                log.warning("⚠️  Disconnected. Reconnecting in 5s...")
            except asyncio.CancelledError:
                if state["client"]:
                    with contextlib.suppress(Exception):
                        await state["client"].disconnect()
                return
            except Exception as e:
                log.warning(f"⚠️  Connection error ({e}). Reconnecting in 5s...")
                state["client"] = None
            await asyncio.sleep(5)

    async def _heartbeat_loop():
        while True:
            await asyncio.sleep(interval)
            client = state["client"]
            if client and client.is_connected:
                try:
                    log.info("💓 Heartbeat...")
                    await client.write_gatt_char(
                        TX_CHARACTERISTIC_UUID, cmd_get_dev_state(), response=False
                    )
                except Exception as e:
                    log.warning(f"⚠️  Heartbeat failed: {e}")

    async def _handle_connection(reader, writer):
        try:
            header = await reader.readexactly(4)
            length = int.from_bytes(header, "big")
            payload = await reader.readexactly(length)
            req = json.loads(payload)

            cmd = req.get("cmd")

            if cmd == "status":
                client = state["client"]
                resp: dict = {"connected": bool(client and client.is_connected)}

            elif cmd == "print":
                client = state["client"]
                if not client or not client.is_connected:
                    resp = {"ok": False, "error": "Printer not connected"}
                else:
                    try:
                        ct = req.get("content_type")
                        energy = req.get("energy", 0xFFFF)
                        if ct == "image":
                            rows = load_image(req["path"], algo=req.get("algo", "floyd-steinberg"))
                        elif ct == "text":
                            rows = text_to_image(req["text"], font_size=req.get("font_size", 24))
                        elif ct == "black":
                            rows = make_solid_black_rows(req["mm"])
                        else:
                            raise ValueError(f"Unknown content_type: {ct!r}")
                        data = build_print_commands(rows, energy=energy)
                        async with lock:
                            done_ev = asyncio.Event()
                            state["done_event"] = done_ev
                            await _transmit(client, data, done_ev)
                        resp = {"ok": True}
                    except Exception as e:
                        resp = {"ok": False, "error": str(e)}

            else:
                resp = {"ok": False, "error": f"Unknown command: {cmd!r}"}

            out = json.dumps(resp).encode()
            writer.write(len(out).to_bytes(4, "big") + out)
            await writer.drain()

        except Exception as e:
            log.warning(f"⚠️  Socket handler error: {e}")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    with contextlib.suppress(FileNotFoundError):
        os.unlink(socket_path)

    log.info(f"⏳ Daemon starting — socket: {socket_path}, heartbeat every {interval}s. Ctrl+C to stop.")

    stop = asyncio.Event()
    asyncio.get_event_loop().add_signal_handler(signal.SIGTERM, stop.set)

    server = await asyncio.start_unix_server(_handle_connection, path=socket_path)
    conn_task = asyncio.create_task(_connection_loop())
    hb_task = asyncio.create_task(_heartbeat_loop())

    async with server:
        await stop.wait()

    conn_task.cancel()
    hb_task.cancel()
    await asyncio.gather(conn_task, hb_task, return_exceptions=True)
    with contextlib.suppress(FileNotFoundError):
        os.unlink(socket_path)
    log.info("✅ Daemon stopped.")


async def send_to_printer(data: bytes, device_arg: Optional[str] = None):
    from bleak import BleakClient

    address = await _resolve_address(device_arg)
    log.info(f"⏳ Connecting to {address}...")

    async with BleakClient(address) as client:
        await _maybe_acquire_mtu(client)
        log.info(f"✅ Connected  |  MTU: {client.mtu_size}")
        done_event = asyncio.Event()
        await client.start_notify(RX_CHARACTERISTIC_UUID, _notify_factory(done_event))
        await _transmit(client, data, done_event)

    log.info("✅ Done.")


async def send_to_daemon(req: dict, socket_path: str = SOCKET_PATH) -> dict:
    reader, writer = await asyncio.open_unix_connection(socket_path)
    try:
        payload = json.dumps(req).encode()
        writer.write(len(payload).to_bytes(4, "big") + payload)
        await writer.drain()
        length = int.from_bytes(await reader.readexactly(4), "big")
        return json.loads(await reader.readexactly(length))
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def scan_and_list():
    from bleak import BleakScanner

    log.info("⏳ Scanning for BLE devices (10 s)...")
    devices = await BleakScanner.discover(timeout=10.0, return_adv=True)
    found = []
    for addr, (dev, adv) in devices.items():
        if any(u in adv.service_uuids for u in POSSIBLE_SERVICE_UUIDS) or (
            dev.name and dev.name.startswith(("GT", "GB"))
        ):
            found.append((dev.name, addr))
            log.info(f"  🖨️  {dev.name or '(unknown)'}  —  {addr}")
    if not found:
        log.info(
            "  No iPrint printers found. Make sure the printer is powered on and nearby."
        )
    return found


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scorchd",
        description="Print images or text on your iPrint BLE thermal printer.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  scorchd photo.jpg\n"
            '  scorchd "Hello!" --text\n'
            "  scorchd --black 20\n"
            "  scorchd note.png --device GT01 --energy 0x8000\n"
            "  scorchd --scan\n"
            "  scorchd --status\n"
            "  scorchd --daemon\n"
            "  scorchd --daemon 60 --socket /tmp/iprint.sock\n"
            "\n"
            "If the daemon is running, print commands are routed through it automatically."
        ),
    )
    p.add_argument(
        "content",
        nargs="?",
        default=None,
        help="Image file path, or text string (with --text).",
    )
    p.add_argument(
        "--text",
        "-t",
        action="store_true",
        help="Treat 'content' as a text string to render and print.",
    )
    p.add_argument(
        "--black",
        type=float,
        default=None,
        metavar="MM",
        help="Print a solid black block with height MM millimeters.",
    )
    p.add_argument(
        "--device",
        "-d",
        default=None,
        metavar="NAME_OR_ADDR",
        help="Printer BLE name (e.g. GT01) or address. Auto-discovers if omitted.",
    )
    p.add_argument(
        "--energy",
        "-e",
        default="0xffff",
        metavar="HEX",
        help="Thermal energy 0x0000 (faint) to 0xffff (dark, default).",
    )
    p.add_argument(
        "--algo",
        "-a",
        default="floyd-steinberg",
        choices=["floyd-steinberg", "atkinson", "threshold", "none"],
        help="Image binarization algorithm (default: floyd-steinberg).",
    )
    p.add_argument(
        "--font-size",
        type=int,
        default=24,
        metavar="N",
        help="Font size for --text mode (default: 24).",
    )
    p.add_argument(
        "--daemon",
        "-k",
        type=int,
        nargs="?",
        const=30,
        metavar="SECONDS",
        help="Run as a persistent daemon: hold BLE connection, heartbeat every SECONDS (default: 30), accept print jobs over a Unix socket.",
    )
    p.add_argument(
        "--socket",
        default=SOCKET_PATH,
        metavar="PATH",
        help=f"Unix socket path for --daemon mode (default: {SOCKET_PATH}).",
    )
    p.add_argument(
        "--status", action="store_true", help="Query the running daemon for printer status."
    )
    p.add_argument(
        "--scan", action="store_true", help="Scan for nearby iPrint printers and exit."
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Build commands but do not send them (for testing).",
    )
    p.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging.")
    return p


def main():
    parser = _build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        log.setLevel(logging.DEBUG)

    if args.scan:
        asyncio.run(scan_and_list())
        return

    if args.daemon is not None:
        asyncio.run(printer_daemon(device_arg=args.device, interval=args.daemon, socket_path=args.socket))
        return

    if args.status:
        resp = asyncio.run(send_to_daemon({"cmd": "status"}, socket_path=args.socket))
        log.info(f"🖨️  Printer connected: {resp.get('connected')}")
        return

    if args.black is not None and args.black <= 0:
        log.error("🛑 --black must be greater than 0.")
        sys.exit(1)

    if args.black is None and args.content is None:
        parser.print_help()
        sys.exit(1)

    try:
        energy = (
            int(args.energy, 16) if args.energy.startswith("0x") else int(args.energy)
        )
    except ValueError:
        log.error(f"🛑 Invalid --energy value: {args.energy!r}. Use hex like 0xffff.")
        sys.exit(1)

    if args.dry_run:
        if args.black is not None:
            rows = make_solid_black_rows(args.black)
        elif args.text:
            rows = text_to_image(args.content, font_size=args.font_size)
        else:
            rows = load_image(args.content, algo=args.algo)
        data = build_print_commands(rows, energy=energy)
        log.info(f"ℹ️  Dry-run — {len(data)} bytes, not sending.")
        return

    use_daemon = os.path.exists(args.socket)

    if use_daemon:
        log.info(f"ℹ️  Routing through daemon at {args.socket}")
        if args.black is not None:
            req: dict = {"cmd": "print", "content_type": "black", "mm": args.black, "energy": energy}
        elif args.text:
            req = {"cmd": "print", "content_type": "text", "text": args.content, "font_size": args.font_size, "energy": energy}
        else:
            if not os.path.isfile(args.content):
                log.error(f"🛑 File not found: {args.content!r}")
                sys.exit(1)
            req = {"cmd": "print", "content_type": "image", "path": os.path.abspath(args.content), "algo": args.algo, "energy": energy}
        resp = asyncio.run(send_to_daemon(req, socket_path=args.socket))
        if resp.get("ok"):
            log.info("✅ Done.")
        else:
            log.error(f"🛑 Daemon error: {resp.get('error')}")
            sys.exit(1)
    else:
        if args.black is not None:
            log.info(f"⏳ Building solid black block: {args.black} mm")
            rows = make_solid_black_rows(args.black)
            log.info(f"✅ Built: {len(rows)} rows × {PRINT_WIDTH} px")
        elif args.text:
            log.info(f"⏳ Rendering text: {args.content!r}")
            rows = text_to_image(args.content, font_size=args.font_size)
            log.info(f"✅ Rendered: {len(rows)} rows × {PRINT_WIDTH} px")
        else:
            if not os.path.isfile(args.content):
                log.error(f"🛑 File not found: {args.content!r}")
                sys.exit(1)
            log.info(f"⏳ Loading image: {args.content}")
            rows = load_image(args.content, algo=args.algo)
            log.info(f"✅ Loaded: {len(rows)} rows × {PRINT_WIDTH} px")
        data = build_print_commands(rows, energy=energy)
        log.info(f"✅ BLE payload: {len(data)} bytes")
        asyncio.run(send_to_printer(data, device_arg=args.device))


if __name__ == "__main__":
    main()
