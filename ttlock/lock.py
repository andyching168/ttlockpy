"""High-level TTLock BLE API.

Usage example::

    import asyncio, json
    from ttlock.lock import TTLock

    async def main():
        lock = TTLock.from_file("lock.json")
        async with lock:
            await lock.unlock()
            print("Battery:", lock.battery)
        lock.save("lock.json")

    asyncio.run(main())
"""

import asyncio
import json
import os
import random
import time
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path

from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError

from .const import (
    DEFAULT_AES_KEY, WRITE_CHAR_UUID, NOTIFY_CHAR_UUID,
    BLE_MTU, CommandType, CommandResponse, LockedStatus,
    FeatureValue, KeyboardPwdType, ICOperate,
)
from .protocol import LockProtocol, build_packet, parse_response, split_into_chunks
from . import commands as cmd


# ---------------------------------------------------------------------------
# Lock data (persisted to JSON)
# ---------------------------------------------------------------------------

@dataclass
class LockData:
    """All data needed to connect and authenticate with a paired lock."""
    address: str = ""            # BLE address
    name: str = "TTLock"
    mac: str = ""                # Physical MAC from manufacturer data
    battery: int = -1
    locked_status: int = int(LockedStatus.UNKNOWN)
    auto_lock_time: int = -1
    # Protocol parameters (from manufacturer data)
    protocol_type: int = 5
    protocol_version: int = 3
    scene: int = 1
    # Credentials obtained during pairing
    aes_key: str = ""            # hex-encoded 16-byte key
    admin_ps: int = 0
    unlock_key: int = 0
    admin_passcode: str = ""

    def is_paired(self) -> bool:
        return bool(self.aes_key and self.admin_ps and self.unlock_key)

    def get_aes_key(self) -> bytes:
        if self.aes_key:
            return bytes.fromhex(self.aes_key)
        return DEFAULT_AES_KEY

    def get_protocol(self) -> LockProtocol:
        # Keep protocol fields aligned with ttlock-sdk-js LockVersion mapping.
        # Some locks advertise scene=2, but commands are accepted only with the
        # canonical scene for that protocol family (e.g. V3 -> scene 1).
        protocol_type = self.protocol_type
        protocol_version = self.protocol_version
        scene = self.scene
        group_id = 1
        org_id = 1

        if protocol_type == 5 and protocol_version == 3:
            # V3 car is scene 7; regular V3 uses scene 1.
            scene = 7 if scene == 7 else 1
        elif protocol_type == 5 and protocol_version in (1, 4):
            scene = 1
        elif protocol_type == 10 and protocol_version == 1:
            scene = 7
        elif protocol_type == 11 and protocol_version == 1:
            scene = 1
        elif protocol_type == 3:
            scene = 0
            group_id = 0
            org_id = 0

        return LockProtocol(
            protocol_type    = protocol_type,
            protocol_version = protocol_version,
            scene            = scene,
            group_id         = group_id,
            org_id           = org_id,
        )


# ---------------------------------------------------------------------------
# Main TTLock class
# ---------------------------------------------------------------------------

class TTLock:
    """Bluetooth interface for a single TTLock device.

    After construction, call `connect()` (or use the async context manager)
    before calling any operation methods.
    """

    def __init__(self, data: LockData):
        self.data = data
        self._client: BleakClient | None = None
        self._rx_buffer = bytearray()
        self._response_queue: asyncio.Queue = asyncio.Queue()
        self.battery: int = data.battery
        self.debug: bool = os.getenv("TTLOCK_DEBUG", "0") == "1"

    def _dbg(self, msg: str) -> None:
        if self.debug:
            print(f"[TTLOCK-DEBUG] {msg}")

    # ------------------------------------------------------------------
    # Factory helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_file(cls, path: str | Path) -> "TTLock":
        with open(path) as f:
            raw = json.load(f)
        return cls(LockData(**raw))

    @classmethod
    def from_address(cls, address: str, name: str = "TTLock") -> "TTLock":
        return cls(LockData(address=address, name=name))

    def save(self, path: str | Path) -> None:
        with open(path, "w") as f:
            json.dump(asdict(self.data), f, indent=2)

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    async def connect(self, timeout: float = 15.0) -> None:
        """Connect to the lock and subscribe to notifications.

        On macOS/CoreBluetooth, service discovery can intermittently drop right
        after connection. We retry with a short scan fallback to resolve the
        current BLEDevice reference before giving up.
        """
        last_error: Exception | None = None
        
        # Reset internal buffers on fresh connect attempt
        self._rx_buffer.clear()
        while not self._response_queue.empty():
            self._response_queue.get_nowait()

        for attempt in range(3):
            try:
                self._dbg(
                    f"connect attempt={attempt+1} addr={self.data.address} "
                    f"mac={self.data.mac or '-'} name={self.data.name or '-'}"
                )
                # Refresh BLEDevice reference when possible. This helps with
                # transient CoreBluetooth "disconnected" during service discovery.
                device = await BleakScanner.find_device_by_address(
                    self.data.address, timeout=min(timeout, 5.0)
                )
                client_target = device if device is not None else self.data.address

                if device is None:
                    # Address can become stale on some platforms (notably macOS).
                    # The lock may be sleeping and not advertising continuously.
                    # We poll with longer scan windows to catch the lock's advertisement
                    # bursts (lock typically advertises once per second when in remote mode).
                    self._dbg(f"device not found, polling for lock to advertise...")
                    discovered: DiscoveredLock | None = None
                    poll_count = max(2, int(timeout / 3))
                    for i in range(poll_count):
                        try:
                            from .scanner import discover_locks
                            found = await discover_locks(timeout=3.0)
                            mac_upper = self.data.mac.upper() if self.data.mac else ""
                            by_mac = next(
                                (d for d in found if mac_upper and d.mac.upper() == mac_upper),
                                None,
                            )
                            by_name = next(
                                (d for d in found if self.data.name and d.name == self.data.name),
                                None,
                            )
                            discovered = by_mac or by_name
                            if discovered is not None:
                                self._dbg(f"lock found on poll {i+1}/{poll_count}")
                                break
                        except Exception as e:
                            self._dbg(f"scan poll {i+1} failed: {e}")
                        # Wait a bit between scans to let lock send another advertisement burst
                        if i + 1 < poll_count:
                            await asyncio.sleep(1.5)

                    if discovered is not None:
                        self._dbg(
                            f"refresh addr via scan old={self.data.address} new={discovered.address}"
                        )
                        self.data.address = discovered.address
                        if discovered.mac:
                            self.data.mac = discovered.mac
                        device = discovered.device
                        client_target = device if device is not None else self.data.address
                    else:
                        self._dbg("lock did not wake up within timeout")

                self._client = BleakClient(client_target, timeout=timeout)
                await self._client.connect()
                try:
                    await self._client.read_gatt_char(NOTIFY_CHAR_UUID)
                except Exception:
                    pass
                await self._client.start_notify(NOTIFY_CHAR_UUID, self._on_notification)
                self._dbg("connect success + notify subscribed")
                return
            except Exception as error:
                self._dbg(f"connect attempt={attempt+1} failed: {error}")
                last_error = error
                try:
                    await self.disconnect()
                except Exception:
                    pass
                if attempt < 2:
                    await asyncio.sleep(0.6)

        raise BleakError(f"Failed to connect after retries: {last_error}")

    async def disconnect(self) -> None:
        if self._client:
            try:
                if self._client.is_connected:
                    await self._client.stop_notify(NOTIFY_CHAR_UUID)
            except Exception:
                pass
            try:
                await self._client.disconnect()
            except Exception:
                pass
        self._client = None

    @property
    def is_connected(self) -> bool:
        return self._client is not None and self._client.is_connected

    async def __aenter__(self) -> "TTLock":
        await self.connect()
        return self

    async def __aexit__(self, *_) -> None:
        await self.disconnect()

    # ------------------------------------------------------------------
    # BLE I/O
    # ------------------------------------------------------------------

    def _on_notification(self, _handle: int, data: bytes) -> None:
        """Accumulate incoming BLE chunks and dispatch complete frames."""
        self._rx_buffer.extend(data)
        if self._rx_buffer[-2:] == b"\r\n":
            frame = bytes(self._rx_buffer)
            self._rx_buffer.clear()
            self._dbg(f"RX frame len={len(frame)} hex={frame.hex()}")
            self._response_queue.put_nowait(frame)

    async def _send_command(
        self,
        cmd_type: CommandType,
        payload: bytes,
        aes_key: bytes | None = None,
        wait_response: bool = True,
        ignore_crc: bool = False,
        require_success: bool = True,
    ) -> dict | None:
        """Build, send, and optionally await a lock command."""
        proto = self.data.get_protocol()
        packet = build_packet(proto, int(cmd_type), payload, aes_key)
        cmd_name = cmd_type.name if hasattr(cmd_type, "name") else f"0x{int(cmd_type):02X}"
        self._dbg(
            f"TX {cmd_name} scene={proto.scene} group={proto.group_id} org={proto.org_id} "
            f"payload_len={len(payload)} packet_len={len(packet)}"
        )

        # Clear any stale responses left over from previous commands
        while not self._response_queue.empty():
            self._response_queue.get_nowait()

        for attempt in range(3):
            # Drain any stale notifications that arrived before we sent this command.
            while not self._response_queue.empty():
                self._response_queue.get_nowait()

            started = time.monotonic()
            for chunk in split_into_chunks(packet):
                self._dbg(f"TX chunk attempt={attempt+1} len={len(chunk)} hex={chunk.hex()}")
                await self._client.write_gatt_char(WRITE_CHAR_UUID, chunk, response=True)

            if not wait_response:
                return None

            try:
                while True:
                    time_left = 8.0 - (time.monotonic() - started)
                    if time_left <= 0:
                        raise asyncio.TimeoutError()
                    
                    frame = await asyncio.wait_for(self._response_queue.get(), timeout=time_left)
                    parsed = parse_response(frame, aes_key=aes_key, ignore_crc=ignore_crc)
                    elapsed_ms = int((time.monotonic() - started) * 1000)
                    
                    self._dbg(
                        f"RX parsed {cmd_name} attempt={attempt+1} elapsed={elapsed_ms}ms "
                        f"resp=0x{parsed['response']:02X} crc_ok={parsed['crc_ok']} data_len={len(parsed['data'])}"
                    )
                    
                    if parsed["cmd_type"] in (int(cmd_type), 0x54):
                        break
                    else:
                        self._dbg(f"Ignoring unrelated frame (cmd_type=0x{parsed['cmd_type']:02X})")
            except asyncio.TimeoutError:
                self._dbg(f"RX timeout {cmd_name} attempt={attempt+1}")
                if attempt < 2:
                    await asyncio.sleep(0.2)
                    continue
                raise TimeoutError(f"No response to command 0x{cmd_type:02X}")

            if not parsed["crc_ok"] and not ignore_crc:
                if attempt < 2:
                    self._dbg(f"CRC bad for {cmd_name}, retrying")
                    await asyncio.sleep(0.2)
                    continue
                raise RuntimeError(f"Command 0x{cmd_type:02X}: persistent CRC errors")

            if require_success and parsed["response"] != CommandResponse.SUCCESS:
                raise RuntimeError(
                    f"Command 0x{cmd_type:02X} failed "
                    f"(response=0x{parsed['response']:02X})"
                )

            return parsed

        raise RuntimeError(f"Command 0x{cmd_type:02X}: no valid response after retries")

    async def wait_for_notification(self, timeout: float = 30.0) -> dict | None:
        """Block until the lock sends an unsolicited notification (e.g. card scan)."""
        aes_key = self.data.get_aes_key() if self.data.is_paired() else None
        try:
            frame = await asyncio.wait_for(
                self._response_queue.get(), timeout=timeout
            )
            return parse_response(frame, aes_key=aes_key, ignore_crc=True)
        except asyncio.TimeoutError:
            return None

    # ------------------------------------------------------------------
    # Authentication helpers
    # ------------------------------------------------------------------

    async def _auth_check_user_time(self) -> int:
        """V3 auth: validate the time window, get psFromLock."""
        resp = await self._send_command(
            CommandType.CHECK_USER_TIME,
            cmd.build_check_user_time(),
            aes_key=self.data.get_aes_key(),
        )
        return cmd.parse_check_user_time(resp["data"])

    async def _auth_admin_login(self) -> int:
        """Older-protocol auth: verify admin identity, get psFromLock."""
        resp = await self._send_command(
            CommandType.CHECK_ADMIN,
            cmd.build_check_admin(self.data.admin_ps),
            aes_key=self.data.get_aes_key(),
        )
        ps_from_lock = cmd.parse_check_admin(resp["data"])
        await self._send_command(
            CommandType.CHECK_RANDOM,
            cmd.build_check_random(ps_from_lock, self.data.unlock_key),
            aes_key=self.data.get_aes_key(),
        )
        return ps_from_lock

    # ------------------------------------------------------------------
    # Pairing
    # ------------------------------------------------------------------

    async def pair(self) -> None:
        """Pair with a factory-fresh lock and store credentials in self.data.

        The lock must be in pairing/setting mode (LED blinking).
        """
        proto = self.data.get_protocol()

        # Step 1: Initialise (no AES key, no payload)
        await self._send_command(
            CommandType.INITIALIZATION,
            cmd.build_init(),
            aes_key=None,
            ignore_crc=True,
            require_success=False,
        )

        # Step 2: Get the lock's AES key (use default key)
        resp = await self._send_command(
            CommandType.GET_AES_KEY,
            cmd.build_get_aes_key(),
            aes_key=DEFAULT_AES_KEY,
        )
        aes_key = cmd.parse_aes_key(resp["data"])
        self.data.aes_key = aes_key.hex()

        # Step 3: Register admin credentials
        admin_ps   = random.randint(1, 99_999_999)
        unlock_key = random.randint(1, 99_999_999)
        await self._send_command(
            CommandType.ADD_ADMIN,
            cmd.build_add_admin(admin_ps, unlock_key),
            aes_key=aes_key,
        )
        self.data.admin_ps   = admin_ps
        self.data.unlock_key = unlock_key

        # Step 4: Calibrate clock (best-effort)
        try:
            await self._send_command(
                CommandType.TIME_CALIBRATE,
                cmd.build_calibrate_time(),
                aes_key=aes_key,
                ignore_crc=True,
            )
        except Exception:
            pass

        # Step 5: Query features
        resp = await self._send_command(
            CommandType.SEARCH_DEVICE_FEATURE,
            cmd.build_search_device_feature(),
            aes_key=aes_key,
        )
        features = cmd.parse_device_features(resp["data"])

        # Step 6: Get / set admin PIN
        if FeatureValue.GET_ADMIN_CODE in features:
            resp = await self._send_command(
                CommandType.GET_ADMIN_CODE,
                cmd.build_get_admin_code(),
                aes_key=aes_key,
            )
            admin_passcode = cmd.parse_admin_code(resp["data"])
            if not admin_passcode:
                admin_passcode = str(random.randint(1_000_000, 9_999_999))
                await self._send_command(
                    CommandType.SET_ADMIN_KEYBOARD_PWD,
                    cmd.build_set_admin_code(admin_passcode),
                    aes_key=aes_key,
                )
            self.data.admin_passcode = admin_passcode

        # Step 7: Signal end of pairing sequence
        await self._send_command(
            CommandType.OPERATE_FINISHED,
            cmd.build_operate_finished(),
            aes_key=aes_key,
        )

    # ------------------------------------------------------------------
    # Unlock / Lock / Status
    # ------------------------------------------------------------------

    async def unlock(self) -> None:
        """Unlock the lock."""
        ps_from_lock = await self._auth_check_user_time()
        resp = await self._send_command(
            CommandType.UNLOCK,
            cmd.build_unlock(ps_from_lock, self.data.unlock_key),
            aes_key=self.data.get_aes_key(),
        )
        parsed = cmd.parse_unlock(resp["data"])
        if "battery" in parsed:
            self.battery = parsed["battery"]
            self.data.battery = self.battery
        self.data.locked_status = int(LockedStatus.UNLOCKED)

    async def lock(self) -> None:
        """Lock the lock."""
        ps_from_lock = await self._auth_check_user_time()
        resp = await self._send_command(
            CommandType.FUNCTION_LOCK,
            cmd.build_lock(ps_from_lock, self.data.unlock_key),
            aes_key=self.data.get_aes_key(),
        )
        parsed = cmd.parse_lock(resp["data"])
        if "battery" in parsed:
            self.battery = parsed["battery"]
            self.data.battery = self.battery
        self.data.locked_status = int(LockedStatus.LOCKED)

    async def reset(self) -> None:
        """Factory-reset the lock (clears all credentials, returns to pairing mode)."""
        await self._auth_admin_login()
        await self._send_command(
            CommandType.RESET_LOCK,
            b"",
            aes_key=self.data.get_aes_key(),
            wait_response=False,
        )

    async def get_locked_status(self) -> LockedStatus:
        """Query the lock for its current locked/unlocked state."""
        last_resp: dict | None = None
        for attempt in range(2):
            # Auth step first to wake up the lock before querying status.
            await self._auth_check_user_time()
            resp = await self._send_command(
                CommandType.SEARCH_BICYCLE_STATUS,
                cmd.build_search_status(),
                aes_key=self.data.get_aes_key(),
                require_success=False,
            )
            last_resp = resp

            status = cmd.parse_search_status(resp["data"])
            if status != LockedStatus.UNKNOWN:
                self.data.locked_status = int(status)
                return status

            self._dbg(
                f"status query invalid resp=0x{resp['response']:02X} data={resp['data'].hex()} attempt={attempt+1}/2"
            )
            if attempt == 0:
                await asyncio.sleep(0.3)

        raise RuntimeError(
            f"Command 0x{int(CommandType.SEARCH_BICYCLE_STATUS):02X} failed "
            f"(response=0x{last_resp['response']:02X})"
        )

    # ------------------------------------------------------------------
    # Auto-lock
    # ------------------------------------------------------------------

    async def get_autolock_time(self) -> int:
        """Return the auto-lock delay in seconds (-1 if not supported)."""
        await self._auth_admin_login()
        resp = await self._send_command(
            CommandType.AUTO_LOCK_MANAGE,
            cmd.build_get_autolock(),
            aes_key=self.data.get_aes_key(),
        )
        seconds = cmd.parse_autolock(resp["data"])
        self.data.auto_lock_time = seconds
        return seconds

    async def set_autolock_time(self, seconds: int) -> None:
        """Set the auto-lock delay in seconds (0 disables auto-lock)."""
        await self._auth_admin_login()
        await self._send_command(
            CommandType.AUTO_LOCK_MANAGE,
            cmd.build_set_autolock(seconds),
            aes_key=self.data.get_aes_key(),
        )
        self.data.auto_lock_time = seconds

    # ------------------------------------------------------------------
    # Passage mode
    # ------------------------------------------------------------------

    async def get_passage_mode(self) -> list[dict]:
        """Return the list of configured passage-mode intervals."""
        await self._auth_admin_login()
        resp = await self._send_command(
            CommandType.CONFIGURE_PASSAGE_MODE,
            cmd.build_get_passage_mode(),
            aes_key=self.data.get_aes_key(),
            ignore_crc=True,
        )
        _, modes = cmd.parse_passage_modes(resp["data"])
        return modes

    async def add_passage_mode(
        self,
        pm_type: int,
        week_or_day: int,
        month: int,
        start_hour: str,
        end_hour: str,
    ) -> None:
        """Add a passage-mode entry.

        pm_type: 1=weekly, 2=monthly.
        week_or_day: 0=every day, 1-7=Mon-Sun (weekly) or 1-31 (monthly).
        month: 0 for weekly, month number for monthly.
        start_hour / end_hour: "HHMM" strings e.g. "0800".
        """
        await self._auth_admin_login()
        await self._send_command(
            CommandType.CONFIGURE_PASSAGE_MODE,
            cmd.build_set_passage_mode(pm_type, week_or_day, month,
                                       start_hour, end_hour),
            aes_key=self.data.get_aes_key(),
        )

    async def delete_passage_mode(
        self, pm_type: int, week_or_day: int, month: int,
        start_hour: str, end_hour: str,
    ) -> None:
        await self._auth_admin_login()
        await self._send_command(
            CommandType.CONFIGURE_PASSAGE_MODE,
            cmd.build_delete_passage_mode(pm_type, week_or_day, month,
                                          start_hour, end_hour),
            aes_key=self.data.get_aes_key(),
        )

    async def clear_passage_mode(self) -> None:
        """Remove all passage-mode entries."""
        await self._auth_admin_login()
        await self._send_command(
            CommandType.CONFIGURE_PASSAGE_MODE,
            cmd.build_clear_passage_mode(),
            aes_key=self.data.get_aes_key(),
        )

    # ------------------------------------------------------------------
    # PIN codes (keyboard passwords)
    # ------------------------------------------------------------------

    async def get_passcodes(self) -> list[dict]:
        """Return all stored PIN codes."""
        await self._auth_admin_login()
        all_codes: list[dict] = []
        sequence = 0
        while True:
            resp = await self._send_command(
                CommandType.PWD_LIST,
                cmd.build_list_passcodes(sequence),
                aes_key=self.data.get_aes_key(),
                ignore_crc=True,
                require_success=False,   # 0x00 = no passcodes or empty page
            )
            # resp may be None on zero-data frames; treat as end of list
            if resp is None or len(resp["data"]) < 4:
                break
            next_seq, codes = cmd.parse_passcodes(resp["data"])
            all_codes.extend(codes)
            if next_seq == 0 or not codes:
                break
            sequence = next_seq
        return all_codes

    async def add_passcode(
        self,
        passcode: str,
        pwd_type: KeyboardPwdType = KeyboardPwdType.PERMANENT,
        start_date: str = "000101000000",
        end_date: str   = "991231235900",
    ) -> bool:
        """Add a PIN code. Returns True on success."""
        await self._auth_admin_login()
        resp = await self._send_command(
            CommandType.MANAGE_KEYBOARD_PASSWORD,
            cmd.build_add_passcode(pwd_type, passcode, start_date, end_date),
            aes_key=self.data.get_aes_key(),
        )
        return True

    async def update_passcode(
        self,
        old_passcode: str,
        new_passcode: str,
        pwd_type: KeyboardPwdType = KeyboardPwdType.PERMANENT,
        start_date: str = "000101000000",
        end_date: str   = "991231235900",
    ) -> None:
        """Update an existing PIN code."""
        await self._auth_admin_login()
        await self._send_command(
            CommandType.MANAGE_KEYBOARD_PASSWORD,
            cmd.build_update_passcode(pwd_type, old_passcode, new_passcode,
                                      start_date, end_date),
            aes_key=self.data.get_aes_key(),
        )

    async def delete_passcode(
        self,
        passcode: str,
        pwd_type: KeyboardPwdType = KeyboardPwdType.PERMANENT,
    ) -> None:
        """Delete one PIN code."""
        await self._auth_admin_login()
        await self._send_command(
            CommandType.MANAGE_KEYBOARD_PASSWORD,
            cmd.build_delete_passcode(pwd_type, passcode),
            aes_key=self.data.get_aes_key(),
        )

    async def clear_passcodes(self) -> None:
        """Delete all PIN codes from the lock."""
        await self._auth_admin_login()
        await self._send_command(
            CommandType.MANAGE_KEYBOARD_PASSWORD,
            cmd.build_clear_passcodes(),
            aes_key=self.data.get_aes_key(),
        )

    # ------------------------------------------------------------------
    # IC cards
    # ------------------------------------------------------------------

    async def get_ic_cards(self) -> list[dict]:
        """Return all stored IC cards."""
        await self._auth_admin_login()
        all_cards: list[dict] = []
        sequence = 0
        while True:
            resp = await self._send_command(
                CommandType.IC_MANAGE,
                cmd.build_list_ic_cards(sequence),
                aes_key=self.data.get_aes_key(),
                ignore_crc=True,
                require_success=False,
            )
            if resp is None or resp["response"] == 0x00 or len(resp["data"]) < 2:
                break
            next_seq, cards = cmd.parse_ic_cards(resp["data"])
            all_cards.extend(cards)
            if next_seq == 0 or not cards:
                break
            sequence = next_seq
        return all_cards

    async def add_ic_card(
        self,
        start_date: str = "000101000000",
        end_date: str   = "991231235900",
    ) -> str:
        """Enter IC card enrolment mode and wait for a card to be scanned.

        Returns the scanned card number string.
        """
        await self._auth_admin_login()
        resp = await self._send_command(
            CommandType.IC_MANAGE,
            cmd.build_add_ic_card(),
            aes_key=self.data.get_aes_key(),
        )
        # Lock enters add mode; wait for card scan notification
        print("  Hold IC card near the lock...")
        notif = await self.wait_for_notification(timeout=30.0)
        if notif is None:
            raise TimeoutError("No IC card scanned within 30 seconds")
        card_number, status = cmd.parse_ic_card_add(notif["data"])
        if not card_number:
            raise RuntimeError("IC card add failed")
        return card_number

    async def update_ic_card(
        self, card_number: str,
        start_date: str, end_date: str,
    ) -> None:
        await self._auth_admin_login()
        await self._send_command(
            CommandType.IC_MANAGE,
            cmd.build_update_ic_card(card_number, start_date, end_date),
            aes_key=self.data.get_aes_key(),
        )

    async def delete_ic_card(self, card_number: str) -> None:
        await self._auth_admin_login()
        await self._send_command(
            CommandType.IC_MANAGE,
            cmd.build_delete_ic_card(card_number),
            aes_key=self.data.get_aes_key(),
        )

    async def clear_ic_cards(self) -> None:
        await self._auth_admin_login()
        await self._send_command(
            CommandType.IC_MANAGE,
            cmd.build_clear_ic_cards(),
            aes_key=self.data.get_aes_key(),
        )

    # ------------------------------------------------------------------
    # Fingerprints
    # ------------------------------------------------------------------

    async def get_fingerprints(self) -> list[dict]:
        """Return all stored fingerprints."""
        await self._auth_admin_login()
        all_fps: list[dict] = []
        sequence = 0
        while True:
            resp = await self._send_command(
                CommandType.FR_MANAGE,
                cmd.build_list_fingerprints(sequence),
                aes_key=self.data.get_aes_key(),
                ignore_crc=True,
                require_success=False,
            )
            if resp is None or resp["response"] == 0x00 or len(resp["data"]) < 2:
                break
            next_seq, fps = cmd.parse_fingerprints(resp["data"])
            all_fps.extend(fps)
            if next_seq == 0 or not fps:
                break
            sequence = next_seq
        return all_fps

    async def add_fingerprint(
        self,
        start_date: str = "000101000000",
        end_date: str   = "991231235900",
    ) -> str:
        """Enter fingerprint enrolment mode.

        Prompts the user to scan their finger multiple times.
        Returns the fingerprint ID string on success.
        """
        await self._auth_admin_login()
        resp = await self._send_command(
            CommandType.FR_MANAGE,
            cmd.build_add_fingerprint(),
            aes_key=self.data.get_aes_key(),
        )
        print("  Place your finger on the sensor (scan multiple times)...")
        fp_number = ""
        while True:
            notif = await self.wait_for_notification(timeout=30.0)
            if notif is None:
                raise TimeoutError("Fingerprint enrolment timed out")
            fp_num, status = cmd.parse_fingerprint_add(notif["data"])
            if status == ICOperate.STATUS_FR_PROGRESS:
                print("  Scan again...")
                continue
            if status == ICOperate.STATUS_ADD_SUCCESS:
                fp_number = fp_num
                break
            raise RuntimeError(f"Fingerprint add failed (status={status})")
        return fp_number

    async def update_fingerprint(
        self, fp_number: str,
        start_date: str, end_date: str,
    ) -> None:
        await self._auth_admin_login()
        await self._send_command(
            CommandType.FR_MANAGE,
            cmd.build_update_fingerprint(fp_number, start_date, end_date),
            aes_key=self.data.get_aes_key(),
        )

    async def delete_fingerprint(self, fp_number: str) -> None:
        await self._auth_admin_login()
        await self._send_command(
            CommandType.FR_MANAGE,
            cmd.build_delete_fingerprint(fp_number),
            aes_key=self.data.get_aes_key(),
        )

    async def clear_fingerprints(self) -> None:
        await self._auth_admin_login()
        await self._send_command(
            CommandType.FR_MANAGE,
            cmd.build_clear_fingerprints(),
            aes_key=self.data.get_aes_key(),
        )

    # ------------------------------------------------------------------
    # Operation log
    # ------------------------------------------------------------------

    async def get_operation_log(self) -> list[dict]:
        """Retrieve all operation log entries from the lock."""
        resp = await self._send_command(
            CommandType.GET_OPERATE_LOG,
            cmd.build_get_operation_log(),
            aes_key=self.data.get_aes_key(),
        )
        _, entries = cmd.parse_operation_log(resp["data"])
        return entries
        
    # ------------------------------------------------------------------
    # Remote Unlock (Heartbeat Polling)
    # ------------------------------------------------------------------

    async def get_remote_unlock_status(self) -> bool:
        """Check if Remote Unlock feature is currently enabled on the lock."""
        await self._auth_admin_login()
        resp = await self._send_command(
            CommandType.CONTROL_REMOTE_UNLOCK,
            cmd.build_get_remote_unlock(),
            aes_key=self.data.get_aes_key(),
        )
        return cmd.parse_remote_unlock(resp["data"])
        
    async def set_remote_unlock(self, enabled: bool) -> None:
        """Enable or disable Remote Unlock.
        When enabled, the lock wakes up periodically to accept connections.
        """
        await self._auth_admin_login()
        await self._send_command(
            CommandType.CONTROL_REMOTE_UNLOCK,
            cmd.build_set_remote_unlock(enabled),
            aes_key=self.data.get_aes_key(),
        )
