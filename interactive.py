import asyncio
import json
import os
import sys

from bleak import BleakScanner
from ttlock import TTLock
from ttlock.scanner import _device_from_advertisement

last_state = {}

def on_event(device, adv, lock):
    global last_state
    
    lock_adv = _device_from_advertisement(device, adv)
    if not lock_adv or (lock_adv.address != lock.data.address and lock_adv.mac != lock.data.mac):
        return

    state_str = "🔓 UNLOCKED" if lock_adv.is_unlocked else "🔒 LOCKED"
    key = lock_adv.address
    
    if last_state.get(key) != lock_adv.is_unlocked:
        last_state[key] = lock_adv.is_unlocked
        print(f"\r\n📡 [Passive listen update] {state_str} (Battery {lock_adv.battery}%)")
        print("ttlock> ", end="", flush=True)

async def interactive_shell(lock, scanner):
    print("\n✅ Connected! Entering Interactive Mode.")
    print("In this mode, the Bluetooth connection stays open and you can run commands continuously.")
    print("=" * 60)
    print("Available commands:")
    print("  unlock             - Unlock the lock")
    print("  lock               - Lock the lock")
    print("  status             - Get current lock status")
    print("  pin list           - List all PIN codes")
    print("  pin clear          - Clear all PIN codes")
    print("  card list          - List all IC cards")
    print("  card add           - Add new IC card")
    print("  fingerprint list   - List all fingerprints")
    print("  fingerprint add    - Add new fingerprint")
    print("  autolock set <sec> - Set auto-lock time in seconds (0 to disable)")
    print("  remote on/off      - Enable/disable remote unlock (heartbeat mode for seamless local access)")
    print("  remote status      - Check remote unlock status")
    print("  log                - Get operation log")
    print("  exit / quit        - Disconnect and exit")
    print("=" * 60)

    loop = asyncio.get_running_loop()

    while True:
        try:
            # 使用 executor 來允許非阻塞的標準輸入
            line = await loop.run_in_executor(None, input, "\nttlock> ")
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            cmd = parts[0].lower()

            if cmd in ("exit", "quit"):
                break

            # 自動偵測是否被鎖體切斷連線，如有中斷則嘗試重連
            if not lock.is_connected:
                print("⚠️ Lock is sleeping or connection lost, auto-reconnecting...")
                retry_count = 0
                max_retries = 3
                while retry_count < max_retries:
                    try:
                        await scanner.stop()  # Pause listening to avoid macOS CoreBluetooth resource conflicts
                        # Wait 1-2 seconds to give lock a chance to wake up
                        await asyncio.sleep(1.5)
                        await lock.connect()
                        print("✅ Reconnected successfully!")
                        break
                    except Exception as e:
                        retry_count += 1
                        if retry_count < max_retries:
                            print(f"⚠️ Attempt {retry_count}/{max_retries} failed, retrying... ({e})")
                            await asyncio.sleep(2)
                        else:
                            print(f"❌ Reconnection failed: {e}")
                            await scanner.start()
                            continue
                if retry_count >= max_retries:
                    continue

            # 暫停被動監聽，把唯一的收發通道單純留給主動指令
            try:
                await scanner.stop()
            except Exception:
                pass

            try:
                if cmd == "unlock":
                    print("Unlocking...")
                    await lock.unlock()
                    print("✅ Lock unlocked")
    
                elif cmd == "lock":
                    print("Locking...")
                    await lock.lock()
                    print("✅ Lock locked")
    
                elif cmd == "status":
                    status_ok = False
                    last_err: Exception | None = None
                    for i in range(3):
                        try:
                            s = await lock.get_locked_status()
                            print(f"✅ Current status: {s.name}")
                            status_ok = True
                            break
                        except Exception as e:
                            last_err = e
                            msg = str(e)
                            # SEARCH_BICYCLE_STATUS can fail right after wake/reconnect.
                            if "Command 0x14 failed" not in msg:
                                raise

                            if i < 2:
                                print("⚠️ Status query not ready, retrying...")
                                try:
                                    await lock.disconnect()
                                except Exception:
                                    pass
                                await asyncio.sleep(0.6)
                                await lock.connect(timeout=20.0)
                                await asyncio.sleep(0.4)

                    if not status_ok and last_err is not None:
                        raise last_err
    
                elif cmd == "pin":
                    if len(parts) > 1 and parts[1] == "list":
                        codes = await lock.get_passcodes()
                        print(json.dumps(codes, indent=2))
                    elif len(parts) > 1 and parts[1] == "clear":
                        await lock.clear_passcodes()
                        print("✅ All PIN codes cleared")
                    else:
                        print("Usage: pin list | pin clear")
    
                elif cmd == "card":
                    if len(parts) > 1 and parts[1] == "list":
                        cards = await lock.get_ic_cards()
                        print(json.dumps(cards, indent=2))
                    elif len(parts) > 1 and parts[1] == "add":
                        print("Please bring IC card closer to the lock scanner...")
                        card_num = await lock.add_ic_card()
                        print(f"✅ Card added successfully, Card number: {card_num}")
                    else:
                        print("Usage: card list | card add")
    
                elif cmd == "fingerprint":
                    if len(parts) > 1 and parts[1] == "list":
                        fps = await lock.get_fingerprints()
                        print(json.dumps(fps, indent=2))
                    elif len(parts) > 1 and parts[1] == "add":
                        print("Place your finger on the fingerprint scanner (may need to repeat)...")
                        fp_num = await lock.add_fingerprint()
                        print(f"✅ Fingerprint added successfully, ID: {fp_num}")
                    else:
                        print("Usage: fingerprint list | fingerprint add")
    
                elif cmd == "autolock":
                    if len(parts) > 2 and parts[1] == "set":
                        sec = int(parts[2])
                        await lock.set_autolock_time(sec)
                        print(f"✅ Auto-lock time set to {sec} seconds")
                    else:
                        print("Usage: autolock set <seconds>")
    
                elif cmd == "remote":
                    if len(parts) > 1 and parts[1] == "status":
                        enabled = await lock.get_remote_unlock_status()
                        print(f"✅ Remote unlock (heartbeat mode) status: {'[ENABLED]' if enabled else '[DISABLED]'}")
                    elif len(parts) > 1 and parts[1] in ("on", "off"):
                        enable = (parts[1] == "on")
                        await lock.set_remote_unlock(enable)
                        print(f"✅ Remote unlock successfully set to: {'ENABLED' if enable else 'DISABLED'}")
                    else:
                        print("Usage: remote status | remote on | remote off")
    
                elif cmd == "log":
                    logs = await lock.get_operation_log()
                    print(json.dumps(logs, indent=2))
    
                else:
                    print("Unknown command. Please refer to the available commands list above.")

            finally:
                try:
                    await scanner.start()
                except Exception:
                    pass

        except Exception as e:
            print(f"❌ Command execution error: {e}")

    print("Disconnecting...")
    await lock.disconnect()
    print("👋 Goodbye!")

async def main():
    if len(sys.argv) < 2:
        print("Startup error: Please provide the lock's auth file.")
        print("Usage: python interactive.py lock.json")
        sys.exit(1)

    lock_file = sys.argv[1]
    if not os.path.exists(lock_file):
        print(f"File not found: {lock_file}")
        sys.exit(1)

    lock = TTLock.from_file(lock_file)
    print(f"Preparing to connect to {lock.data.name} ({lock.data.address})...")
    print("Please gently tap the lock's keypad to wake it up, avoid letting it sleep!")
    
    try:
        await lock.connect()
    except Exception as e:
        print(f"Connection failed. Please wake up the lock and try again! Error details: {e}")
        sys.exit(1)

    # 啟動背景監聽任務
    def filter_event(device, adv):
        on_event(device, adv, lock)

    scanner = BleakScanner(detection_callback=filter_event)
    await scanner.start()

    try:
        await interactive_shell(lock, scanner)
    finally:
        await scanner.stop()

if __name__ == "__main__":
    # Suppress extra exception messages from Event Loop shutdown on macOS
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user.")
