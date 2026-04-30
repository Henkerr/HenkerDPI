"""
HenkerDPI V2 macOS - Service Manager (LaunchAgent)
"""

import sys
import os
import subprocess
import signal
import plistlib

SERVICE_NAME = "com.henkerr.henkerdpi.v2"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT_PATH = os.path.join(SCRIPT_DIR, "main.py")
PID_FILE = os.path.join(SCRIPT_DIR, "henkerdpi_v2.pid")
PLIST_PATH = os.path.expanduser(f"~/Library/LaunchAgents/{SERVICE_NAME}.plist")
PYTHON_PATH = sys.executable


def start():
    """Start HenkerDPI V2 in background."""
    if _is_running():
        print("[!] HenkerDPI V2 is already running.")
        return

    proc = subprocess.Popen(
        ["sudo", PYTHON_PATH, SCRIPT_PATH],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    with open(PID_FILE, "w") as f:
        f.write(str(proc.pid))
    print(f"[+] HenkerDPI V2 running in background (PID: {proc.pid})")


def stop():
    """Stop running HenkerDPI V2 process."""
    if not os.path.exists(PID_FILE):
        print("[-] HenkerDPI V2 is not running.")
        return

    with open(PID_FILE, "r") as f:
        pid = f.read().strip()

    if pid.isdigit():
        try:
            os.kill(int(pid), signal.SIGTERM)
            print(f"[-] HenkerDPI V2 stopped (PID: {pid})")
        except ProcessLookupError:
            print(f"[-] PID {pid} already stopped.")
        except PermissionError:
            # Root process — try sudo kill
            subprocess.run(["sudo", "kill", pid], capture_output=True)
            print(f"[-] HenkerDPI V2 stopped (PID: {pid})")

    try:
        os.remove(PID_FILE)
    except OSError:
        pass


def status():
    """Check if HenkerDPI V2 is running."""
    if _is_running():
        with open(PID_FILE, "r") as f:
            pid = f.read().strip()
        print(f"[+] HenkerDPI V2 is running (PID: {pid})")
    else:
        print("[-] HenkerDPI V2 is not running.")


def restart():
    """Restart HenkerDPI V2."""
    stop()
    start()


def install():
    """Add HenkerDPI V2 to macOS login items via LaunchAgent."""
    plist = {
        "Label": SERVICE_NAME,
        "ProgramArguments": ["sudo", PYTHON_PATH, SCRIPT_PATH],
        "RunAtLoad": True,
        "KeepAlive": False,
        "StandardOutPath": os.path.join(SCRIPT_DIR, "henkerdpi_v2.log"),
        "StandardErrorPath": os.path.join(SCRIPT_DIR, "henkerdpi_v2_err.log"),
    }

    # LaunchAgents dizinini olustur
    launch_dir = os.path.dirname(PLIST_PATH)
    os.makedirs(launch_dir, exist_ok=True)

    with open(PLIST_PATH, "wb") as f:
        plistlib.dump(plist, f)

    # LaunchAgent'i yukle
    subprocess.run(["launchctl", "load", PLIST_PATH], capture_output=True)
    print("[+] HenkerDPI V2 added to macOS login items!")


def uninstall():
    """Remove HenkerDPI V2 from macOS login items."""
    stop()

    if os.path.exists(PLIST_PATH):
        subprocess.run(["launchctl", "unload", PLIST_PATH], capture_output=True)
        os.remove(PLIST_PATH)
        print("[-] HenkerDPI V2 removed from macOS login items.")
    else:
        print("[-] LaunchAgent not found.")


def _is_running():
    """Check if process is running via PID file."""
    if not os.path.exists(PID_FILE):
        return False
    with open(PID_FILE, "r") as f:
        pid = f.read().strip()
    if not pid.isdigit():
        return False
    # Check if PID is alive
    try:
        os.kill(int(pid), 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def print_usage():
    print("HenkerDPI V2 macOS Service Manager")
    print()
    print("  python service.py start     - Start in background")
    print("  python service.py stop      - Stop")
    print("  python service.py restart   - Restart")
    print("  python service.py status    - Check status")
    print("  python service.py install   - Add to login items")
    print("  python service.py uninstall - Remove from login items")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(0)

    commands = {
        "start": start,
        "stop": stop,
        "restart": restart,
        "status": status,
        "install": install,
        "uninstall": uninstall,
    }

    cmd = sys.argv[1].lower()
    if cmd in commands:
        commands[cmd]()
    else:
        print(f"[!] Unknown command: {cmd}")
        print_usage()
