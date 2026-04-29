"""
HenkerDPI V2 - Windows Service Manager
"""

import sys
import os
import subprocess

SERVICE_NAME = "HenkerDPI_V2"
PYTHON_PATH = r"C:\Users\mumin\AppData\Local\Programs\Python\Python310\python.exe"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT_PATH = os.path.join(SCRIPT_DIR, "main.py")
PID_FILE = os.path.join(SCRIPT_DIR, "henkerdpi_v2.pid")

# Hide console windows for all subprocess calls
_SW = subprocess.STARTUPINFO()
_SW.dwFlags |= subprocess.STARTF_USESHOWWINDOW
_SW.wShowWindow = 0  # SW_HIDE


def start():
    """Start HenkerDPI V2 in the background."""
    if _is_running():
        print("[!] HenkerDPI V2 is already running.")
        return

    proc = subprocess.Popen(
        [PYTHON_PATH, SCRIPT_PATH],
        creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
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
        result = subprocess.run(
            ["taskkill", "/f", "/pid", pid],
            capture_output=True, text=True, startupinfo=_SW,
        )
        if result.returncode == 0:
            print(f"[-] HenkerDPI V2 stopped (PID: {pid})")
        else:
            print(f"[-] PID {pid} already stopped.")

    try:
        os.remove(PID_FILE)
    except OSError:
        pass


def status():
    if _is_running():
        with open(PID_FILE, "r") as f:
            pid = f.read().strip()
        print(f"[+] HenkerDPI V2 is running (PID: {pid})")
    else:
        print("[-] HenkerDPI V2 is not running.")


def restart():
    stop()
    start()


def install():
    """Add to Windows startup via Task Scheduler."""
    cmd = [
        "schtasks", "/create",
        "/tn", SERVICE_NAME,
        "/tr", f'"{PYTHON_PATH}" "{SCRIPT_PATH}"',
        "/sc", "onlogon",
        "/rl", "highest",
        "/f",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, startupinfo=_SW)
    if result.returncode == 0:
        print("[+] Added to Windows startup!")
    else:
        print(f"[!] Error: {result.stderr}")


def uninstall():
    """Remove from Windows startup."""
    stop()
    cmd = ["schtasks", "/delete", "/tn", SERVICE_NAME, "/f"]
    result = subprocess.run(cmd, capture_output=True, text=True, startupinfo=_SW)
    if result.returncode == 0:
        print("[-] Removed from Windows startup.")
    else:
        print(f"[!] Error: {result.stderr}")


def _is_running():
    if not os.path.exists(PID_FILE):
        return False
    with open(PID_FILE, "r") as f:
        pid = f.read().strip()
    if not pid.isdigit():
        return False
    result = subprocess.run(
        ["tasklist", "/fi", f"PID eq {pid}"],
        capture_output=True, text=True, startupinfo=_SW,
    )
    return "python" in result.stdout.lower()


def print_usage():
    print("HenkerDPI V2 Service Manager")
    print()
    print("  python service.py start     - Start in background")
    print("  python service.py stop      - Stop")
    print("  python service.py restart   - Restart")
    print("  python service.py status    - Check status")
    print("  python service.py install   - Add to Windows startup")
    print("  python service.py uninstall - Remove from startup")


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
