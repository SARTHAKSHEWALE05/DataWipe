import platform
import os
import sys
import subprocess

# Existing imports
from device_detection1 import run_cmd, is_tool, RULESET

# ---------------- Admin / Root Utilities ----------------
def is_admin():
    """Check if the current process has admin/root privileges."""
    system = platform.system().lower()
    if system == "windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        # Linux / macOS
        return os.geteuid() == 0

def elevate_command(cmd_list):
    """Relaunch the given command list with admin/root privileges."""
    system = platform.system().lower()
    if system == "windows":
        import ctypes
        script = " ".join(cmd_list)
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, script, None, 1
        )
        sys.exit(0)
    else:
        # Linux/macOS
        os.execvp("sudo", ["sudo"] + cmd_list)

# ---------------- Updated wipe_device ----------------
def wipe_device(device, confirm=True, dry_run=False):
    """
    Securely wipe a device based on its classification & RULESET commands.
    - confirm: if True, ask before executing
    - dry_run: if True, only print commands instead of running
    """
    dtype = device.get("detected_type", "Unknown")
    path = device.get("path")
    serial = device.get("serial")

    system = platform.system().lower()
    rules = RULESET.get(dtype, RULESET["Unknown"])
    cmds = rules["commands"].get(system, [])

    if not cmds:
        return f"No wipe commands defined for {dtype} on {system}"

    # Replace placeholders
    processed_cmds = []
    for c in cmds:
        c = c.replace("{path}", str(path or ""))
        c = c.replace("{serial}", str(serial or ""))
        processed_cmds.append(c)

    # Safety confirmation
    if confirm:
        print(f"\n[!] WARNING: You are about to ERASE {path} ({dtype})")
        ans = input("Proceed? (yes/[no]) ").strip().lower()
        if ans != "yes":
            return "Wipe cancelled by user."

    results = []
    for cmd in processed_cmds:
        if dry_run:
            results.append(f"[DRY RUN] {cmd}")
        else:
            out = run_cmd(cmd, shell=True)

            # Check for permission errors
            if ("permission denied" in out.lower() or "access is denied" in out.lower()) and not is_admin():
                print(f"[!] Insufficient privileges for command:\n{cmd}")
                print("[!] Relaunching with admin/root privileges...")
                elevate_command([sys.executable] + sys.argv)
                sys.exit(1)  # Will not reach here after elevate_command

            results.append(f"$ {cmd}\n{out}")
    return "\n".join(results)
