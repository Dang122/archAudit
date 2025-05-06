# scanner.py
import platform
import os
import subprocess

def get_os_info():
    return {
        "system": platform.system(),
        "node": platform.node(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
    }

def get_distribution_info():
    if os.path.exists("/etc/os-release"):
        with open("/etc/os-release") as f:
            return dict(line.strip().split("=", 1) for line in f if "=" in line)
    return {}

def list_users():
    with open("/etc/passwd", "r") as f:
        return [line.split(":")[0] for line in f]

def list_services():
    try:
        output = subprocess.check_output(["systemctl", "list-units", "--type=service", "--state=running"])
        return output.decode().splitlines()
    except Exception as e:
        return [f"Error listando servicios: {e}"]
