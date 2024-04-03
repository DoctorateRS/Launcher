import json
import logging
import logging.handlers
import lzma
import os
import subprocess
import sys
import threading
import time

from base64 import b64decode
from contextlib import suppress
from pathlib import Path
from typing import Any
from zipfile import ZipFile

import frida
import ppadb
import requests

from ppadb.client import Client as AdbClient

stdout_handler = logging.StreamHandler()
stdout_formatter = logging.Formatter(fmt="%(message)s")
stdout_handler.setFormatter(stdout_formatter)
stdout = logging.getLogger("stdout")
stdout.setLevel(os.environ.get("LOGLEVEL", "INFO"))
stdout.addHandler(stdout_handler)


def main(adb_path: str, timeout: int, event: threading.Event) -> None:
    """Launch ODPy.

    A function to perform a series of tasks including checking Python version, loading configuration from a JSON file,
    checking for updates, connecting to an emulator, downloading necessary files if not found, starting servers,
    installing Frida server, and starting various threads. This function is strongly typed and includes type hints
    for all function arguments and return type

    Arguments:
    ---------
        adb_path (str):
            Path to the ADB executable

        timeout (int):
            Timeout in seconds for requests and other operations

        event (threading.Event):
            An event for the frida server to properly time the injection of the frida hook

        python_version (tuple[int, int, int]):
            Python version information for logging

    """
    with open("config/config.json", encoding="utf-8") as f:
        config: dict[str, Any] = json.load(f)

    if not os.path.exists(adb_path):
        if not os.path.exists("adb.zip"):
            stdout.info("No adb file found. Downloading the latest version.")
            download_adb_zip(timeout)
        ZipFile("adb.zip").extractall(".")
        os.remove("adb.zip")

    subprocess.run(f"{adb_path} kill-server", check=True)
    subprocess.run(f"{adb_path} start-server", check=True)
    stdout.info("Attempting connection to emulator...")
    adb_device: ppadb.device.Device = get_device(AdbClient(host="127.0.0.1", port=5037), [7555, 5555, 62001])
    stdout.info("Check the emulator and accept if it asks for root permission.")

    with suppress(RuntimeError):
        adb_device.root()

    subprocess.run(f"{adb_path} -s {adb_device.serial} wait-for-device", check=True)

    if not adb_device.shell("test -f /data/local/tmp/frida-server && echo True").strip():
        stdout.info("Frida server not found. Installing...")
        install_frida(adb_device, timeout)
    else:
        stdout.info("Frida server found. Skipping installation.")

    threading.Thread(target=start_frida_server, args=(adb_path, adb_device, event, config["server"]["port"])).start()
    event.wait()
    time.sleep(0.25)
    threading.Thread(target=start_frida_hook, args=(adb_device, config)).start()


def get_device(client: ppadb.device.Device, ports: list[int]) -> ppadb.device.Device:
    """Connect to all available devices and return either one device if there is only one, or ask the user to select one.

    Arguments:
    ---------
        client (ppadb.device.Device):
            The ppadb client device object containing device information
        ports (list[int]):
            A list of ports to attempt connecting to devices on.

    Returns:
    -------
        ppadb.device.Device: Pure-Python Android-Debugging-Bridge Device

    """
    while True:
        for port in ports:
            client.remote_connect("127.0.0.1", port)
        devices: list["ppadb.device.Device"] = client.devices()
        if len(devices) == 0:
            stdout.info("No devices found. Retrying...")
            continue
        break

    if len(devices) > 1:
        stdout.info("Multiple devices found.\n")
        for enum, device_num in enumerate(devices):
            stdout.info(f"    {enum + 1}: {device_num.serial}")
        stdout.info("\nInput the number of the device that you wish to connect to.")
        while True:
            try:
                selected_device: int = int(input()) - 1
            except ValueError:
                stdout.info("Invalid input. Please enter a valid number.")
                continue
            if selected_device < 0 or selected_device >= len(devices):
                stdout.info("Invalid device number. Please enter a valid number.")
                continue
            break
        stdout.info(f"Selected: {devices[selected_device].serial}")
        return devices[selected_device]
    return devices[0]


def download_adb_zip(timeout: int) -> None:
    """Download ADB zip file and save it in the current directory.

    Arguments:
    ---------
        timeout (int): Timeout in seconds for the request.

    """
    r: requests.Response = requests.get("https://dl.google.com/android/repository/platform-tools-latest-windows.zip", allow_redirects=True, timeout=timeout)
    with open("adb.zip", "wb") as f:
        f.write(r.content)
        f.write(r.content)


def install_frida(adb_device: ppadb.device.Device, timeout: int) -> None:
    """Check if frida server is installed on the device, and if not, install it.

    Arguments:
    ---------
        adb_device (ppadb.device.Device):
            An ADB device object
        timeout (int):
            Timeout in seconds for requests and other operations

    """
    architecture: str = adb_device.shell("getprop ro.product.cpu.abi").strip().replace("-v8a", "")
    stdout.info(f"\nArchitecture: {architecture}")

    if not os.path.exists(f"frida-server-{architecture}.xz"):
        version: str = requests.get("https://api.github.com/repos/frida/frida/releases/latest", timeout=timeout).json()["tag_name"]
        name: str = f"frida-server-{version}-android-{architecture}"
        stdout.info(f"Downloading {name}...")
        url: str = f"https://github.com/frida/frida/releases/download/{version}/{name}.xz"
        r: requests.models.Response = requests.get(url, allow_redirects=True, timeout=timeout)
        with open(f"frida-server-{architecture}.xz", "wb") as f:
            f.write(r.content)

    stdout.info("Extracting frida....")

    with lzma.open(f"frida-server-{architecture}.xz") as f, open("frida-server", "wb") as fout:
        file_content: bytes = f.read()
        fout.write(file_content)

    stdout.info("Copying frida-server...")
    adb_device.push("frida-server", "/data/local/tmp/frida-server")
    stdout.info("Modifying permissions")
    adb_device.shell("chmod 755 /data/local/tmp/frida-server")
    os.remove("frida-server")
    stdout.info("Frida-server is installed!")


def on_message(message: str, data: str) -> None:
    """Return message and data when frida receives message from script.

    Arguments:
    ---------
    message (str):
        The name of the event that triggered the message.
    data (str):
        The data that was sent with the message.

    """
    stdout.info(f"[{message}] => {data}")


def start_frida_server(
    adb_path: str,
    adb_device: ppadb.device.Device,
    event: threading.Event,
    server_port: int,
) -> None:
    """Start the Frida server on the device.

    Arguments:
    ---------
    adb_path (str):
            The path to the ADB executable
    adb_device (ppadb.device.Device):
        A ppadb.device.Device object containing device information
    event (threading.Event):
        A threading.Event object to set when the server is ready
    server_port (int):
        The port to use for the Frida server

    """
    subprocess.run([adb_path, "start-server"], check=True)

    with suppress(RuntimeError):
        adb_device.root()

    subprocess.run([adb_path, "-s", adb_device.serial, "wait-for-device"], check=True)
    subprocess.run(
        [
            adb_path,
            "-s",
            adb_device.serial,
            "reverse",
            f"tcp:{server_port}",
            f"tcp:{server_port}",
        ],
        check=True,
    )
    event.set()
    os.system(f'"{adb_path}" -s {adb_device.serial}' + " shell /data/local/tmp/frida-server &")


def start_frida_hook(adb_device: ppadb.device.Device, config: dict[str, Any]) -> None:
    """Start a Frida hook on the Arknights game process.

    The hook listens for messages from the Arknights game script and
    displays them in the console.

    Arguments:
    ---------
        adb_device (ppadb.device.Device):
            A ppadb.device.Device object containing device information
        config (dict[str, Any]):
            The configuration dictionary from config/config.json

    """
    frida_device = frida.get_device(adb_device.serial, timeout=10)

    if config["server"]["mode"] == "cn":
        b64_cn = "Y29tLmh5cGVyZ3J5cGguYXJrbmlnaHRz"
        b64_cn_decode = b64decode(b64_cn).decode()
        pid = frida_device.spawn(b64_cn_decode)
        frida_device.resume(pid)
        session = frida_device.attach(pid)

    else:
        b64_global = "Y29tLllvU3RhckVOLkFya25pZ2h0cw=="
        b64_global_decode = b64decode(b64_global).decode()
        pid = frida_device.spawn(b64_global_decode)
        frida_device.resume(pid)
        session = frida_device.attach(pid, realm="emulated")

    s = Path("_.js").read_text(encoding="utf-8")

    vision = Path("vision.js").read_text(encoding="utf-8")

    s = (
        s.replace("@@@DOCTORATE_HOST@@@", "NO_PROXY" if config["server"]["noProxy"] else config["server"]["host"], 1)
        .replace("@@@DOCTORATE_PORT@@@", str(config["server"]["port"]), 1)
        .replace("@@@DOCTORATE_ACTIVITY_MIN_START_TS@@@", str(config["userConfig"]["activityMinStartTs"]), 1)
        .replace("@@@DOCTORATE_ACTIVITY_MAX_START_TS@@@", str(config["userConfig"]["activityMaxStartTs"]), 1)
    )

    script = session.create_script(s)
    vision_script = session.create_script(vision)
    script.on("message", on_message)
    script.load()
    vision_script.load()
    stdout.info("Launching game...")
    sys.stdin.read()
    session.detach()


main("platform-tools\\adb.exe", 30, threading.Event(), sys.version_info)
