import json
import lzma
import os
import random
import secrets
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
import server.log.logging as log

from ppadb.client import Client as AdbClient


log.clear_log()

script_name = os.path.basename(__file__)

# TODO(): Add logging for codebase
# TODO(): Add exceptions for codebase
# TODO(): Add type docstrings and type annotations for all functions


def main(
    adb_path: str,
    timeout: int,
    event: threading.Event,
    python_version: tuple[int, int, int],
) -> None:
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

        event (threading.Event[None]):
            An event for the frida server to properly time the injection of the frida hook

        python_version (tuple[int, int, int]):
            Python version information for logging

    """
    log.log(
        f"Python Version: {python_version[0]}.{python_version[1]}.{python_version[2]}",
        stdout=False,
    )

    with open("config/config.json", encoding="utf-8") as f:
        config: dict[str, Any] = json.load(f)

    log.log("Loaded config/config.json", stdout=False)

    check_updates(config, timeout)

    # if os.path.isfile("data/user/user.json"):
    #     randomizer(config)

    if False:
        randomizer(config)

    elif not os.path.exists(adb_path):
        if not os.path.exists("adb.zip"):
            log.log("No adb file found. Downloading the latest version.")
            download_adb_zip(timeout)
        ZipFile("adb.zip").extractall(".")
        os.remove("adb.zip")

    subprocess.run(f"{adb_path} kill-server", check=True)
    subprocess.run(f"{adb_path} start-server", check=True)
    log.log("Attempting connection to emulator...")
    adb_device: ppadb.device.Device = get_device(
        AdbClient(host="127.0.0.1", port=5037), [7555, 5555, 62001], config
    )

    threading.Thread(
        target=check_device_state, args=(adb_path, adb_device, event)
    ).start()
    log.log("Waiting for device to be ready...")
    event.wait()
    event.clear()

    log.log(
        "Check the emulator and accept if it asks for root permission.", log_file=False
    )

    with suppress(RuntimeError):
        adb_device.root()

    subprocess.run(f"{adb_path} -s {adb_device.serial} wait-for-device", check=True)

    if not adb_device.shell(
        "test -f /data/local/tmp/frida-server && echo True"
    ).strip():
        log.log("Frida server not found. Installing...")
        install_frida(adb_device, timeout)
    else:
        log.log("Frida server found. Skipping installation.")

    with open("config/config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4)

    # threading.Thread(target=start_local_server).start()
    threading.Thread(
        target=start_frida_server,
        args=(adb_path, adb_device, event, config["server"]["port"]),
    ).start()
    event.wait()
    time.sleep(0.25)
    threading.Thread(target=start_frida_hook, args=(adb_device, config)).start()


def check_updates(
    config_file: dict[str, dict[str, dict[str, str]]], timeout: int
) -> None:
    """Check for updates and update necessary client, activity, and network information.

    Arguments:
    ---------
        config_file (dict[str, dict[str, dict[str, str]]]):
            A dictionary containing the contents of config/config.json

        timeout (int):
            Timeout in seconds for requests and other operations

    """
    client_version_mismatch: bool = False
    res_version_mismatch: bool = False
    old_res_ver: str = config_file["version"]["android"]["resVersion"]
    old_client_ver: str = config_file["version"]["android"]["clientVersion"]
    old_func_ver: str = config_file["networkConfig"]["cn"]["content"]["funcVer"]
    while True:
        try:
            version: dict[str, str] = requests.get(
                "https://ak-conf.hypergryph.com/config/prod/official/Android/version",
                timeout=timeout,
            ).json()
            res_version: str = version["resVersion"]
            client_version: str = version["clientVersion"]
            log.log(f"Old Resource Version: {old_res_ver}", stdout=False)
            log.log(f"New Resource Version: {res_version}", stdout=False)
            if res_version != old_res_ver:
                log.log("Resource Version Mismatch!", stdout=False)
                config_file["version"]["android"]["resVersion"] = res_version
                res_version_mismatch = True
            log.log(f"Old Client Version: {old_client_ver}", stdout=False)
            log.log(f"New Client Version: {client_version}", stdout=False)
            if client_version != old_client_ver:
                log.log("Client Version Mismatch!", stdout=False)
                config_file["version"]["android"]["clientVersion"] = client_version
                client_version_mismatch = True
            network_config: dict[str, Any] = requests.get(
                "https://ak-conf.hypergryph.com/config/prod/official/network_config",
                timeout=timeout,
            ).json()
            content: dict[str, Any] = json.loads(network_config["content"])
            func_version: str = content["funcVer"]
            log.log(f"Old Network Configuration Version: {old_func_ver}", stdout=False)
            log.log(f"New Network Configuration Version: {func_version}", stdout=False)
            if func_version != old_func_ver:
                log.log("Network Configuration Version Mismatch!", stdout=False)
                config_file["networkConfig"]["cn"]["content"]["funcVer"] = func_version
                config_file["networkConfig"]["cn"]["content"]["configs"][
                    func_version
                ] = config_file["networkConfig"]["cn"]["content"]["configs"][
                    old_func_ver
                ]
                del config_file["networkConfig"]["cn"]["content"]["configs"][
                    old_func_ver
                ]

        except requests.exceptions.Timeout:
            log.log(
                "Timed out while trying to fetch version information. Retrying...",
                log_level="WARNING",
            )
        break

    if client_version_mismatch:
        update_client(timeout)
    else:
        log.log("Skipping client update.")

    if res_version_mismatch:
        try:
            update_activity(config_file)
        except Exception:  # noqa: BLE001 - Ruff is stupid and doesn't understand logging
            log.log("Failed to update activity table.", log_level="EXCEPTION")
    else:
        log.log("Skipping resource update.")


def update_client(timeout: int) -> None:
    """Update client /data/excel files.

    Arguments:
    ---------
        timeout (int):
            Timeout in seconds for requests and other operations

    """
    log.log("Updating client...")
    s: requests.sessions.Session = requests.Session()
    r: requests.models.Response = s.get(
        "https://api.github.com/repos/Kengxxiao/ArknightsGameData/contents/zh_CN/gamedata/excel",
        timeout=timeout,
    )
    log.log(
        "Fetching JSON API Response from: https://api.github.com/repos/Kengxxiao/ArknightsGameData/contents/zh_CN/gamedata/excel",
        stdout=False,
    )
    log.log(f"Found {len(r.json())} files", stdout=False)
    for file in r.json():
        if file["path"] == "zh_CN/gamedata/excel/vc":
            log.log("Skipping vc folder", stdout=False)
            continue
        log.log(f"Downloading {file['name']}", log_file=False)
        r: requests.models.Response = s.get(
            f"https://raw.githubusercontent.com/Kengxxiao/ArknightsGameData/master/{file['path']}",
            timeout=timeout,
        )
        log.log(
            f"Fetching data from: https://raw.githubusercontent.com/Kengxxiao/ArknightsGameData/master/{file['path']}",
            stdout=False,
        )
        with open(f"data/excel/{file['name']}", "w", encoding="utf-8") as f:
            f.write(r.text)
        log.log(f"Saved as: data/excel/{file['name']}", stdout=False)


def update_activity(config: dict[str, dict[str, Any]]) -> None:
    """Update activity table to enable current events.

    Arguments:
    ---------
        config (dict[str, dict[str, Any]]):
            A dictionary containing the contents of data/excel/activity_table.json

    """
    log.log("Updating activity table...")
    with open("data/excel/activity_table.json", encoding="utf-8") as f:
        activity_table = json.load(f)
    activity_start_time_list: list[int] = []
    for event in activity_table["basicInfo"]:
        if event.endswith(("side", "sre")):
            start_time: int = activity_table["basicInfo"][event]["startTime"]
            activity_start_time_list.append(start_time)
    max_activity_start_time: int = max(activity_start_time_list)
    config["userConfig"]["activityStartTs"] = max_activity_start_time - (
        7 * 24 * 60 * 60
    )


def get_device(
    client: ppadb.device.Device, ports: list[int], config_file: dict[str, Any]
) -> ppadb.device.Device:  # noqa: C901, PLR0912 - Too lazy to make this less shitty
    """Connect to all available devices and return either one device if there is only one, or ask the user to select one.

    Arguments:
    ---------
        client (ppadb.device.Device):
            The ppadb client device object containing device information

        ports (list[int]):
            A list of ports to attempt connecting to devices on

        config_file (dict):
            A dictionary containing the contents of config/config.json

    Returns:
    -------
        ppadb.device.Device:
            Pure-Python Android-Debugging-Bridge Device

    """
    while True:
        for port in ports:
            log.log(
                f"Attempting connection to device at 127.0.0.0:{port}...", stdout=False
            )
            client.remote_connect("127.0.0.1", port)
        devices: list["ppadb.device.Device"] = client.devices()
        if len(devices) == 0:
            log.log("No devices found. Retrying...")
            continue
        break

    if len(devices) > 1:
        if config_file["userConfig"]["defaultDevice"] is not None:
            for device_num in devices:
                if device_num.serial == config_file["userConfig"]["defaultDevice"]:
                    log.log(
                        f"Multiple devices found. Defaulting to {device_num.serial}. This option can be changed in config/config.json",
                        log_file=False,
                    )
                    log.log("Multiple devices found.", stdout=False)
                    log.log(f"Connecting to Device: {device_num.serial}", stdout=False)
                    return device_num
        else:
            log.log("Multiple devices found.")
            log.log("\n", log_file=False)
            for enum, device_num in enumerate(devices):
                log.log(f"Device {enum + 1}: {device_num.serial}", stdout=False)
                log.log(f"    {enum + 1}: {device_num.serial}", log_file=False)
            log.log(
                "\nInput the number of the device that you wish to connect to.",
                log_file=False,
            )
            while True:
                try:
                    selected_device: int = int(input()) - 1
                except ValueError:
                    log.log(
                        "Invalid input. Please enter a valid number.", log_file=False
                    )
                    continue
                if selected_device < 0 or selected_device >= len(devices):
                    log.log(
                        "Invalid device number. Please enter a valid number.",
                        log_file=False,
                    )
                    continue
                break
            if (
                input(
                    "Would you like to set this device as the default device? (Y/N) "
                ).lower()
                == "y" | "yes"
            ):
                config_file["userConfig"]["defaultDevice"] = devices[
                    selected_device
                ].serial
                log.log(f"Setting default device to: {devices[selected_device].serial}")
            log.log(
                f"Connecting to Device: {devices[selected_device].serial}", stdout=False
            )
            return devices[selected_device]
    log.log(f"Connecting to Device: {devices[0].serial}", stdout=False)
    return devices[0]


def check_device_state(
    adb_path: str,
    adb_device: ppadb.device.Device,
    event: threading.Event,
) -> None:
    """Check the device state for connectivity and set the event if the device is ready.

    Arguments:
    ---------
        adb_path (str):
            The path to the ADB executable

        adb_device (ppadb.device.Device):
            The ppadb device object containing device information

        event (threading.Event):
            A threading event that will be set when the device is ready

    """
    netstat_tulpn = subprocess.check_output(
        f"{adb_path} -s {adb_device.serial} shell netstat -tulpn",
        encoding="utf-8",
    )
    if "system_server" in netstat_tulpn and "frida-server" not in netstat_tulpn:
        log.log("Incompatible device state. Resetting...")
        subprocess.Popen(f"{adb_path} shell reboot")
    while True:
        try:
            if "CONNECTED/CONNECTED" in subprocess.check_output(
                f"{adb_path} -s {adb_device.serial} shell dumpsys connectivity | sed -e '/[0-9] NetworkAgentInfo.*CONNECTED/p' -n",
                encoding="utf-8",
                stderr=subprocess.DEVNULL,
            ):
                log.log("Device ready.")
                event.set()
                break
        except subprocess.CalledProcessError:
            pass


def randomizer(config_file: dict[str, Any]) -> None:  # noqa: PLR0915 ur mother has too many statements
    """Check to see if randomizer settings are applied, then randomize each section that is enabled.

    Arguments:
    ---------
        config_file (Dict[str, Any]):
           A dictionary containing the contents of config/config.json

    """
    with open("data/user/user.json", encoding="utf-8") as f:
        user: dict[str, Any] = json.load(f)
    if config_file["userConfig"]["randomSecretary"]["active"]:
        log.log("Randomizing secretary...", stdout=False)
        if config_file["userConfig"]["randomSecretary"]["sixStarOnly"]:
            log.log("Only selecting TIER_6 characters for secretary...", stdout=False)
            with open("data/excel/character_table.json", encoding="utf8") as f:
                data: dict[str, Any] = json.load(f)
            array: list[str] = [
                i
                for i in user["user"]["troop"]["chars"]
                if data[user["user"]["troop"]["chars"][i]["charId"]]["rarity"]
                == "TIER_6"
            ]
            choice: str = secrets.choice(array)
        else:
            array: list[str] = list(user["user"]["troop"]["chars"])
            choice: str = secrets.choice(array)
        operator: str = user["user"]["troop"]["chars"][choice]["charId"]
        log.log(f"Selected: {operator} as secretary.", stdout=False)
        skin: str = user["user"]["troop"]["chars"][choice]["skin"]
        log.log(f"Selected: {skin} as secretary skin.", stdout=False)
        config_file["userConfig"]["secretary"] = operator
        config_file["userConfig"]["secretarySkinId"] = skin
        user["user"]["status"]["secretary"] = operator
        user["user"]["status"]["secretarySkinId"] = skin

    if config_file["userConfig"]["randomBackground"]:
        log.log("Randomizing background...", stdout=False)
        with open("data/excel/display_meta_table.json", encoding="utf8") as f:
            themes: dict[str, Any] = json.load(f)
        choice: dict[str, Any] = secrets.choice(
            themes["homeBackgroundData"]["homeBgDataList"]
        )
        log.log(f"Selected: {choice['bgId']} as background.", stdout=False)
        config_file["userConfig"]["background"] = choice["bgId"]
        user["user"]["status"]["background"] = choice["bgId"]

    if config_file["userConfig"]["randomTheme"]:
        log.log("Randomizing UI theme...", stdout=False)
        with open("data/excel/display_meta_table.json", encoding="utf8") as f:
            themes: dict[str, Any] = json.load(f)
        choice: dict[str, Any] = secrets.choice(
            themes["homeBackgroundData"]["themeList"]
        )
        log.log(f"Selected: {choice['id']} as UI theme.", stdout=False)
        config_file["userConfig"]["theme"] = choice["id"]
        user["user"]["status"]["theme"] = choice["id"]

    if config_file["userConfig"]["randomSquad"]["active"]:
        log.log("Randomizing 4th squad...", stdout=False)
        with open("config/squads.json", encoding="utf-8") as f:
            squads: dict[str, Any] = json.load(f)
        if config_file["userConfig"]["randomSquad"]["sixStarOnly"]:
            log.log("Only selecting TIER_6 characters for 4th squad...", stdout=False)
            with open("data/excel/character_table.json", encoding="utf8") as f:
                data: dict[str, Any] = json.load(f)
            array: list[str] = [
                i
                for i in user["user"]["troop"]["chars"]
                if data[user["user"]["troop"]["chars"][i]["charId"]]["rarity"]
                == "TIER_6"
            ]
            choices: list[str] = random.sample(array, 12)
            log.log(f"Selected {choices} characters for 4th squad.", stdout=False)
        else:
            choices: list[str] = random.sample(list(user["user"]["troop"]["chars"]), 12)
        array: list[dict[str, Any]] = []
        for x in choices:
            array.append(
                {
                    "charId": user["user"]["troop"]["chars"][x]["charId"],
                    "skillIndex": user["user"]["troop"]["chars"][x][
                        "defaultSkillIndex"
                    ],
                    "currentEquip": user["user"]["troop"]["chars"][x]["currentEquip"],
                }
            )
        squads["3"]["slots"] = array
        log.log(f"Selected {[x['charId'] for x in array]} for 4th squad.", stdout=False)
    with open("data/user/user.json", "w", encoding="utf-8") as f:
        json.dump(user, f, indent=4)


def download_adb_zip(timeout: int) -> None:
    """Download ADB zip file and save it in the current directory.

    Arguments:
    ---------
        timeout (int): Timeout in seconds for the request

    """
    r: requests.Response = requests.get(
        "https://dl.google.com/android/repository/platform-tools-latest-windows.zip",
        allow_redirects=True,
        timeout=timeout,
    )
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
    architecture: str = (
        adb_device.shell("getprop ro.product.cpu.abi").strip().replace("-v8a", "")
    )
    log.log(f"Device Architecture: {architecture}")

    if not os.path.exists(f"frida-server-{architecture}.xz"):
        version: str = requests.get(
            "https://api.github.com/repos/frida/frida/releases/latest", timeout=timeout
        ).json()["tag_name"]
        name: str = f"frida-server-{version}-android-{architecture}"
        log.log(f"Downloading {name}...")
        url: str = (
            f"https://github.com/frida/frida/releases/download/{version}/{name}.xz"
        )
        r: requests.models.Response = requests.get(
            url, allow_redirects=True, timeout=timeout
        )
        with open(f"frida-server-{architecture}.xz", "wb") as f:
            f.write(r.content)

    log.log("Extracting frida....")

    with lzma.open(f"frida-server-{architecture}.xz") as f, open(
        "frida-server", "wb"
    ) as fout:
        file_content: bytes = f.read()
        fout.write(file_content)

    log.log("Copying frida-server...")
    adb_device.push("frida-server", "/data/local/tmp/frida-server")
    log.log("Modifying permissions")
    adb_device.shell("chmod 755 /data/local/tmp/frida-server")
    os.remove("frida-server")
    log.log("Frida-server is installed!")


def on_message(message: str, data: str) -> None:
    """Return message and data when frida receives message from script.

    Arguments:
    ---------
        message (str):
            The name of the event that triggered the message

        data (str):
            The data that was sent with the message

    """
    log.log(f"[{message}] => {data}")


def start_local_server() -> None:
    """Start the local server."""
    try:
        log.log("Starting local server...", name_override=script_name)
        subprocess.run(["env/Scripts/python.exe", "server/app.py"], check=True)
    except Exception:
        log.log(
            "Caught exception in start_local_server()",
            stdout=False,
            log_level="EXCEPTION",
            name_override=script_name,
        )
        raise


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
    try:
        log.log("Starting Frida server...", name_override=script_name)
        subprocess.run([adb_path, "start-server"], check=True)

        log.log("Attempting root...", name_override=script_name)
        with suppress(RuntimeError):
            adb_device.root()

        subprocess.run(
            [adb_path, "-s", adb_device.serial, "wait-for-device"], check=True
        )
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
        os.system(
            f'"{adb_path}" -s {adb_device.serial}'
            + " shell /data/local/tmp/frida-server &"
        )  # noqa: S605 : Unable to convert this to subprocess.run()/call()/popen()
    except Exception:
        log.log(
            "Caught exception in start_frida_server()",
            stdout=False,
            log_level="EXCEPTION",
            name_override=script_name,
        )
        raise


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
    try:
        log.log("Grabbing frida device...", name_override=script_name)
        frida_device = frida.get_device(adb_device.serial, timeout=10)

        if config["server"]["mode"] == "cn":
            b64_cn = "Y29tLmh5cGVyZ3J5cGguYXJrbmlnaHRz"
            b64_cn_decode = b64decode(b64_cn).decode()
            log.log("Mode: CN", name_override=script_name)
            log.log(
                f"Launching APK with code: {b64_cn} = {b64_cn_decode}",
                name_override=script_name,
            )
            pid = frida_device.spawn(b64_cn_decode)
            frida_device.resume(pid)
            session = frida_device.attach(pid)

        else:
            b64_global = "Y29tLllvU3RhckVOLkFya25pZ2h0cw=="
            b64_global_decode = b64decode(b64_global).decode()
            log.log("Mode: GLOBAL", name_override=script_name)
            log.log(
                f"Launching APK with code: {b64_global} = {b64_global_decode}",
                name_override=script_name,
            )
            pid = frida_device.spawn(b64_global_decode)
            frida_device.resume(pid)
            session = frida_device.attach(pid, realm="emulated")

        scriptmanager("data/scripts", session, config)
        sys.stdin.read()
        session.detach()
    except Exception:
        log.log(
            "Caught exception in start_frida_hook()",
            stdout=False,
            log_level="EXCEPTION",
            name_override=script_name,
        )
        raise


def scriptmanager(
    script_dir: str, session: frida.core.Session, config: dict[str, Any]
) -> None:
    """Find scripts in the specified directory and execute them if they are enabled in the config.

    Args:
    ----
        script_dir (str):
            The directory containing the scripts.

        session (frida.core.Session):
            The Frida session to interact with.

        config (dict[str, Any]):
            Configuration settings including server configuration and script configurations.

    """
    try:
        for filename in os.listdir(script_dir):
            file = os.path.join(script_dir, filename)
            script_file = Path(file).read_text(encoding="utf-8")
            if filename == "_.js":
                script_file = (
                    script_file.replace(
                        "@@@DOCTORATE_HOST@@@",
                        "NO_PROXY"
                        if config["server"]["noProxy"]
                        else config["server"]["host"],
                        1,
                    )
                    .replace("@@@DOCTORATE_PORT@@@", str(config["server"]["port"]), 1)
                    .replace(
                        "@@@DOCTORATE_ACTIVITY_MIN_START_TS@@@",
                        str(config["userConfig"]["activityMinStartTs"]),
                        1,
                    )
                    .replace(
                        "@@@DOCTORATE_ACTIVITY_MAX_START_TS@@@",
                        str(config["userConfig"]["activityMaxStartTs"]),
                        1,
                    )
                )
            elif filename not in config["scriptConfig"]:
                config["scriptConfig"][filename] = False
            if filename == "_.js" or config["scriptConfig"][filename] is True:
                script = session.create_script(script_file)
                script.on("message", on_message)
                script.load()
        with open("config/config.json", "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)
    except Exception:
        log.log(
            "Caught exception in scriptmanager()", stdout=False, log_level="EXCEPTION"
        )
        raise


if __name__ == "__main__":
    try:
        main("platform-tools\\adb.exe", 30, threading.Event(), sys.version_info)
    except Exception:
        log.log("Caught exception in main()", stdout=False, log_level="EXCEPTION")
        raise
