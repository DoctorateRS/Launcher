import json  # noqa: INP001, D100, CPY001
import lzma
import os
import random
import secrets
import subprocess  # noqa: S404 - ur mother is possibly insecure
import sys
import threading
import time

from base64 import b64decode
from contextlib import suppress
from pathlib import Path
from zipfile import ZipFile


os.system("color")  # noqa: S605, S607


try:
    import server.log.logging as log
except ModuleNotFoundError:

    class log:  # noqa: N801
        """Log messages to stdout if log module is missing."""

        @staticmethod
        def log(
            message: str,
            *,
            log_level: str = "INFO",
            stdout: bool = True,
            log_file: bool = True,  # noqa: ARG004
            name_override: str | None = None,  # noqa: ARG004
        ) -> None:
            """Log messages to stdout if log module is missing.

            Arguments:
            ---------
                message:
                    The message to be printed to stdout.

                log_level:
                    Used to determine the color and log level of the message.

                stdout:
                    Used to determine if the message should be printed to stdout.

                log_file:
                    Ignored.

                name_override:
                    Ignored.

            """
            if stdout:
                match log_level:
                    case "INFO":
                        print(message)  # noqa: T201
                    case "DEBUG":
                        print(message)  # noqa: T201
                    case "WARNING":
                        print(f"\x1b[93m[WARNING]\x1b[0m {message}")  # noqa: T201
                    case "ERROR":
                        print(f"\x1b[91m[ERROR]\x1b[0m {message}")  # noqa: T201
                    case "EXCEPTION":
                        print(f"\x1b[91m[EXCEPTION]\x1b[0m {message}")  # noqa: T201
                    case "CRITICAL":
                        print(f"\x1b[91m[CRITICAL]\x1b[0m {message}")  # noqa: T201


venv = r"env\Scripts\activate.bat"

try:
    import frida
except ModuleNotFoundError:
    subprocess.run(f"call activate {venv} & uv pip install frida", shell=True, check=True)  # noqa: S602
    import frida
try:
    import ppadb  # noqa: I001
    from ppadb.client import Client as AdbClient
except ModuleNotFoundError:
    subprocess.run(f"call activate {venv} & uv pip install pure-python-adb", shell=True, check=True)  # noqa: S602
    import ppadb  # noqa: I001
    from ppadb.client import Client as AdbClient
try:
    import regex
except ModuleNotFoundError:
    subprocess.run(f"call activate {venv} & uv pip install regex", shell=True, check=True)  # noqa: S602
    import regex
try:
    import requests
except ModuleNotFoundError:
    subprocess.run(f"call activate {venv} & uv pip install requests", shell=True, check=True)  # noqa: S602
    import requests

with suppress(AttributeError):
    log.clear_log()

SCRIPT_NAME = Path(__file__).name
REGEX_PATTERN = regex.compile(r"(?<=mLegacyTypeTracker:\s*\n\s*Supported types: .*\s*\n\s*Current state:\s*\n\s*[0-9] ).*")


def main(  # noqa: PLR0915
    adb_path: str,
    timeout: int,
    event: threading.Event,
    python_version: tuple[int, int, int],
) -> None:
    """Launch ODPy.

    This function is responsible for checking the Python version, loading the configuration from a JSON file,
    checking for updates, connecting to an emulator, downloading necessary files if not found, starting servers,
    installing Frida server, and starting various threads.

    Arguments:
    ---------
        adb_path (str):
            Path to the ADB executable.

        timeout (int):
            Timeout in seconds for requests and other operations.

        event (threading.Event[None]):
            An event for the frida server to properly time the injection of the frida hook.

        python_version (tuple[int, int, int]):
            Python version information for logging.

    """
    log.log(f"Python Version: {python_version[0]}.{python_version[1]}.{python_version[2]}", stdout=False)

    try:
        with Path("config/config.json").open(encoding="utf-8") as f:
            config = json.load(f)
        log.log("Successfully loaded config/config.json from file.", stdout=False)
    except FileNotFoundError:
        log.log("Could not find config/config.json file. Creating default config.")
        if not Path("config").exists():
            Path("config").mkdir()
        with Path("config/config.json").open("a+") as f:
            f.write("{}")
            f.seek(0)
            config = json.load(f)
        log.log("Saved default config to config/config.json", stdout=False)

    check_updates(config, timeout)

    if Path("data/user/user.json").is_file():
        randomizer(config)

    if not Path(adb_path).exists():
        if not Path("adb.zip").exists():
            log.log("No adb file found. Downloading the latest version.")
            download_adb_zip(timeout)
        ZipFile("adb.zip").extractall(".")
        Path("adb.zip").unlink()

    subprocess.run(f"{adb_path} kill-server", check=True)  # noqa: S603 why dont you check some bitches for execution of untrusted input
    subprocess.run(f"{adb_path} start-server", check=True)  # noqa: S603
    log.log("Attempting connection to emulator...")
    adb_device = get_device(AdbClient(host="127.0.0.1", port=5037), [7555, 5555, 62001], config)

    check_device_state(adb_path, adb_device, event)
    event.wait()
    event.clear()

    log.log("Check the emulator and accept if it asks for root permission.", log_file=False)

    with suppress(RuntimeError):
        adb_device.root()

    subprocess.run(f"{adb_path} -s {adb_device.serial} wait-for-device", check=True)  # noqa: S603

    if not adb_device.shell("test -f /data/local/tmp/frida-server && echo True").strip():
        log.log("Frida server not found. Installing...")
        install_frida(adb_device, timeout)
    else:
        log.log("Frida server found. Skipping installation.")

    with Path("config/config.json").open("w", encoding="utf-8") as f:
        json.dump(config, f, indent=4)

    threading.Thread(target=start_local_server).start()
    if "server" not in config:
        config["server"] = {}
    if "port" not in config["server"]:
        config["server"]["port"] = 8443
    threading.Thread(target=start_frida_server, args=(adb_path, adb_device, event, config["server"]["port"])).start()
    event.wait()
    time.sleep(0.25)
    threading.Thread(target=start_frida_hook, args=(adb_device, config)).start()


def check_updates(  # noqa: C901, PLR0912, PLR0915
    config_file: dict,
    timeout: int,
) -> None:
    """Check if there are any updates for the client, activity, and network configuration and update them if necessary.

    Arguments:
    ---------
        config_file (dict):
            A dictionary containing the contents of config/config.json.

        timeout (int):
            Timeout in seconds for requests and other operations.

    """
    client_version_mismatch = False
    res_version_mismatch = False

    if "version" not in config_file:
        config_file["version"] = {}
    if "android" not in config_file["version"]:
        config_file["version"]["android"] = {}
    if "resVersion" not in config_file["version"]["android"]:
        config_file["version"]["android"]["resVersion"] = ""
    if "clientVersion" not in config_file["version"]["android"]:
        config_file["version"]["android"]["clientVersion"] = ""
    old_res_ver = config_file["version"]["android"]["resVersion"]
    old_client_ver = config_file["version"]["android"]["clientVersion"]

    if "networkConfig" not in config_file:
        config_file["networkConfig"] = {}
    if "cn" not in config_file["networkConfig"]:
        config_file["networkConfig"]["cn"] = {}
    if "content" not in config_file["networkConfig"]["cn"]:
        config_file["networkConfig"]["cn"]["content"] = {}
    if "funcVer" not in config_file["networkConfig"]["cn"]["content"]:
        config_file["networkConfig"]["cn"]["content"]["funcVer"] = ""
    old_func_ver = config_file["networkConfig"]["cn"]["content"]["funcVer"]
    while True:
        try:
            version = requests.get(
                "https://ak-conf.hypergryph.com/config/prod/official/Android/version",
                timeout=timeout,
            ).json()
            res_version = version["resVersion"]
            client_version = version["clientVersion"]
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
            network_config = requests.get(
                "https://ak-conf.hypergryph.com/config/prod/official/network_config",
                timeout=timeout,
            ).json()
            content = json.loads(network_config["content"])
            func_version = content["funcVer"]
            log.log(f"Old Network Configuration Version: {old_func_ver}", stdout=False)
            log.log(f"New Network Configuration Version: {func_version}", stdout=False)
            if func_version != old_func_ver:
                log.log("Network Configuration Version Mismatch!", stdout=False)
                config_file["networkConfig"]["cn"]["content"]["funcVer"] = func_version
                if "configs" not in config_file["networkConfig"]["cn"]["content"]:
                    config_file["networkConfig"]["cn"]["content"]["configs"] = {
                        "": {
                            "override": True,
                            "network": {
                                "gs": "{server}",
                                "as": "{server}",
                                "u8": "{server}/u8",
                                "hu": "{server}/assetbundle/official",
                                "hv": "{server}/config/prod/official/{0}/version",
                                "rc": "{server}/config/prod/official/remote_config",
                                "an": "{server}/config/prod/announce_meta/{0}/announcement.meta.json",
                                "prean": "{server}/config/prod/announce_meta/{0}/preannouncement.meta.json",
                                "sl": "https://ak.hypergryph.com/protocol/service",
                                "of": "https://ak.hypergryph.com/index.html",
                                "pkgAd": None,
                                "pkgIOS": None,
                                "secure": False,
                            },
                        },
                    }
                config_file["networkConfig"]["cn"]["content"]["configs"][func_version] = config_file["networkConfig"]["cn"]["content"][
                    "configs"
                ][old_func_ver]
                del config_file["networkConfig"]["cn"]["content"]["configs"][old_func_ver]

        except requests.exceptions.Timeout:
            log.log("Timed out while trying to fetch version information. Retrying...", log_level="WARNING")
        break

    if client_version_mismatch:
        update_client(timeout)
    else:
        log.log("Skipping client update.")

    if res_version_mismatch:
        update_activity(config_file)
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
    s = requests.Session()
    r = s.get("https://api.github.com/repos/Kengxxiao/ArknightsGameData/contents/zh_CN/gamedata/excel", timeout=timeout)
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
        r = s.get(
            f"https://raw.githubusercontent.com/Kengxxiao/ArknightsGameData/master/{file['path']}",
            timeout=timeout,
        )
        log.log(
            f"Fetching data from: https://raw.githubusercontent.com/Kengxxiao/ArknightsGameData/master/{file['path']}",
            stdout=False,
        )
        if not Path("data").exists():
            Path("data").mkdir()
        if not Path("data/excel").exists():
            Path("data/excel").mkdir()
        Path(f"data/excel/{file['name']}").write_text(r.text, encoding="utf-8")
        log.log(f"Saved as: data/excel/{file['name']}", stdout=False)


def update_activity(config: dict) -> None:
    """Update activity table to enable current events.

    Arguments:
    ---------
        config (dict):
            A dictionary containing the contents of data/excel/activity_table.json

    """
    log.log("Updating activity table...")
    with Path("data/excel/activity_table.json").open(encoding="utf-8") as f:
        activity_table = json.load(f)
    activity_start_time_list = []
    for event in activity_table["basicInfo"]:
        if event.endswith(("side", "sre")):
            start_time = activity_table["basicInfo"][event]["startTime"]
            activity_start_time_list.append(start_time)
    max_activity_start_time = max(activity_start_time_list)
    if "userConfig" not in config:
        config["userConfig"] = {}
    if "activityStartTs" not in config["userConfig"]:
        config["userConfig"]["activityStartTs"] = 0
    config["userConfig"]["activityStartTs"] = max_activity_start_time - (7 * 24 * 60 * 60)


def get_device(  # noqa: C901, PLR0912
    client: ppadb.device.Device,
    ports: list[int],
    config_file: dict,
) -> ppadb.device.Device:
    """Connect to an android device connected to this machine.

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
            log.log(f"Attempting connection to device at 127.0.0.0:{port}...", stdout=False)
            client.remote_connect("127.0.0.1", port)
        devices = client.devices()
        if len(devices) == 0:
            log.log("No devices found. Retrying...")
            continue
        break

    if len(devices) > 1:
        if "userConfig" not in config_file:
            config_file["userConfig"] = {}
        if "defaultDevice" not in config_file["userConfig"]:
            config_file["userConfig"]["defaultDevice"] = None
        if config_file["userConfig"]["defaultDevice"]:
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
            log.log("\n", log_file=False)
            log.log("Input the number of the device that you wish to connect to.", log_file=False)
            while True:
                try:
                    selected_device = int(input()) - 1
                except ValueError:
                    log.log("Invalid input. Please enter a valid number.", log_file=False)
                    continue
                if selected_device < 0 or selected_device >= len(devices):
                    log.log("Invalid device number. Please enter a valid number.", log_file=False)
                    continue
                break
            if input("Would you like to set this device as the default device? (Y/N) ").lower() in {"y", "yes"}:
                config_file["userConfig"]["defaultDevice"] = devices[selected_device].serial
                log.log(f"Setting default device to: {devices[selected_device].serial}")
            log.log(f"Connecting to Device: {devices[selected_device].serial}", stdout=False)
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
        f"{adb_path} -s {adb_device.serial} shell netstat -tulpn",  # noqa: S603
        encoding="utf-8",
    )
    log.log(netstat_tulpn, stdout=False, name_override=SCRIPT_NAME)
    check_state = ["system_server", "ntp_server", "adbd"]
    if any(check in netstat_tulpn for check in check_state) and "frida-server" not in netstat_tulpn:
        log.log("Incompatible device state. Resetting...", name_override=SCRIPT_NAME)
        subprocess.Popen(f"{adb_path} -s {adb_device.serial} shell reboot")  # noqa: S603
        time.sleep(5)
        reboot_timeout = time.time() + 30
        while True:
            try:
                if time.time() > reboot_timeout:
                    log.log("Timed out waiting for device to reboot. Continuing.", name_override=SCRIPT_NAME)
                    break
                dumpsys = subprocess.check_output(
                    f"{adb_path} -s {adb_device.serial} shell dumpsys connectivity",  # noqa: S603
                    encoding="utf-8",
                    stderr=subprocess.DEVNULL,
                )
                connectivity = regex.search(REGEX_PATTERN, dumpsys)
                if connectivity and connectivity.group(0):
                    log.log(f"Device state: {connectivity.group(0)}", stdout=False, name_override=SCRIPT_NAME)
                    log.log("Device ready.", name_override=SCRIPT_NAME)
                    break
            except subprocess.CalledProcessError:
                log.log("Caught exception in dumpsys", stdout=False, log_level="EXCEPTION", name_override=SCRIPT_NAME)
    event.set()


def randomizer(config_file: dict) -> None:  # noqa: PLR0915 , C901, PLR0912
    """Check to see if randomizer settings are applied, then randomize each section that is enabled.

    Arguments:
    ---------
        config_file (dict):
           A dictionary containing the contents of config/config.json

    """
    with Path("data/user/user.json").open(encoding="utf-8") as f:
        user = json.load(f)
    if "userConfig" not in config_file:
        config_file["userConfig"] = {}
    if "randomSecretary" not in config_file["userConfig"]:
        config_file["userConfig"]["randomSecretary"] = {"active": False, "sixStarOnly": True}
    if config_file["userConfig"]["randomSecretary"]["active"]:
        log.log("Randomizing secretary...", stdout=False)
        if config_file["userConfig"]["randomSecretary"]["sixStarOnly"]:
            log.log("Only selecting TIER_6 characters for secretary...", stdout=False)
            with Path("data/excel/character_table.json").open(encoding="utf8") as f:
                data = json.load(f)
            array = [i for i in user["user"]["troop"]["chars"] if data[user["user"]["troop"]["chars"][i]["charId"]]["rarity"] == "TIER_6"]
            choice = secrets.choice(array)
        else:
            array = list(user["user"]["troop"]["chars"])
            choice = secrets.choice(array)
        operator = user["user"]["troop"]["chars"][choice]["charId"]
        log.log(f"Selected: {operator} as secretary.", stdout=False)
        skin = user["user"]["troop"]["chars"][choice]["skin"]
        log.log(f"Selected: {skin} as secretary skin.", stdout=False)
        config_file["userConfig"]["secretary"] = operator
        config_file["userConfig"]["secretarySkinId"] = skin
        user["user"]["status"]["secretary"] = operator
        user["user"]["status"]["secretarySkinId"] = skin

    if "randomBackground" not in config_file["userConfig"]:
        config_file["userConfig"]["randomBackground"] = False
    if config_file["userConfig"]["randomBackground"]:
        log.log("Randomizing background...", stdout=False)
        with Path("data/excel/display_meta_table.json").open(encoding="utf8") as f:
            themes = json.load(f)
        choice = secrets.choice(themes["homeBackgroundData"]["homeBgDataList"])
        log.log(f"Selected: {choice['bgId']} as background.", stdout=False)
        config_file["userConfig"]["background"] = choice["bgId"]
        user["user"]["status"]["background"] = choice["bgId"]

    if "randomTheme" not in config_file["userConfig"]:
        config_file["userConfig"]["randomTheme"] = False
    if config_file["userConfig"]["randomTheme"]:
        log.log("Randomizing UI theme...", stdout=False)
        with Path("data/excel/display_meta_table.json").open(encoding="utf8") as f:
            themes = json.load(f)
        choice = secrets.choice(themes["homeBackgroundData"]["themeList"])
        log.log(f"Selected: {choice['id']} as UI theme.", stdout=False)
        config_file["userConfig"]["theme"] = choice["id"]
        user["user"]["status"]["theme"] = choice["id"]

    if "randomSquad" not in config_file["userConfig"]:
        config_file["userConfig"]["randomSquad"] = {"active": False, "sixStarOnly": True}
    if config_file["userConfig"]["randomSquad"]["active"]:
        log.log("Randomizing 4th squad...", stdout=False)
        with Path("config/squads.json").open(encoding="utf-8") as f:
            squads = json.load(f)
        if config_file["userConfig"]["randomSquad"]["sixStarOnly"]:
            log.log("Only selecting TIER_6 characters for 4th squad...", stdout=False)
            with Path("data/excel/character_table.json").open(encoding="utf8") as f:
                data = json.load(f)
            array = [i for i in user["user"]["troop"]["chars"] if data[user["user"]["troop"]["chars"][i]["charId"]]["rarity"] == "TIER_6"]
            choices = random.sample(array, 12)
        else:
            choices = random.sample(list(user["user"]["troop"]["chars"]), 12)
        array = []
        for x in choices:
            array.append({
                "charId": user["user"]["troop"]["chars"][x]["charId"],
                "skillIndex": user["user"]["troop"]["chars"][x]["defaultSkillIndex"],
                "currentEquip": user["user"]["troop"]["chars"][x]["currentEquip"],
            })
        squads["3"]["slots"] = array
        log.log(f"Selected {[x['charId'] for x in array]} for 4th squad.", stdout=False)
    with Path("data/user/user.json").open("w", encoding="utf-8") as f:
        json.dump(user, f, indent=4)


def download_adb_zip(timeout: int) -> None:
    """Download ADB zip file and save it in the current directory.

    Arguments:
    ---------
        timeout (int): Timeout in seconds for the request

    """
    r = requests.get(
        "https://dl.google.com/android/repository/platform-tools-latest-windows.zip",
        allow_redirects=True,
        timeout=timeout,
    )
    Path("adb.zip").write_bytes(r.content)


def install_frida(adb_device: ppadb.device.Device, timeout: int) -> None:
    """Check if frida server is installed on the device, and if not, install it.

    Arguments:
    ---------
        adb_device (ppadb.device.Device):
            An ADB device object

        timeout (int):
            Timeout in seconds for requests and other operations

    """
    architecture = adb_device.shell("getprop ro.product.cpu.abi").strip().replace("-v8a", "")
    log.log(f"Device Architecture: {architecture}")

    if not Path(f"frida-server-{architecture}.xz").exists():
        version = requests.get("https://api.github.com/repos/frida/frida/releases/latest", timeout=timeout).json()["tag_name"]
        name = f"frida-server-{version}-android-{architecture}"
        log.log(f"Downloading {name}...")
        url = f"https://github.com/frida/frida/releases/download/{version}/{name}.xz"
        r = requests.get(url, allow_redirects=True, timeout=timeout)
        Path(f"frida-server-{architecture}.xz").write_bytes(r.content)

    log.log("Extracting frida....")

    with lzma.open(f"frida-server-{architecture}.xz") as f:
        file_content = f.read()
    Path("frida-server").write_bytes(file_content)

    log.log("Copying frida-server...")
    adb_device.push("frida-server", "/data/local/tmp/frida-server")
    log.log("Modifying permissions")
    adb_device.shell("chmod 755 /data/local/tmp/frida-server")
    Path("frida-server").unlink()
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
    server_file = None
    server_file = None
    base_dir = os.walk(".")
    ignore_list = ["env", "platform-tools", "__pycache__"]
    for root, dirs, files in base_dir:
        dirs[:] = [d for d in dirs if not any(ignore in d for ignore in ignore_list)]

        for file in files:
            if "app.py" in file or ".exe" in file:
                server_file = Path(root) / file
    if server_file is None:
        log.log("Could not find a server file. Skipping server launch.", stdout=False, log_level="WARNING", name_override=SCRIPT_NAME)
        log.log(
            "Could not find a server file. Please launch the local server manually.",
            log_file=False,
            log_level="WARNING",
            name_override=SCRIPT_NAME,
        )
        return
    if str(server_file).endswith(".py"):
        try:
            log.log("Starting local server...", name_override=SCRIPT_NAME)
            subprocess.run(["env/Scripts/python.exe", server_file], check=True)  # noqa: S603, S607
        except Exception:
            log.log(
                "Caught exception in start_local_server()",
                stdout=False,
                log_level="EXCEPTION",
                name_override=SCRIPT_NAME,
            )
            raise
    if str(server_file).endswith(".exe"):
        try:
            log.log("Starting local server...", name_override=SCRIPT_NAME)
            subprocess.run([server_file], check=True)  # noqa: S603
        except Exception:
            log.log(
                "Caught exception in start_local_server()",
                stdout=False,
                log_level="EXCEPTION",
                name_override=SCRIPT_NAME,
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
        log.log("Starting Frida server...", name_override=SCRIPT_NAME)
        subprocess.run([adb_path, "start-server"], check=True)  # noqa: S603

        log.log("Attempting root...", name_override=SCRIPT_NAME)
        with suppress(RuntimeError):
            adb_device.root()

        subprocess.run([adb_path, "-s", adb_device.serial, "wait-for-device"], check=True)  # noqa: S603
        subprocess.run(
            [  # noqa: S603
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
        os.system(f'"{adb_path}" -s {adb_device.serial}' + " shell /data/local/tmp/frida-server &")  # noqa: S605 Unable to convert this to subprocess.run()/call()/popen()
    except Exception:
        log.log(
            "Caught exception in start_frida_server()",
            stdout=False,
            log_level="EXCEPTION",
            name_override=SCRIPT_NAME,
        )
        raise


def start_frida_hook(adb_device: ppadb.device.Device, config: dict) -> None:
    """Start a Frida hook on the Arknights game process.

    The hook listens for messages from the Arknights game script and
    displays them in the console.

    Arguments:
    ---------
        adb_device (ppadb.device.Device):
            A ppadb.device.Device object containing device information

        config (dict):
            The configuration dictionary from config/config.json

    """
    try:
        log.log("Grabbing frida device...", name_override=SCRIPT_NAME)
        frida_device = frida.get_device(adb_device.serial, timeout=10)

        b64_cn = "Y29tLmh5cGVyZ3J5cGguYXJrbmlnaHRz"
        b64_cn_decode = b64decode(b64_cn).decode()
        log.log("Mode: CN", name_override=SCRIPT_NAME)
        log.log(f"Launching APK with code: {b64_cn} -> {b64_cn_decode}", name_override=SCRIPT_NAME)
        pid = frida_device.spawn(b64_cn_decode)
        frida_device.resume(pid)
        session = frida_device.attach(pid)

        script_manager("data/scripts", session, config)
        sys.stdin.read()
        session.detach()
    except Exception:
        log.log(
            "Caught exception in start_frida_hook()",
            stdout=False,
            log_level="EXCEPTION",
            name_override=SCRIPT_NAME,
        )
        raise


def script_manager(  # noqa: C901, PLR0912
    script_dir: str,
    session: frida.core.Session,
    config: dict,
) -> None:
    """Find scripts in the specified directory and execute them if they are enabled in the config.

    Args:
    ----
        script_dir (str):
            The directory containing the scripts.

        session (frida.core.Session):
            The Frida session to interact with.

        config (dict):
            Configuration settings including server configuration and script configurations.

    """
    if not Path("data").exists():
        Path("data").mkdir()
    if not Path("data/scripts").exists():
        Path("data/scripts").mkdir()
    if not Path("data/scripts/_.js").exists():
        r = requests.get("https://raw.githubusercontent.com/sSasha-uwu/odpy-defaults/main/_.js", timeout=30)
        with Path("data/scripts/_.js").open("wb") as f:
            f.write(r.content)
    try:
        for filename in os.listdir(script_dir):
            file = Path(script_dir) / filename
            script_file = Path(file).read_text(encoding="utf-8")
            if "noProxy" not in config["server"]:
                config["server"]["noProxy"] = False
            if "host" not in config["server"]:
                config["server"]["host"] = "127.0.0.1"
            if "port" not in config["server"]:
                config["server"]["port"] = 8080
            if "activityMinStartTs" not in config["userConfig"]:
                config["userConfig"]["activityMinStartTs"] = 0
            if "activityMaxStartTs" not in config["userConfig"]:
                config["userConfig"]["activityMaxStartTs"] = 0
            if filename == "_.js":
                script_file = (
                    script_file.replace(
                        "@@@DOCTORATE_HOST@@@",
                        "NO_PROXY" if config["server"]["noProxy"] else config["server"]["host"],
                        1,
                    )
                    .replace(
                        "@@@DOCTORATE_PORT@@@",
                        str(config["server"]["port"]),
                        1,
                    )
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
            if "scriptConfig" not in config:
                config["scriptConfig"] = {}
            elif filename not in config["scriptConfig"]:
                config["scriptConfig"][filename] = False
            if filename == "_.js" or config["scriptConfig"][filename] is True:
                script = session.create_script(script_file)
                script.on("message", on_message)
                script.load()
        with Path("config/config.json").open("w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)
    except Exception:
        log.log("Caught exception in scriptmanager()", stdout=False, log_level="EXCEPTION")
        raise


if __name__ == "__main__":
    try:
        main("platform-tools\\adb.exe", 30, threading.Event(), sys.version_info)
    except Exception:
        log.log("Caught exception in main()", stdout=False, log_level="EXCEPTION")
        raise
