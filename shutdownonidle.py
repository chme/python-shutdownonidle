import argparse
import json
import logging
import os
import re
import sched
import subprocess
import sys
import time
import typing
import urllib.error
import urllib.parse
import urllib.request

from email.message import Message


DEFAULT_INTERVAL_SECONDS = 60
DEFAULT_PRIORITY = 5
DEFAULT_IDLE_THRESHOLD = 5

ACTION_SHUTDOWN = "shutdown"
ACTION_SUSPEND = "suspend"
ACTION_NOOP = "noop"

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter(fmt="%(levelname)s: %(message)s", datefmt="%Y.%m.%d %H:%M:%S")
handler = logging.StreamHandler(stream=sys.stdout)
handler.setFormatter(formatter)
logger.addHandler(handler)


class IdleState:
    count = 0
    last_check_ts = time.time()

    def reset(self):
        self.count = 0
        self.last_check_ts = time.time()

    def increment(self):
        self.count += 1
        self.last_check_ts = time.time()


def main(args: list[str] | None = None) -> int:
    """Run the main program.

    Parameters:
        args: Arguments passed from the command line.

    Returns:
        An exit code.
    """
    parser = get_parser()
    opts = parser.parse_args(args=args)

    if opts.verbose:
        logger.setLevel(logging.DEBUG)
    logger.info("Arguments: %s", opts)

    state = IdleState()

    my_scheduler = sched.scheduler(time.time, time.sleep)
    my_scheduler.enter(opts.interval, DEFAULT_PRIORITY, run, (my_scheduler, state, opts))

    logger.info(f"Scheduled first idle check to run in {opts.interval} seconds")
    my_scheduler.run()

    return 0


def get_parser() -> argparse.ArgumentParser:
    """Return the CLI argument parser.

    Returns:
        An argparse parser.
    """
    parser = argparse.ArgumentParser(
        prog="shutdownonidle",
        description=re.sub(
            r"\n *",
            "\n",
            f"""
            Utility script to check if a system is idle.

            When running this script as a daemon process, it will periodically run 
            checks to identify if the system is idle. When a set number of consecutive 
            runs indicate no activity, the system is deemed idle.
            The script will then initiate a shutdown or a suspend.

            ### Checks

            To determin if a system is idle, different checks can be enabled:

            - session: Checks that no user session exists (uses the "who" command).
            - smb: Checks that no SMB session exists (uses the "smbstatus" command).
            - files: Checks that a given list of files were not modified between two runs (uses the files mtime).
            - owntone: Checks if OwnTone is not playing and no library scan is running (requires setting the "owntone-url").

            If no check are set via the CLI argument, only the "session" check will be performed.
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-i",
        "--interval",
        action="store",
        type=int,
        default=DEFAULT_INTERVAL_SECONDS,
        metavar="INTERVAL_SECONDS",
        dest="interval",
        help="Specifies the time interval in seconds for checking if the system is idle. "
        "Default: %(default)s.",
    )
    parser.add_argument(
        "-t",
        "--threshold",
        action="store",
        type=int,
        default=DEFAULT_IDLE_THRESHOLD,
        metavar="IDLE_THRESHOLD",
        dest="threshold",
        help="Specifies number of consecutive checks after which the system is considered as idle. "
        "Default: %(default)s.",
    )
    parser.add_argument(
        "-a",
        "--action",
        action="store",
        default=ACTION_SHUTDOWN,
        choices=[ACTION_SHUTDOWN, ACTION_SUSPEND, ACTION_NOOP],
        metavar="ACTION",
        dest="action",
        help="Action to perform, when the system is considered idle. "
        "Supported values: %(choices)s. Default: %(default)s.",
    )
    parser.add_argument(
        "-c",
        "--checks",
        action="store",
        type=_comma_separated_list,
        default=["session"],
        metavar="CHECK",
        dest="checks",
        help="A comma-separated list of checks to perform, "
        "in order to identify if the system is idle or not. "
        "See available checks in the description. "
        "Default: session.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        dest="verbose",
        help="Enable verbose logging.",
    )
    parser.add_argument(
        "-f",
        "--file",
        action="store",
        type=argparse.FileType("r"),
        required=False,
        nargs="*",
        metavar="FILE",
        dest="files",
        help="Check the FILE(s) modification timestamp to determine if the system is idle or not.",
    )
    parser.add_argument(
        "--owntone-url",
        action="store",
        required=False,
        metavar="OWNTONE_URL",
        dest="owntone_url",
        help="URL of the OwnTone server to check player and library state.",
    )
    return parser


def _comma_separated_list(value: str) -> list[str]:
    return value.split(",")


def run(my_scheduler: sched.scheduler, state: IdleState, opts: argparse.Namespace):
    try:
        active, inactive, skipped = run_checks(state, opts)
        if active:
            state.reset()
            logger.info(f"Activity detected, resetting idle counter {state.count}/{opts.threshold}: active = {active}, inactive = {inactive}, skipped = {skipped}")
        else:
            state.increment()
            logger.info(f"No activity detected, incrementing idle counter {state.count}/{opts.threshold}: active = {active}, inactive = {inactive}, skipped = {skipped}")

        if state.count >= opts.threshold:
            logger.info(f"Idle counter threshold reached {state.count} >= {opts.threshold}: initiating {opts.action}")
            state.reset()
            on_idle(opts.action)
        my_scheduler.enter(opts.interval, DEFAULT_PRIORITY, run, (my_scheduler, state, opts))
    except Exception:
        logger.exception("Error occurred trying to check the idle state.")


def run_checks(state: IdleState, opts: argparse.Namespace) -> tuple[list[str], list[str], list[str]]:
    active:   list[str] = []
    inactive: list[str] = []
    skipped:  list[str] = []
    skipped.extend(opts.checks)
    for check in opts.checks:
        if check == "session":
            skipped.remove(check)
            if check_user_sessions():
                active.append(check)
                break
            else:
                inactive.append(check)
        elif check == "smb":
            skipped.remove(check)
            if check_smbsessions():
                active.append(check)
                break
            else:
                inactive.append(check)
        elif check == "files":
            skipped.remove(check)
            if check_files(state, opts):
                active.append(check)
                break
            else:
                inactive.append(check)
        elif check == "owntone":
            skipped.remove(check)
            if check_owntone(opts):
                active.append(check)
                break
            else:
                inactive.append(check)
        else:
            logger.warn("Ignoring unsupported check: %s", check)
    return active, inactive, skipped


def on_idle(action: str) -> None:
    if action == ACTION_SHUTDOWN:
        exec("shutdown", "now")
    elif action == ACTION_SUSPEND:
        exec("systemctl", "suspend")


def check_user_sessions() -> bool:
    sessions = exec("who", "-s")
    return len(sessions.splitlines()) > 0


def check_smbsessions() -> bool:
    output = exec("smbstatus", "-bj")
    smbstatus = json.loads(output)
    return bool(smbstatus.get("sessions", {}))


def check_files(state: IdleState, opts: argparse.Namespace) -> bool:
    if not opts.files:
        return False

    for f in opts.files:
        if os.path.getmtime(f.name) > state.last_check_ts:
            logger.debug(f"File modification detected on '{f.name}'") 
            return True
    return False


def check_owntone(opts: argparse.Namespace) -> bool:
    return _check_owntone_playing(opts) or _check_owntone_scanning(opts)


def _check_owntone_playing(opts: argparse.Namespace) -> bool:
    url = f"{opts.owntone_url}/api/player"
    logger.debug("owntone: Get player state: %s", url)
    response = request(url)
    logger.debug("owntone: Player state response: %s", response)
    if response.status == 200:
        json_response = response.json()
        return json_response.get("state", "") == "play"
    return False


def _check_owntone_scanning(opts: argparse.Namespace) -> bool:
    url = f"{opts.owntone_url}/api/library"
    logger.debug("owntone: Get library state: %s", url)
    response = request(url)
    logger.debug("owntone: Library state response: %s", response)
    if response.status == 200:
        json_response = response.json()
        return json_response.get("updating", False)
    return False


class Response(typing.NamedTuple):
    """Container for HTTP response."""

    body: str
    headers: Message
    status: int
    error_count: int = 0

    def json(self) -> typing.Any:
        """
        Decode body's JSON.

        Returns:
            Pythonic representation of the JSON object
        """
        try:
            output = json.loads(self.body)
        except json.JSONDecodeError:
            output = ""
        return output


def request(
    url: str,
    data: dict = None,
    params: dict = None,
    headers: dict = None,
    method: str = "GET",
    data_as_json: bool = True,
    error_count: int = 0,
) -> Response:
    """
    Perform HTTP request.

    Args:
        url: url to fetch
        data: dict of keys/values to be encoded and submitted
        params: dict of keys/values to be encoded in URL query string
        headers: optional dict of request headers
        method: HTTP method , such as GET or POST
        data_as_json: if True, data will be JSON-encoded
        error_count: optional current count of HTTP errors, to manage recursion

    Raises:
        URLError: if url starts with anything other than "http"

    Returns:
        A dict with headers, body, status code, and, if applicable, object
        rendered from JSON
    """
    if not url.startswith("http"):
        raise urllib.error.URLError("Incorrect and possibly insecure protocol in url")
    method = method.upper()
    request_data = None
    headers = headers or {}
    data = data or {}
    params = params or {}
    headers = {"Accept": "application/json", **headers}

    if method == "GET":
        params = {**params, **data}
        data = None

    if params:
        url += "?" + urllib.parse.urlencode(params, doseq=True, safe="/")

    if data:
        if data_as_json:
            request_data = json.dumps(data).encode()
            headers["Content-Type"] = "application/json; charset=UTF-8"
        else:
            request_data = urllib.parse.urlencode(data).encode()

    httprequest = urllib.request.Request(
        url, data=request_data, headers=headers, method=method
    )

    try:
        with urllib.request.urlopen(httprequest) as httpresponse:
            response = Response(
                headers=httpresponse.headers,
                status=httpresponse.status,
                body=httpresponse.read().decode(
                    httpresponse.headers.get_content_charset("utf-8")
                ),
            )
    except urllib.error.HTTPError as e:
        response = Response(
            body=str(e.reason),
            headers=e.headers,
            status=e.code,
            error_count=error_count + 1,
        )
    except urllib.error.URLError as e:
        response = Response(
            body=str(e.reason),
            headers=None,
            status=999,
            error_count=error_count + 1,
        )

    return response


def exec(command: str, *args: str) -> str:
    """Run a shell command.

    Parameters:
        command: The shell command to execute.
        *args:   Arguments passed to the Git command.

    Returns:
        The output of the command.
    """
    return subprocess.check_output(
        [command, *args],
        text=True,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
