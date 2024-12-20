# Copyright 2024 Christian Meffert
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This file includes code from the https://github.com/bowmanjd/pysimpleurl, which is also
# licensed under the Apache License, Version 2.0

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
ACTION_REBOOT = "reboot"
ACTION_NOOP = "noop"

ACTIONS = {
    ACTION_SHUTDOWN: ["shutdown", "now"],
    ACTION_SUSPEND: ["systemctl", "suspend"],
    ACTION_REBOOT: ["reboot"],
    ACTION_NOOP: [],
}

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter(
    fmt="%(levelname)s: %(message)s", datefmt="%Y.%m.%d %H:%M:%S"
)
handler = logging.StreamHandler(stream=sys.stdout)
handler.setFormatter(formatter)
logger.addHandler(handler)


def _comma_separated_list(value: str) -> list[str]:
    return value.split(",")


class IdleState:
    count = 0
    last_check_ts = time.time()

    def reset(self):
        self.count = 0
        self.last_check_ts = time.time()

    def increment(self):
        self.count += 1
        self.last_check_ts = time.time()


class ShutdownOnIdle:
    def __init__(self):
        self.reboot_required_file = "/var/run/reboot-required"
        self.state = IdleState()

    def main(self, args: list[str] | None = None) -> int:
        """Run the main program.

        Parameters:
            args: Arguments passed from the command line.

        Returns:
            An exit code.
        """
        parser = self.get_parser()
        opts = parser.parse_args(args=args)

        if opts.verbose:
            logger.setLevel(logging.DEBUG)
        logger.info("Arguments: %s", opts)

        my_scheduler = sched.scheduler(time.time, time.sleep)
        my_scheduler.enter(
            opts.interval, DEFAULT_PRIORITY, self.run, (my_scheduler, self.state, opts)
        )

        logger.info(f"Scheduled first idle check to run in {opts.interval} seconds")
        my_scheduler.run()

        return 0

    def get_parser(self) -> argparse.ArgumentParser:
        """Return the CLI argument parser.

        Returns:
            An argparse parser.
        """
        parser = argparse.ArgumentParser(
            prog="shutdownonidle",
            description=re.sub(
                r"\n *",
                "\n",
                """
                shutdownonidle: Idle System Checker and Shutdown Utility

                This utility script monitors system activity to determine if
                the system is idle. When running as a daemon, it periodically
                performs checks. If a configured number of consecutive checks
                indicate no activity, the system is considered idle. Depending
                on the configured action, the script can then initiate a
                shutdown or suspend the system.

                **Available Actions**

                The following actions are available when the system is deemed idle:

                - `shutdown`: Shuts down the system.
                - `suspend`: Suspends the system.
                - `noop`: Performs no action. Useful for testing and debugging.

                **Available Checks**

                Various checks can be enabled to determine system idleness:

                - `session`: Verifies that no active user sessions exist using
                    the `who` command.
                - `smb`: Confirms that no active SMB sessions exist by utilizing
                    the `smbstatus` command.
                - `files`: Checks if a specified list of files has remained
                    unmodified between consecutive runs, based on their
                    modification time (mtime).
                - `owntone`: Monitors the OwnTone server to ensure it is neither
                    playing audio nor scanning the library. This check requires
                    the `--owntone-url` option to be set.

                Default Behavior: If no checks are explicitly specified, only the session check will be performed.
                """,
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
            help="Sets the time interval (in seconds) between consecutive idle checks. "
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
            help="Specifies the number of consecutive idle checks required to declare the system idle. "
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
            help="Defines the action to take when the system is deemed idle. "
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
            help='Provides a comma-separated list of checks to determine system idleness. See "Available Checks" for details. '
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
            help="Monitors the modification timestamps of the specified FILE(s) to check for activity.",
        )
        parser.add_argument(
            "--owntone-url",
            action="store",
            required=False,
            metavar="OWNTONE_URL",
            dest="owntone_url",
            help="Specifies the URL of the OwnTone server for monitoring playback and library status.",
        )
        parser.add_argument(
            "-r",
            "--reboot-if-required",
            action="store_true",
            dest="reboot",
            help="Allows the system to reboot if a reboot is required. This is triggered by the presence of the file `/var/run/reboot-required`. Note: This option is effective only when the action is set to `suspend`",
        )
        return parser

    def run(
        self, my_scheduler: sched.scheduler, state: IdleState, opts: argparse.Namespace
    ):
        try:
            active, inactive, skipped = self.run_checks(state, opts)
            if active:
                state.reset()
                logger.info(
                    f"Activity detected, resetting idle counter {state.count}/{opts.threshold}: active = {active}, inactive = {inactive}, skipped = {skipped}"
                )
            else:
                state.increment()
                logger.info(
                    f"No activity detected, incrementing idle counter {state.count}/{opts.threshold}: active = {active}, inactive = {inactive}, skipped = {skipped}"
                )

            if state.count >= opts.threshold:
                logger.info(
                    f"Idle counter threshold reached {state.count} >= {opts.threshold}: initiating {opts.action}"
                )
                self.on_idle(opts)
                return

            my_scheduler.enter(
                opts.interval, DEFAULT_PRIORITY, self.run, (my_scheduler, state, opts)
            )
        except Exception:
            logger.exception("Error occurred trying to check the idle state.")
            sys.exit(1)

    def run_checks(
        self, state: IdleState, opts: argparse.Namespace
    ) -> tuple[list[str], list[str], list[str]]:
        active: list[str] = []
        inactive: list[str] = []
        skipped: list[str] = []
        skipped.extend(opts.checks)
        for check in opts.checks:
            if check == "session":
                skipped.remove(check)
                if self.check_user_sessions():
                    active.append(check)
                    break
                else:
                    inactive.append(check)
            elif check == "smb":
                skipped.remove(check)
                if self.check_smbsessions():
                    active.append(check)
                    break
                else:
                    inactive.append(check)
            elif check == "files":
                skipped.remove(check)
                if self.check_files(state, opts):
                    active.append(check)
                    break
                else:
                    inactive.append(check)
            elif check == "owntone":
                skipped.remove(check)
                if self.check_owntone(opts):
                    active.append(check)
                    break
                else:
                    inactive.append(check)
            else:
                logger.warn("Ignoring unsupported check: %s", check)
        return active, inactive, skipped

    def on_idle(self, opts: argparse.Namespace) -> None:
        action = opts.action
        if action == ACTION_SUSPEND and opts.reboot and self.check_reboot_required():
            action = ACTION_REBOOT
        logger.info("Running idle action '%s'", action)
        args = ACTIONS.get(action)
        if args:
            self.exec(*args)

    def check_reboot_required(self) -> bool:
        return os.path.isfile(self.reboot_required_file)

    def check_user_sessions(self) -> bool:
        output = self.exec("who", "-s")
        return len(output.get("output").splitlines()) > 0

    def check_smbsessions(self) -> bool:
        output = self.exec("smbstatus", "-bj")
        smbstatus = json.loads(output.get("output"))
        return bool(smbstatus.get("sessions", {}))

    def check_files(self, state: IdleState, opts: argparse.Namespace) -> bool:
        if not opts.files:
            return False

        for f in opts.files:
            if os.path.getmtime(f.name) > state.last_check_ts:
                logger.debug(f"File modification detected on '{f.name}'")
                return True
        return False

    def check_owntone(self, opts: argparse.Namespace) -> bool:
        return self._check_owntone_playing(opts) or self._check_owntone_scanning(opts)

    def _check_owntone_playing(self, opts: argparse.Namespace) -> bool:
        url = f"{opts.owntone_url}/api/player"
        logger.debug("owntone: Get player state: %s", url)
        response = request(url)
        logger.debug("owntone: Player state response: %s", response)
        if response.status == 200:
            json_response = response.json()
            return json_response.get("state", "") == "play"
        return False

    def _check_owntone_scanning(self, opts: argparse.Namespace) -> bool:
        url = f"{opts.owntone_url}/api/library"
        logger.debug("owntone: Get library state: %s", url)
        response = request(url)
        logger.debug("owntone: Library state response: %s", response)
        if response.status == 200:
            json_response = response.json()
            return json_response.get("updating", False)
        return False

    def exec(self, command: str, *args: str) -> dict[str, str | list[str], float]:
        """Run a shell command.

        Parameters:
            command: The shell command to execute.
            *args:   Arguments passed to the Git command.

        Returns:
            The output of the command.
        """
        logger.debug("Executing command %s with arg = %s", command, args)
        start_time = time.time()
        output = self._exec(command, args)
        end_time = time.time()
        duration = end_time - start_time
        logger.debug(
            "Executed command %s with arg = %s in %f seconds", command, args, duration
        )
        return {
            "output": output,
            "command": [command] + list(args),
            "start": start_time,
            "end": end_time,
            "duration": duration,
        }

    def _exec(self, command: str, *args: str) -> str:
        return subprocess.check_output(
            [command, *args],
            text=True,
        )


class Response(typing.NamedTuple):
    """Container for HTTP response."""

    # Original code from https://github.com/bowmanjd/pysimpleurl

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

    # Original code from https://github.com/bowmanjd/pysimpleurl

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


if __name__ == "__main__":
    app = ShutdownOnIdle()
    sys.exit(app.main(sys.argv[1:]))
