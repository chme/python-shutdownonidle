import argparse
import json
import logging
import os
import re
import sched
import subprocess
import sys
import time


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
