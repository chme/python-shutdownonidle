import argparse
import json
import logging
import sched
import subprocess
import sys
import time


DEFAULT_INTERVAL_SECONDS = 60
DEFAULT_PRIORITY = 5
DEFAULT_IDLE_THRESHOLD = 5

ACTION_SHUTDOWN = "shutdown"
ACTION_SUSPEND = "suspend"

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter(fmt="%(levelname)s: %(message)s", datefmt="%Y.%m.%d %H:%M:%S")
handler = logging.StreamHandler(stream=sys.stdout)
handler.setFormatter(formatter)
logger.addHandler(handler)


class IdleState:
    count = 0

    def reset(self):
        self.count = 0

    def increment(self):
        self.count += 1


def main(args: list[str] | None = None) -> int:
    """Run the main program.

    Parameters:
        args: Arguments passed from the command line.

    Returns:
        An exit code.
    """
    parser = get_parser()
    opts = parser.parse_args(args=args)

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
    parser = argparse.ArgumentParser(prog="shutdownonidle")
    parser.add_argument(
        "-i",
        "--interval",
        action="store",
        type=int,
        default=DEFAULT_INTERVAL_SECONDS,
        metavar="INTERVAL_SECONDS",
        dest="interval",
        help="Specifies the time interval in seconds for checking if the system is idle. Default: %(default)s.",
    )
    parser.add_argument(
        "-t",
        "--threshold",
        action="store",
        type=int,
        default=DEFAULT_IDLE_THRESHOLD,
        metavar="IDLE_THRESHOLD",
        dest="threshold",
        help="Specifies number of consecutive checks after which the system is considered as idle. Default: %(default)s.",
    )
    parser.add_argument(
        "-a",
        "--action",
        action="store",
        default=ACTION_SHUTDOWN,
        choices=[ACTION_SHUTDOWN, ACTION_SUSPEND],
        metavar="ACTION",
        dest="action",
        help="Action to perform, when the system is considered idle. Supported values: %(choices)s. Default: %(default)s.",
    )
    return parser


def run(my_scheduler: sched.scheduler, state: IdleState, opts: argparse.ArgumentParser):
    try:
        has_login = check_user_sessions()
        has_smbsession = check_smbsessions()
        if has_login or has_smbsession:
            state.reset()
            logger.info(f"Activity detected, resetting idle counter {state.count}: active login session = {has_login}, active SMB session = {has_smbsession}")
        else:
            state.increment()
            logger.info(f"No activity detected, incrementing idle counter {state.count}: active login session = {has_login}, active SMB session = {has_smbsession}")

        if state.count >= opts.threshold:
            logger.info(f"Idle counter threshold reached {state.count} >= {opts.threshold}: running on_idle action")
            state.reset()
            on_idle(opts.action)
        my_scheduler.enter(opts.interval, DEFAULT_PRIORITY, run, (my_scheduler, state, opts))
    except Exception:
        logger.exception("Error occurred trying to check the idle state.")


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
