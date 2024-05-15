import argparse
import json
import logging
import sched
import subprocess
import sys
import time


DEFAULT_INTERVAL_SECONDS = 10
DEFAULT_PRIORITY = 5
DEFAULT_IDLE_THRESHOLD = 2

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter(fmt="%(asctime)s %(name)s.%(levelname)s: %(message)s", datefmt="%Y.%m.%d %H:%M:%S")
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
    my_scheduler.enter(DEFAULT_INTERVAL_SECONDS, DEFAULT_PRIORITY, run, (my_scheduler, state))

    logger.info(f"Scheduled first idle check to run in {DEFAULT_INTERVAL_SECONDS} seconds")
    my_scheduler.run()

    return 0


def get_parser() -> argparse.ArgumentParser:
    """Return the CLI argument parser.

    Returns:
        An argparse parser.
    """
    parser = argparse.ArgumentParser(prog="shutdownonidle")
    return parser


def run(my_scheduler: sched.scheduler, state: IdleState):
    has_login = check_user_sessions()
    has_smbsession = check_smbsessions()
    if has_login or has_smbsession:
        state.reset()
        logger.info(f"Activity detected, resetting idle counter {state.count}: active login session = {has_login}, active SMB session = {has_smbsession}")
    else:
        state.increment()
        logger.info(f"No activity detected, incrementing idle counter {state.count}: active login session = {has_login}, active SMB session = {has_smbsession}")

    if state.count >= DEFAULT_IDLE_THRESHOLD:
        logger.info(f"Idle counter threshold reached {state.count} >= {DEFAULT_IDLE_THRESHOLD}: running on_idle action")
        on_idle()
    my_scheduler.enter(DEFAULT_INTERVAL_SECONDS, DEFAULT_PRIORITY, run, (my_scheduler, state))


def on_idle() -> None:
    exec("shutdown", "now")


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
