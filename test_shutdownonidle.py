import tempfile
import unittest

from shutdownonidle import ACTION_SHUTDOWN, ACTIONS, ShutdownOnIdle


class MyShutdownOnIdle(ShutdownOnIdle):
    def __init__(self):
        super().__init__()
        self.test_executed = []
        self.test_commands = []

    def _exec(self, command: str, *args: str) -> str:
        self.test_executed.append([command] + list(*args))
        out = self.test_commands.pop(0)
        return out


class TestStringMethods(unittest.TestCase):
    def setUp(self):
        self.under_test = MyShutdownOnIdle()

    def execute(self, *args: str):
        return self.under_test.main(list(args))

    def with_command(self, cmd_output: str):
        self.under_test.test_commands.append(cmd_output)

    def assertIdleCount(self, count: int):
        self.assertEqual(self.under_test.state.count, count)

    def assertOnIdleAction(self, action):
        idle_command = self.under_test.test_executed[-1]
        self.assertEqual(idle_command, ACTIONS.get(action))

    def test_help(self):
        with self.assertRaises(SystemExit):
            self.execute("--help")

    def test_session_check(self):
        # arrange
        self.with_command("testuser")  # session
        self.with_command("")  # session
        self.with_command("")  # shutdown

        # act
        exit_code = self.execute(
            "--interval", "1", "--threshold", "1", "--checks", "session"
        )

        # assert
        self.assertEqual(exit_code, 0)
        self.assertIdleCount(1)
        self.assertOnIdleAction(ACTION_SHUTDOWN)

    def test_smb(self):
        # arrange
        self.with_command(
            '{"timestamp": "2024-12-20T11:14:44.161125+0000", "sessions": {"xxx": {"session_id": "1", "uid": 1000, "gid": 1000}}}'
        )  # smb
        self.with_command('{"timestamp": "2024-12-20T11:14:44.161125+0000"}')  # smb
        self.with_command("")  # shutdown

        # act
        exit_code = self.execute(
            "--interval", "1", "--threshold", "1", "--checks", "smb"
        )

        # assert
        self.assertEqual(exit_code, 0)
        self.assertIdleCount(1)
        self.assertOnIdleAction(ACTION_SHUTDOWN)

    def test_file(self):
        # arrange
        self.with_command("")  # shutdown

        # act
        with tempfile.NamedTemporaryFile() as fp:
            exit_code = self.execute(
                "--interval",
                "1",
                "--threshold",
                "1",
                "--checks",
                "file",
                "--file",
                fp.name,
            )

            # assert
            self.assertEqual(exit_code, 0)
            self.assertIdleCount(1)
            self.assertOnIdleAction(ACTION_SHUTDOWN)


if __name__ == "__main__":
    unittest.main()
