# Shutdown on idle

shutdownonidle: Idle System Checker and Shutdown Utility

This utility script monitors system activity to determine if
the system is idle. When running as a daemon, it periodically
performs checks. If a configured number of consecutive checks
indicate no activity, the system is considered idle. Depending
on the configured action, the script can then initiate a
shutdown or suspend the system.

## Available Actions

The following actions are available when the system is deemed idle:

- `shutdown`: Shuts down the system.
- `suspend`: Suspends the system.
- `noop`: Performs no action. Useful for testing and debugging.

## Available Checks

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

``` bash
usage: shutdownonidle [-h] [-i INTERVAL_SECONDS] [-t IDLE_THRESHOLD] [-a ACTION] [-c CHECK] [-v] [-f [FILE ...]] [--owntone-url OWNTONE_URL] [-r]

options:
  -h, --help            show this help message and exit
  -i, --interval INTERVAL_SECONDS
                        Sets the time interval (in seconds) between consecutive idle checks. Default: 60.
  -t, --threshold IDLE_THRESHOLD
                        Specifies the number of consecutive idle checks required to declare the system idle. Default: 5.
  -a, --action ACTION   Defines the action to take when the system is deemed idle. Supported values: shutdown, suspend, noop. Default: shutdown.
  -c, --checks CHECK    Provides a comma-separated list of checks to determine system idleness. See "Available Checks" for details. Default: session.
  -v, --verbose         Enable verbose logging.
  -f, --file [FILE ...]
                        Monitors the modification timestamps of the specified FILE(s) to check for activity.
  --owntone-url OWNTONE_URL
                        Specifies the URL of the OwnTone server for monitoring playback and library status.
  -r, --reboot-if-required
                        Allows the system to reboot if a reboot is required. This is triggered by the presence of the file `/var/run/reboot-required`. Note: This option is effective
                        only when the action is set to `suspend`
```

## Example systemd service file

``` properties
[Unit]
Description=Shutdown on idle
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/shutdownonidle
ExecStart=/usr/bin/python3 /opt/shutdownonidle/shutdownonidle.py
Restart=always

[Install]
WantedBy=multi-user.target
```
