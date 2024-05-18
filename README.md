# Shutdown on idle

Utility script to check if a system is idle.

When running this script as a daemon process, it will periodically run 
checks to identify if the system is idle. When a set number of consecutive 
runs indicate no activity, the system is deemed idle.
The script will then initiate a shutdown or a suspend.

__Checks__

To determin if a system is idle, different checks can be enabled:

- session: Checks that no user session exists (uses the "who" command).
- smb: Checks that no SMB session exists (uses the "smbstatus" command).
- files: Checks that a given list of files were not modified between two runs (uses the files mtime).
- owntone: Checks if OwnTone is not playing and no library scan is running (requires setting the "owntone-url").

If no check are set via the CLI argument, only the "session" check will be performed.

```
usage: shutdownonidle [-h] [-i INTERVAL_SECONDS] [-t IDLE_THRESHOLD] [-a ACTION] [-c CHECK] [-v] [-f [FILE ...]] [--owntone-url OWNTONE_URL]

options:
  -h, --help            show this help message and exit
  -i INTERVAL_SECONDS, --interval INTERVAL_SECONDS
                        Specifies the time interval in seconds for checking if the system is idle. Default: 60.
  -t IDLE_THRESHOLD, --threshold IDLE_THRESHOLD
                        Specifies number of consecutive checks after which the system is considered as idle. Default: 5.
  -a ACTION, --action ACTION
                        Action to perform, when the system is considered idle. Supported values: shutdown, suspend, noop. Default: shutdown.
  -c CHECK, --checks CHECK
                        A comma-separated list of checks to perform, in order to identify if the system is idle or not. See available checks in the description. Default: session.
  -v, --verbose         Enable verbose logging.
  -f [FILE ...], --file [FILE ...]
                        Check the FILE(s) modification timestamp to determine if the system is idle or not.
  --owntone-url OWNTONE_URL
                        URL of the OwnTone server to check player and library state.
```
