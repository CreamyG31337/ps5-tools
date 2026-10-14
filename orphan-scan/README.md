# ps5-orphan-scan

A read-only scanner that finds leftover and inconsistent game content on a jailbroken PS5:
half-finished installs, DLC whose base game is gone, licenses for titles that aren't installed,
stale download tasks, stray `.pkg` files, and titles that `app.db` and the disk disagree about.

It only lists directories and downloads `app.db` to a temp file. It never writes to, renames or
deletes anything on the console. Clean up what it finds from the console's own UI where you can.

Python 3.9+, standard library only.

## Requirements

An FTP server running on the console with read access to `/user`, `/system_data` and `/data`,
for example the `ftpsrv` payload (port 2121, anonymous login).

## Usage

```
python ps5_orphan_scan.py --ip 192.168.0.50
python ps5_orphan_scan.py --ip 192.168.0.50 --console-fw 4.03 --json report.json
```

The IP can also come from the `PS5_IP` environment variable or a `ps5-ip.txt` file in the
current directory or next to the script.

| Option | Default | Meaning |
|---|---|---|
| `--ip` | `$PS5_IP`, then `ps5-ip.txt` | Console address |
| `--port` | 2121 | FTP port |
| `--console-fw` | not set | Firmware version (e.g. `4.03`). Turns on the "needs a backport" check. |
| `--offline DIR` | | Scan a local copy of the console's filesystem instead of FTP |
| `--json FILE` | | Also write a JSON report |
| `--all` | | Show every title in the disk-usage table, including empty system apps |
| `--max-depth` | 6 | Recursion depth for the stray `.pkg` search |
| `--min-pkg-size` | 1 MiB | An `app.pkg` smaller than this is flagged |
| `--timeout` | 30 | FTP command timeout in seconds |

Exit code: 0 if nothing was found, 1 if there are findings, 2 on a connection or usage error.

## Checks

| # | What it looks for |
|---|---|
| 1 | App content with no `appmeta` |
| 2 | `appmeta` with no app content |
| 3 | App folder with no `app.pkg`, a 0-byte or very small one, or temp/partial files |
| 4 | DLC (`addcont`) or a patch whose base game is not installed |
| 5 | A license `.rif` that matches no installed title |
| 6 | An installed fake package with no license |
| 7 | Leftover entries in `bgft/task` (download/install tasks) |
| 8 | A `/data/homebrew/backports/<TITLE>` folder for a title that isn't installed; with `--console-fw`, also an installed title that needs a newer firmware and has no backport |
| 9 | Titles in `app.db` with no files, and files with no `app.db` row |
| 10 | Stray `.pkg` files anywhere it searches |
| 11 | Disk usage per title (report table) |
| 12 | Extracted game folders in `/data`, `/mnt/usb*`, `/mnt/ext*` |

Each finding has a severity (CRITICAL, HIGH, MEDIUM, LOW, INFO). Homebrew and Sony system
apps are recognised and downgraded so they don't drown out real problems. The report ends with
a "suggested manual cleanup" list. Treat it as a list to check by hand, not a script to run.

## Tests

```
python -m unittest discover -s tests
```

The tests build a fake console filesystem in a temp directory and run every check against it.
