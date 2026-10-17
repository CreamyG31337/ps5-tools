# ps5-tools

Small, standalone tools for working with a jailbroken PS5 and its files. Each folder is its own
tool with its own README and tests. Python 3.9+, standard library only.

| Tool | What it does |
|---|---|
| [`orphan-scan/`](orphan-scan/) | Read-only scan of a console over FTP for leftover and inconsistent game content |
| [`self-tools/`](self-tools/) | Inspect, find, extract and SDK-patch fake-signed PS5 SELF files (for backporting) |
| [`backport/`](backport/) | Backport a game to an older firmware from its untouched files: SDK patching, missing-function stand-ins, release diffing. See [RECIPE.md](backport/RECIPE.md) |

These tools don't ship, download or decrypt any Sony or game files. You need your own console
and your own dumps.

## Tests

```
cd orphan-scan && python -m unittest discover -s tests
cd self-tools && python -m unittest discover -s tests
cd backport && python -m unittest discover -s tests
```

## License

MIT, see [LICENSE](LICENSE).
