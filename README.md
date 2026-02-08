<p align="center">
  <img src="docs/banner.svg" alt="Safe Share — Dispersal Wolves" width="100%">
</p>

# Safe Share

**Temporary file sharing with limits and local-first defaults.**

Serves selected files with a random access token, expiration, download limits, access logs, and optional user-provided TLS.

## Start

```console
python src/safe_share.py ./release.zip
```

For a global `safe-share` command, run `python -m pip install .`.

Run the command with `--help` for every option. The tool works locally, collects no telemetry, and supports machine-readable output where applicable.

## Principles

- **Local first.** Host data stays on the host unless you explicitly configure a webhook.
- **Safe by default.** Inspection is read-only and mutation requires a deliberate command.
- **Small contract.** The tool solves one defensive job and reports its limits plainly.
- **Scriptable.** Stable exit codes and structured output make automation practical.

## Platform

The initial release targets Linux. Portable behavior is also tested on Windows where the underlying operating-system facilities allow it. See [the threat model](docs/threat-model.md) for trust boundaries and non-goals.

## Development

This repository uses **Python** and the standard library only. The default share binds to loopback, expires after 30 minutes, and permits one download. Binding another interface requires a certificate and private key.

```console
python -m compileall -q src
python -m unittest discover -s tests -v
```

## License

[MIT](LICENSE) © Dispersal Wolves.
