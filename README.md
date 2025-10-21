# mbox-reader

Kotlin/Swing mailbox inspector for `.mbox` archives. GUI launches by default and uses SwingBox for rich HTML rendering.

## Quick Install

> ⚠️ Review the install script before running if you have any concerns.

macOS / Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/allquixotic/mbox_reader/main/scripts/install.sh | bash
```

Windows (PowerShell):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/allquixotic/mbox_reader/main/scripts/install.ps1 | iex"
```

Both installers download Temurin Java 25 and Kotlin 2.2.20, place them under a local app directory, install the `mbox-reader` launcher in your user-level bin path, and grab the latest `mbox_reader.main.kts`.

Launch after installation:

```bash
mbox-reader
```

## Development Notes

- The GUI script lives at `mbox_reader.main.kts`.
- Installer helpers are in `scripts/install.sh` and `scripts/install.ps1`.
- SwingBox is resolved at runtime via script annotations; no additional build tooling required.
