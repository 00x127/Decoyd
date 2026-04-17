<p align="center">
  <img src="/assets/logo.png" width="140"/>
</p>

<h1 align="center">Decoyd</h1>

<p align="center">
  A local honeypot and deception system for Windows, Linux, and macOS
</p>

<p align="center">
  <img src="/assets/demo.gif" width="700"/>
</p>

---

## What it does

Decoyd plants bait files - fake password lists, crypto wallets, credential spreadsheets - and silently monitors them.

If anything reads, copies, modifies, or moves them, you get a desktop notification and optional email alert within seconds.

| Event                | Detection                                   |
| -------------------- | ------------------------------------------- |
| File read (Linux)    | `inotifywait` (falls back to atime polling) |
| File read (Windows)  | Security Event Log (Event ID 4663 via SACL) |
| File read (fallback) | Access-time polling (3s interval)           |
| File copied          | SHA-256 hash matching                       |
| File modified        | chokidar watcher                            |
| File moved/deleted   | chokidar + short window check               |

---

## Features

* Preset bait files (`passwords.txt`, `wallet_backup.json`, `accounts.xlsx`)
* Fully custom bait files (name, content, location)
* Desktop notifications on access
* Silent mode (no alerts to attacker)
* Optional email alerts (SMTP)
* Stealth mode (tray-only)
* Persistent event log with filtering
* Fully offline, no telemetry

---

## Installation

Download from the [Releases](../../releases) page.

* **Windows:** Run `Decoyd.exe`
* **macOS:** Open `Decoyd.dmg` -> drag to Applications
* **Linux:** See below

---

## Linux

### AppImage

```bash id="2zqk3p"
chmod +x Decoyd.AppImage
./Decoyd.AppImage
```

**Dependencies (FUSE):**

```bash id="x5r8cw"
# Ubuntu / Debian (new)
sudo apt install libfuse2t64

# Ubuntu / Debian (old)
sudo apt install libfuse2

# Fedora / RHEL
sudo dnf install fuse

# Arch
sudo pacman -S fuse2
```

**No FUSE?**

```bash id="l7y2om"
./Decoyd.AppImage --appimage-extract
cd squashfs-root
./AppRun
```

---

### Better read detection (optional)

```bash id="yq9r1u"
# Ubuntu / Debian
sudo apt install inotify-tools

# Fedora / RHEL
sudo dnf install inotify-tools

# Arch
sudo pacman -S inotify-tools
```

Falls back to polling if not installed.
