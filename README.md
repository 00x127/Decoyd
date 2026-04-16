<p align="center">
  <img src="/assets/logo.png" width="140"/>
</p>

<h1 align="center">Decoyd</h1>

A local honeypot and deception system for Windows, Linux, and macOS. Deploy convincing fake files across your machine and get alerted the moment anything touches them.

<p align="center">
  <img src="/assets/demo.gif" width="700"/>
</p>

---

## What it does

Decoyd plants bait files - fake password lists, crypto wallets, credential spreadsheets - and silently monitors them. If anything reads, copies, modifies, or moves them, you get a desktop notification and optional email alert within seconds.

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

```bash
chmod +x Decoyd.AppImage
./Decoyd.AppImage
```

**Dependencies (FUSE):**

```bash
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

```bash
./Decoyd.AppImage --appimage-extract
cd squashfs-root
./AppRun
```

---

### .deb (Ubuntu / Debian)

```bash
sudo dpkg -i Decoyd.deb
```

Run from app menu or:

```bash
decoyd
```

---

### Better read detection (optional)

```bash
# Ubuntu / Debian
sudo apt install inotify-tools

# Fedora / RHEL
sudo dnf install inotify-tools

# Arch
sudo pacman -S inotify-tools
```

Falls back to polling if not installed.

---

## Email setup

| Provider | Host                  | Port |
| -------- | --------------------- | ---- |
| Gmail    | smtp.gmail.com        | 587  |
| Brevo    | smtp-relay.brevo.com  | 587  |
| Mailgun  | smtp.mailgun.org      | 587  |
| Outlook  | smtp-mail.outlook.com | 587  |

Gmail requires an App Password:
[https://myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
