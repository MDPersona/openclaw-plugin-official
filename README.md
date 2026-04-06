# MDPersona for OpenClaw

MDPersona is a preference profile service that lets you define your personal tastes and habits once — travel preferences, media interests, dietary requirements, communication style — and have them automatically available to any AI agent you work with. This plugin syncs your encrypted profiles into your OpenClaw workspace on demand, so your agent always knows your preferences without you repeating yourself.

## Installation

```
openclaw plugins install mdpersona-plugin
```

## Setup

After installation, run a sync to fetch your profiles:

```
openclaw mdpersona sync
```

You will be prompted for your MDPersona email and password. Your password is never stored — it is used in-memory only to decrypt your profiles, then immediately zeroed.

## Commands

| Command | Description |
|---|---|
| `openclaw mdpersona sync [--email <email>]` | Fetch and decrypt your MDPersona profiles into the workspace |
| `openclaw mdpersona status` | Show last sync time and loaded profiles |
| `openclaw mdpersona uninstall` | Remove all MDPersona data from the workspace |

## Profile files

The plugin writes the following files to your workspace:

- **Reservations.md** — travel, hotel, restaurant, transport and activity preferences
- **Media.md** — news filtering, entertainment recommendations and alert preferences

These files are referenced in `AGENTS.md` automatically, so your agent reads them at the start of every session.

## Privacy

Your password **never leaves your device** and is **never stored**. The MDPersona server stores only AES-256-GCM encrypted blobs; decryption happens locally using your password as the key material (PBKDF2-SHA256, 100,000 iterations). The password buffer is zeroed from memory immediately after decryption.

For more information visit [mdpersona.com](https://mdpersona.com).
