# SSH MCP

Rust MCP stdio server for user-registered SSH hosts. It authenticates with passwords or private keys, verifies host keys using the local `~/.ssh/known_hosts`, and keeps interactive shells alive between tool calls.

## Configure servers

Copy `servers.example.json` to `servers.json` in this directory and replace the example credentials. Or set `SSH_SERVERS_FILE` to a different file. `servers.json` is excluded by `.gitignore`; restrict its Windows file permissions because password credentials are stored as plaintext.

Each entry has a unique `name`, `destination`, optional `port` (default `22`), `username`, `authentication`, and optional `description`. Password and private key authentication are supported. The SSH host key must already be verified and present in the current user's `~/.ssh/known_hosts`; unknown or changed keys are rejected.

## Tools

- `list_servers`: list registered hosts and authentication types without exposing credentials.
- `open_session`: authenticate to a registered host and return a reusable `session_id`.
- `send_command`: run a command in that persistent shell. Directory and environment changes persist. Use `isolated: true` for a one-shot command that closes stdin and returns its exit code without persisting shell changes.
- `close_session`: close a session when finished.

Sessions exist only for the lifetime of this MCP process and expire after the configured idle timeout. A command timeout closes its session to prevent late output from mixing with later commands. Remote commands run with the registered account's permissions; use least-privilege accounts and register only approved hosts.

## Build

Requires Rust 1.89+ and Cargo. From this directory:

```powershell
cargo build --release --locked
.\target\release\ssh-mcp.exe
```

For MCP stdio configuration, set `command` to this executable's absolute path and `cwd` to this directory. Optional environment settings are `SSH_SERVERS_FILE`, `SSH_CONNECT_TIMEOUT_SECS` (1–60), `SSH_IDLE_TIMEOUT_SECS` (30–86400; default 1800), and `SSH_USER`.
