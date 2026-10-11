# SSH MCP

Rust MCP stdio server for user-configured SSH hosts. It supports password and private-key authentication, checks host keys against the local `~/.ssh/known_hosts`, and keeps interactive shells alive between MCP calls.

## Host configuration

Copy `host.example.json` to `host.json` in this MCP directory and replace the example values. Configure the MCP client's `cwd` as this same directory so the server loads `host.json`. You can override the path with `SSH_HOST_FILE`; the older `SSH_SERVERS_FILE` environment variable remains supported. `host.json` is excluded from Git because it contains credentials. Restrict its Windows file permissions.

The JSON can be a single host object, an array of hosts, or an object with a `hosts` array. Each host has a unique `name`, `destination`, optional `port` (default `22`), `username`, `authentication`, and optional `description`. Authentication supports `password` or `private_key` with a key path and optional passphrase. Unknown or changed server keys are rejected; verify and add the key to the current user's `~/.ssh/known_hosts` first.

The MCP reloads `host.json` whenever `list_servers` or `open_session` is called. Changes therefore apply to the next tool call without restarting the MCP process. Existing SSH sessions remain connected with their original settings; close and reopen a session to apply host changes. If the file is temporarily invalid JSON, the tool returns a reload error and retains the last valid configuration.

## MCP tools

- `list_servers`: list host names and authentication types without revealing credentials.
- `open_session`: authenticate and return a reusable `session_id`.
- `send_command`: execute a command in that persistent shell. `cd` and exported variables persist. Set `isolated: true` to run a one-shot command and return its exit code without persisting shell changes.
- `close_session`: close the SSH session.

Sessions last for the MCP process lifetime and expire after the idle timeout. Remote commands run with the registered account's permissions; use least-privilege accounts and register only approved hosts.

## Build

Requires Rust 1.89+ and Cargo. From this directory:

```powershell
cargo build --release --locked
.\target\release\ssh-mcp.exe
```

Set the MCP client's `command` to the executable's absolute path and `cwd` to this directory. Optional environment settings: `SSH_HOST_FILE`, `SSH_CONNECT_TIMEOUT_SECS` (1–60), `SSH_IDLE_TIMEOUT_SECS` (30–86400; default 1800), and `SSH_USER`.
