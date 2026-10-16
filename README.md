# SSH MCP

Rust-based MCP server that opens persistent SSH shell sessions over stdio. It supports password and private-key authentication, and checks server keys against the current user's `known_hosts` file.

## Features

- Load one or more SSH hosts from a local JSON registry.
- Reload registry changes on `list_servers` and `open_session` calls without restarting the MCP process.
- Run commands in persistent sessions or as isolated one-shot commands.
- Record the most recent tool failure for inspection with `debug`.
- Reject unknown or changed SSH server keys.

## Configuration

Copy [`host.example.json`](host.example.json) to `host.json` in the same directory as `ssh-mcp.exe`, then replace the placeholder values. By default, the server reads settings from this adjacent `host.json`; the MCP client's working directory does not affect that lookup. The registry accepts a single host object, an array of hosts, or an object containing a `hosts` array.

Each host has the following fields:

| Field | Required | Description |
| --- | --- | --- |
| `name` | Yes | Unique name used to select the host in MCP calls. |
| `destination` | Yes | Hostname or IP address. It may be prefixed with `username@`. |
| `port` | No | SSH port; defaults to `22`. |
| `username` | No | SSH account name. Can be supplied in `destination` or through `SSH_USER`. |
| `authentication` | Yes | An authentication object described below. |
| `description` | No | Human-readable label shown by `list_servers`. |

Authentication supports these forms:

```json
{"type":"password","password":"replace-me"}
```

```json
{"type":"private_key","private_key_path":"C:\\Users\\you\\.ssh\\id_ed25519","passphrase":""}
```

Use an absolute key path to avoid ambiguity about the process working directory. Before connecting, verify the SSH server fingerprint and add its key to the current user's `~/.ssh/known_hosts` file (`%USERPROFILE%\.ssh\known_hosts` on Windows). Unknown and changed keys are rejected; this server does not offer a prompt to trust a new key.

Set `SSH_HOST_FILE` to override the adjacent `host.json` path. The older `SSH_SERVERS_FILE` variable is also supported; relative override paths are resolved from the MCP process's working directory. `host.json` is Git-ignored because it contains credentials; restrict its filesystem permissions and never commit it.

The registry is reloaded on every `list_servers` and `open_session` call. A valid edit applies to the next call without restarting the process. If the file is temporarily invalid, the call reports a reload error and the last valid registry stays active. Existing sessions keep their original connection and credentials; close and reopen them to apply host changes.

## MCP tools

| Tool | Purpose |
| --- | --- |
| `list_servers` | Reload the registry and list host names, authentication types, and active session counts. Credentials are not returned. |
| `open_session` | Reload the registry, authenticate to a selected host, and return a reusable `session_id`. |
| `send_command` | Run a single-line command in a session and return its output and exit code. |
| `close_session` | Close a persistent SSH session. |
| `debug` | Return the latest failure's UTC time, operation, host/session context, and details. |

`send_command` uses the persistent shell by default, so directory changes and exported variables remain in effect for later commands. Set `isolated: true` to run a one-shot command without preserving shell changes. Isolated mode requires common POSIX shell utilities on the remote host, including `mktemp`, `cat`, and `rm`. The optional `timeout_secs` argument defaults to 30 seconds and is limited to 1–300 seconds. Sessions expire after the configured idle timeout and close when the MCP process exits.

The most recent failure is held in memory until another failure or process exit. Successful calls do not clear it. Nonzero remote command exit codes are recorded with their output. Command text and credentials are not recorded, but output from a failed remote command may be included and can contain sensitive data. Output is truncated at 64 KiB.

## Security

Anyone who can call this MCP's tools can run arbitrary remote commands with the permissions of a registered SSH account. There is no command allowlist or per-command confirmation. Do not register a root account; use a dedicated, restricted account with only the permissions the MCP needs, and register only approved hosts.

This server uses MCP over stdio and does not listen for network connections. Publishing this repository on GitHub does not by itself expose the running MCP process. Access depends on who can invoke the configured local process and on the credentials in the local, Git-ignored `host.json`.

## Build and test

Requires Rust 1.89 or later and Cargo. From the repository directory:

```powershell
cargo build --release --locked
cargo test --locked
```

The release executable is `target\release\ssh-mcp.exe` on Windows. After building from the repository root, copy the example registry beside it:

```powershell
Copy-Item .\host.example.json .\target\release\host.json
```

Replace the example credentials before use. Configure the MCP client to launch `ssh-mcp.exe`; its working directory can be set independently because the default registry path is resolved beside the executable.

## Environment variables

| Variable | Description |
| --- | --- |
| `SSH_HOST_FILE` | Path to the host registry. Takes precedence over `SSH_SERVERS_FILE`. |
| `SSH_SERVERS_FILE` | Legacy alias for the registry path. |
| `SSH_USER` | Fallback username when the host entry and destination omit one. |
| `SSH_CONNECT_TIMEOUT_SECS` | SSH connection timeout in seconds; accepted range is 1–60, default is 10. |
| `SSH_IDLE_TIMEOUT_SECS` | Idle session timeout in seconds; accepted range is 30–86400, default is 1800. |
