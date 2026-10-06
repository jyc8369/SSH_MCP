use std::{collections::HashMap, env, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig},
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
};
use russh::{
    client::{self, Handler},
    keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate},
};
use schemars::JsonSchema;
use serde::Deserialize;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, mpsc, oneshot},
    time::{sleep, timeout},
};
use uuid::Uuid;

const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_BUFFER_BYTES: usize = MAX_OUTPUT_BYTES * 2;
const DEFAULT_COMMAND_TIMEOUT_SECS: u64 = 30;
const MAX_COMMAND_TIMEOUT_SECS: u64 = 300;
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 1800;

#[derive(Clone)]
struct SshServer {
    tool_router: ToolRouter<Self>,
    servers: Arc<HashMap<String, RegisteredServer>>,
    sessions: SessionStore,
    default_user: Option<String>,
    connect_timeout_secs: u64,
    idle_timeout_secs: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct RegisteredServer {
    name: String,
    destination: String,
    #[serde(default)]
    username: Option<String>,
    #[serde(default = "default_port")]
    port: u16,
    authentication: Authentication,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Authentication {
    Password {
        password: String,
    },
    PrivateKey {
        private_key_path: PathBuf,
        #[serde(default)]
        passphrase: Option<String>,
    },
}

impl Authentication {
    fn kind(&self) -> &'static str {
        match self {
            Self::Password { .. } => "password",
            Self::PrivateKey { .. } => "private_key",
        }
    }
}

#[derive(Clone)]
struct SessionStore(Arc<Mutex<HashMap<String, Arc<SessionHandle>>>>);

struct SessionHandle {
    server_name: String,
    command_tx: mpsc::UnboundedSender<SessionCommand>,
    last_used: Mutex<tokio::time::Instant>,
}

enum SessionCommand {
    Run {
        command: String,
        timeout_secs: u64,
        isolated: bool,
        reply: oneshot::Sender<std::result::Result<(String, i32), String>>,
    },
    Close,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ServerNameRequest {
    server: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SessionRequest {
    session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CommandRequest {
    session_id: String,
    command: String,
    timeout_secs: Option<u64>,
    #[serde(default)]
    isolated: bool,
}

#[derive(Clone)]
struct HostKeyChecker {
    host: String,
    port: u16,
    known_hosts_path: PathBuf,
}

impl Handler for HostKeyChecker {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(russh::keys::known_hosts::check_known_hosts_path(
            &self.host,
            self.port,
            &server_key.public_key(),
            &self.known_hosts_path,
        )
        .unwrap_or(false))
    }
}

#[tool_router]
impl SshServer {
    fn new() -> Result<Self> {
        let registry_path = env::var_os("SSH_SERVERS_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("servers.json"));
        let servers = if registry_path.exists() {
            let raw = std::fs::read_to_string(&registry_path)
                .with_context(|| format!("failed to read {}", registry_path.display()))?;
            let entries: Vec<RegisteredServer> = serde_json::from_str(&raw)
                .with_context(|| format!("invalid JSON in {}", registry_path.display()))?;
            validate_registry(entries)?
        } else {
            HashMap::new()
        };

        Ok(Self {
            tool_router: Self::tool_router(),
            servers: Arc::new(servers),
            sessions: SessionStore(Arc::new(Mutex::new(HashMap::new()))),
            default_user: env::var("SSH_USER").ok().filter(|v| !v.trim().is_empty()),
            connect_timeout_secs: env::var("SSH_CONNECT_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10)
                .clamp(1, 60),
            idle_timeout_secs: env::var("SSH_IDLE_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS)
                .clamp(30, 86_400),
        })
    }

    #[tool(
        name = "list_servers",
        description = "List SSH servers registered in the user's local JSON file."
    )]
    async fn list_servers(&self) -> Result<CallToolResult, McpError> {
        let mut servers: Vec<_> = self.servers.values().collect();
        servers.sort_by(|a, b| a.name.cmp(&b.name));
        let sessions: Vec<_> = self.sessions.0.lock().await.values().cloned().collect();
        let mut lines = Vec::new();
        for server in servers {
            let mut active = 0;
            for session in &sessions {
                if session.server_name == server.name {
                    active += 1;
                }
            }
            let label = server
                .description
                .as_deref()
                .filter(|s| !s.eq_ignore_ascii_case("none"))
                .unwrap_or(&server.destination);
            lines.push(format!(
                "{} — {}:{}; auth={}; active sessions: {}",
                server.name,
                label,
                server.port,
                server.authentication.kind(),
                active
            ));
        }
        if lines.is_empty() {
            lines.push("No SSH servers are registered. Add entries to SSH_SERVERS_FILE.".into());
        }
        Ok(CallToolResult::success(vec![ContentBlock::text(
            lines.join("\n"),
        )]))
    }

    #[tool(
        name = "open_session",
        description = "Authenticate to a registered SSH server with its JSON credentials and keep an interactive shell alive. Returns a session_id."
    )]
    async fn open_session(
        &self,
        Parameters(input): Parameters<ServerNameRequest>,
    ) -> Result<CallToolResult, McpError> {
        let server = self
            .servers
            .get(&input.server)
            .ok_or_else(|| {
                McpError::invalid_params("server is not registered; call list_servers", None)
            })?
            .clone();
        let username = server
            .username
            .clone()
            .or_else(|| {
                server
                    .destination
                    .split_once('@')
                    .and_then(|(user, _)| (!user.is_empty()).then(|| user.to_owned()))
            })
            .or_else(|| self.default_user.clone())
            .ok_or_else(|| {
                McpError::invalid_params(
                    "set username in the server JSON or use destination as username@host",
                    None,
                )
            })?;
        let host = server
            .destination
            .split_once('@')
            .map_or(server.destination.as_str(), |(_, host)| host)
            .to_owned();
        validate_host(&host).map_err(|e| McpError::invalid_params(e, None))?;
        let (session_handle, mut channel) = timeout(
            Duration::from_secs(self.connect_timeout_secs + 15),
            connect_server(
                &host,
                &username,
                server.port,
                &server.authentication,
                self.connect_timeout_secs,
            ),
        )
        .await
        .map_err(|_| McpError::internal_error("SSH connection timed out", None))?
        .map_err(|error| McpError::internal_error(error, None))?;

        let ready_marker = format!("__LITE_SSH_READY_{}__", Uuid::new_v4().simple());
        channel
            .write_all(
                format!("export TERM=dumb; PS1=; PROMPT=; stty -echo 2>/dev/null; printf '\\n{ready_marker}\\n'\n")
                    .as_bytes(),
            )
            .await
            .map_err(|e| {
                McpError::internal_error(format!("could not initialize remote shell: {e}"), None)
            })?;
        channel.flush().await.map_err(|e| {
            McpError::internal_error(format!("could not initialize remote shell: {e}"), None)
        })?;
        let _ = read_until_token(
            &mut channel,
            ready_marker.as_bytes(),
            Duration::from_secs(self.connect_timeout_secs + 5),
        )
        .await
        .map_err(|error| McpError::internal_error(error, None))?;

        let (command_tx, command_rx) = mpsc::unbounded_channel();
        tokio::spawn(run_session(session_handle, channel, command_rx));
        let handle = Arc::new(SessionHandle {
            server_name: server.name.clone(),
            command_tx,
            last_used: Mutex::new(tokio::time::Instant::now()),
        });
        let session_id = Uuid::new_v4().to_string();
        self.sessions
            .0
            .lock()
            .await
            .insert(session_id.clone(), handle);
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "session_id: {session_id}\nserver: {}\nAuthenticated persistent SSH shell is open.",
            server.name
        ))]))
    }

    #[tool(
        name = "send_command",
        description = "Run one command in an existing persistent SSH shell; cd and exported variables persist between calls. For Proxmox container commands, use `pct exec` with isolated=true; do not use interactive `pct enter` with this command tool. isolated=true runs without a controlling terminal, closes stdin, and collects output and exit code. It inherits the current directory and environment, but changes made by the command do not persist."
    )]
    async fn send_command(
        &self,
        Parameters(input): Parameters<CommandRequest>,
    ) -> Result<CallToolResult, McpError> {
        let handle = self.get_session(&input.session_id).await?;
        let command = input.command.trim();
        if command.is_empty() || command.contains('\n') || command.contains('\r') {
            return Err(McpError::invalid_params(
                "command must be non-empty and contain only one line",
                None,
            ));
        }
        let timeout_secs = input
            .timeout_secs
            .unwrap_or(DEFAULT_COMMAND_TIMEOUT_SECS)
            .clamp(1, MAX_COMMAND_TIMEOUT_SECS);
        *handle.last_used.lock().await = tokio::time::Instant::now();
        let (reply, response) = oneshot::channel();
        handle
            .command_tx
            .send(SessionCommand::Run {
                command: command.to_owned(),
                timeout_secs,
                isolated: input.isolated,
                reply,
            })
            .map_err(|_| {
                McpError::internal_error("SSH session has ended; open a new session", None)
            })?;
        let (output, exit_code) = response
            .await
            .map_err(|_| {
                McpError::internal_error("SSH session closed before the command completed", None)
            })?
            .map_err(|error| McpError::internal_error(error, None))?;
        *handle.last_used.lock().await = tokio::time::Instant::now();
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "exit_code: {exit_code}\n{}",
            truncate(&output)
        ))]))
    }

    #[tool(
        name = "close_session",
        description = "Close a persistent SSH shell session."
    )]
    async fn close_session(
        &self,
        Parameters(input): Parameters<SessionRequest>,
    ) -> Result<CallToolResult, McpError> {
        let handle = self
            .sessions
            .0
            .lock()
            .await
            .remove(&input.session_id)
            .ok_or_else(|| McpError::invalid_params("unknown session_id", None))?;
        let _ = handle.command_tx.send(SessionCommand::Close);
        Ok(CallToolResult::success(vec![ContentBlock::text(
            "SSH session closed.".to_owned(),
        )]))
    }
}

impl SshServer {
    async fn get_session(&self, id: &str) -> Result<Arc<SessionHandle>, McpError> {
        self.sessions
            .0
            .lock()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| {
                McpError::invalid_params(
                    "unknown or expired session_id; open a session first",
                    None,
                )
            })
    }
}

async fn connect_server(
    host: &str,
    username: &str,
    port: u16,
    authentication: &Authentication,
    connect_timeout_secs: u64,
) -> std::result::Result<
    (
        client::Handle<HostKeyChecker>,
        russh::ChannelStream<client::Msg>,
    ),
    String,
> {
    let known_hosts_path = home_dir().join(".ssh").join("known_hosts");
    if !known_hosts_path.exists() {
        return Err(format!(
            "known_hosts file not found at {}; add and verify the server key first",
            known_hosts_path.display()
        ));
    }
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(connect_timeout_secs * 3)),
        ..Default::default()
    });
    let handler = HostKeyChecker {
        host: host.to_owned(),
        port,
        known_hosts_path,
    };
    let mut handle = client::connect(config, (host, port), handler)
        .await
        .map_err(|e| format!("SSH handshake or host-key verification failed: {e}"))?;
    let auth_result = match authentication {
        Authentication::Password { password } => handle
            .authenticate_password(username, password)
            .await
            .map_err(|_| {
                "SSH password authentication failed; verify username and password".to_owned()
            })?,
        Authentication::PrivateKey {
            private_key_path,
            passphrase,
        } => {
            let key = russh::keys::load_secret_key(private_key_path, passphrase.as_deref())
                .map_err(|_| {
                    format!(
                        "could not load private key at {}",
                        private_key_path.display()
                    )
                })?;
            let hash = handle
                .best_supported_rsa_hash()
                .await
                .map_err(|e| format!("could not negotiate SSH key algorithm: {e}"))?
                .flatten();
            handle
                .authenticate_publickey(username, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
                .await
                .map_err(|_| "SSH private-key authentication failed".to_owned())?
        }
    };
    if !auth_result.success() {
        return Err("SSH server rejected the configured credentials".into());
    }
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("could not open SSH channel: {e}"))?;
    channel
        .request_pty(true, "xterm", 120, 40, 0, 0, &[])
        .await
        .map_err(|e| format!("could not request remote terminal: {e}"))?;
    channel
        .request_shell(true)
        .await
        .map_err(|e| format!("could not start remote shell: {e}"))?;
    Ok((handle, channel.into_stream()))
}

async fn run_session<H: Handler<Error = russh::Error>>(
    ssh_handle: client::Handle<H>,
    mut channel: impl AsyncRead + tokio::io::AsyncWrite + Unpin,
    mut command_rx: mpsc::UnboundedReceiver<SessionCommand>,
) {
    let _keep_ssh_alive = ssh_handle;
    while let Some(message) = command_rx.recv().await {
        match message {
            SessionCommand::Close => break,
            SessionCommand::Run {
                command,
                timeout_secs,
                isolated,
                reply,
            } => {
                let marker = format!("__LITE_SSH_CMD_{}__", Uuid::new_v4().simple());
                let command_input = if isolated {
                    isolated_command_script(&command, &marker)
                } else {
                    format!("{command}\nprintf '\\n{marker}:%s\\n' \"$?\"\n")
                };
                let result = async {
                    channel
                        .write_all(command_input.as_bytes())
                        .await
                        .map_err(|e| format!("failed to send command: {e}"))?;
                    channel
                        .flush()
                        .await
                        .map_err(|e| format!("failed to flush command: {e}"))?;
                    let (output, status) = read_until_token_with_suffix(
                        &mut channel,
                        marker.as_bytes(),
                        Duration::from_secs(timeout_secs),
                    )
                    .await?;
                    let exit_code = status
                        .trim_start_matches(':')
                        .trim()
                        .parse::<i32>()
                        .map_err(|_| {
                            format!(
                                "remote shell returned an invalid exit status marker: {status:?}"
                            )
                        })?;
                    Ok((
                        strip_terminal_controls(&String::from_utf8_lossy(&output)),
                        exit_code,
                    ))
                }
                .await;
                let timed_out = result
                    .as_ref()
                    .err()
                    .is_some_and(|e: &String| e.contains("timed out"));
                let _ = reply.send(result);
                if timed_out {
                    break;
                }
            }
        }
    }
    let _ = channel.shutdown().await;
}

fn isolated_command_script(command: &str, marker: &str) -> String {
    let suffix = Uuid::new_v4().simple().to_string().to_uppercase();
    let output_var = format!("__LITE_SSH_OUTPUT_{suffix}");
    let status_var = format!("__LITE_SSH_STATUS_{suffix}");
    let pid_var = format!("__LITE_SSH_PID_{suffix}");
    let result_var = format!("__LITE_SSH_RESULT_{suffix}");
    let child_result_var = format!("__LITE_SSH_CHILD_RESULT_{suffix}");

    format!(
        "if {output_var}=$(mktemp); then\n\
         {status_var}=\"${{{output_var}}}.status\"\n\
         ( {command}; {child_result_var}=$?; printf '%s\\n' \"${{{child_result_var}}}\" > \"${{{status_var}}}\" ) </dev/null >\"${{{output_var}}}\" 2>&1 &\n\
         {pid_var}=$!\n\
         wait \"${{{pid_var}}}\"\n\
         {result_var}=$(cat \"${{{status_var}}}\" 2>/dev/null) || {result_var}=125\n\
         cat \"${{{output_var}}}\"\n\
         rm -f \"${{{output_var}}}\" \"${{{status_var}}}\"\n\
         printf '\\n{marker}:%s\\n' \"${{{result_var}}}\"\n\
         else\n\
         printf '\\n{marker}:125\\n'\n\
         fi\n"
    )
}

async fn read_until_token<R: AsyncRead + Unpin>(
    reader: &mut R,
    token: &[u8],
    wait: Duration,
) -> std::result::Result<Vec<u8>, String> {
    read_until_token_inner(reader, token, wait)
        .await
        .map(|(output, _)| output)
}

async fn read_until_token_with_suffix<R: AsyncRead + Unpin>(
    reader: &mut R,
    token: &[u8],
    wait: Duration,
) -> std::result::Result<(Vec<u8>, String), String> {
    read_until_token_inner(reader, token, wait).await
}

async fn read_until_token_inner<R: AsyncRead + Unpin>(
    reader: &mut R,
    token: &[u8],
    wait: Duration,
) -> std::result::Result<(Vec<u8>, String), String> {
    let deadline = tokio::time::Instant::now() + wait;
    let mut collected = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        if let Some(index) = find_subslice(&collected, token) {
            let after = index + token.len();
            if let Some(newline) = collected[after..].iter().position(|b| *b == b'\n') {
                let output = collected[..index].to_vec();
                let suffix =
                    String::from_utf8_lossy(&collected[after..after + newline]).to_string();
                return Ok((output, suffix));
            }
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("command timed out; SSH session closed to prevent late output mixing with the next command".into());
        }
        let read = timeout(remaining, reader.read(&mut chunk)).await
            .map_err(|_| "command timed out; SSH session closed to prevent late output mixing with the next command".to_owned())?
            .map_err(|e| format!("failed to read SSH channel: {e}"))?;
        if read == 0 {
            return Err("remote shell closed the SSH channel".into());
        }
        collected.extend_from_slice(&chunk[..read]);
        if collected.len() > MAX_BUFFER_BYTES {
            let remove = collected.len() - MAX_OUTPUT_BYTES;
            collected.drain(..remove);
        }
    }
}

fn validate_host(host: &str) -> std::result::Result<(), String> {
    if host.trim().is_empty()
        || host.starts_with('-')
        || host.chars().any(|c| c.is_control() || c.is_whitespace())
        || host.contains('/')
        || host.contains('\\')
        || host.contains('@')
    {
        return Err("destination must be a hostname or IP address, not an OpenSSH config alias or user@host".into());
    }
    Ok(())
}

fn validate_registry(entries: Vec<RegisteredServer>) -> Result<HashMap<String, RegisteredServer>> {
    let mut servers = HashMap::new();
    for entry in entries {
        let name = entry.name.trim();
        if name.is_empty() || name.chars().any(char::is_control) {
            anyhow::bail!(
                "registered server names must be non-empty and contain no control characters"
            );
        }
        let host = entry
            .destination
            .split_once('@')
            .map_or(entry.destination.as_str(), |(_, host)| host);
        validate_host(host).map_err(|e| anyhow::anyhow!("registered server '{}': {e}", name))?;
        if entry.port == 0 {
            anyhow::bail!("registered server '{}' has invalid port 0", name);
        }
        if entry
            .username
            .as_deref()
            .is_some_and(|user| user.trim().is_empty() || user.chars().any(char::is_control))
        {
            anyhow::bail!("registered server '{}' has an invalid username", name);
        }
        match &entry.authentication {
            Authentication::Password { password } if password.is_empty() => {
                anyhow::bail!("registered server '{}' has an empty password", name)
            }
            Authentication::PrivateKey {
                private_key_path, ..
            } if private_key_path.as_os_str().is_empty() => {
                anyhow::bail!("registered server '{}' has an empty private_key_path", name)
            }
            _ => {}
        }
        if servers
            .insert(
                name.to_owned(),
                RegisteredServer {
                    name: name.to_owned(),
                    ..entry
                },
            )
            .is_some()
        {
            anyhow::bail!("duplicate registered server name: {name}");
        }
    }
    Ok(servers)
}

fn home_dir() -> PathBuf {
    env::var_os("USERPROFILE")
        .or_else(|| env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn start_idle_reaper(sessions: SessionStore, idle_secs: u64) {
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(30)).await;
            let snapshot: Vec<(String, Arc<SessionHandle>)> = {
                let map = sessions.0.lock().await;
                map.iter()
                    .map(|(id, session)| (id.clone(), session.clone()))
                    .collect()
            };
            let mut expired = Vec::new();
            for (id, session) in snapshot {
                if session.last_used.lock().await.elapsed().as_secs() >= idle_secs {
                    expired.push(id);
                }
            }
            let mut map = sessions.0.lock().await;
            for id in expired {
                if let Some(session) = map.remove(&id) {
                    let _ = session.command_tx.send(SessionCommand::Close);
                }
            }
        }
    });
}

fn default_port() -> u16 {
    22
}
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
fn strip_terminal_controls(text: &str) -> String {
    text.chars()
        .filter(|c| *c == '\n' || *c == '\r' || *c == '\t' || !c.is_control())
        .collect()
}

fn truncate(text: &str) -> String {
    if text.len() <= MAX_OUTPUT_BYTES {
        return text.to_owned();
    }
    let mut end = MAX_OUTPUT_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}\n[output truncated at {MAX_OUTPUT_BYTES} bytes]",
        &text[..end]
    )
}

#[tool_handler]
impl ServerHandler for SshServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_instructions("AI usage: call list_servers to identify a registered host, then open_session and keep reusing its session_id in send_command. For one-shot commands inside a Proxmox container, use `pct exec <CTID> -- <command>` with send_command isolated=true. Do not use interactive `pct enter` with send_command; it does not finish like a normal command. isolated=true closes stdin and runs without a controlling terminal, then returns output and exit code; the command inherits the current directory and environment, but changes it do not persist. Use the default isolated=false for normal shell commands when cd or exported variables must persist. Close sessions with close_session when done.")
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let server = SshServer::new()?;
    start_idle_reaper(server.sessions.clone(), server.idle_timeout_secs);
    let service = server
        .serve(stdio())
        .await
        .context("failed to start stdio MCP transport")?;
    service
        .waiting()
        .await
        .context("MCP server stopped unexpectedly")?;
    Ok(())
}
