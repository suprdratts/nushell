//! The `seksh-git` command - secure git operations with internal credential injection
//!
//! This command runs git operations with credentials injected from the broker.
//! The shell NEVER sees the actual credential values.

use nu_engine::command_prelude::*;
use nu_seks::{BrokerClient, register_named_secret, scrub_output};
use std::io::Write;
use std::process::{Command as StdCommand, Stdio};

#[derive(Clone)]
pub struct SekshGit;

impl Command for SekshGit {
    fn name(&self) -> &str {
        "seksh-git"
    }

    fn description(&self) -> &str {
        "Run git commands with credentials injected securely from the broker."
    }

    fn signature(&self) -> Signature {
        Signature::build("seksh-git")
            .input_output_types(vec![(Type::Nothing, Type::String)])
            .required(
                "command",
                SyntaxShape::String,
                "Git command to run (clone, push, pull, fetch, etc.)",
            )
            .rest(
                "args",
                SyntaxShape::String,
                "Arguments to pass to git",
            )
            .named(
                "token",
                SyntaxShape::String,
                "Secret name for GitHub/GitLab token (uses as password with 'git' or 'oauth2' user)",
                Some('t'),
            )
            .named(
                "user",
                SyntaxShape::String,
                "Secret name for git username",
                Some('u'),
            )
            .named(
                "pass",
                SyntaxShape::String,
                "Secret name for git password",
                Some('p'),
            )
            .named(
                "ssh-key",
                SyntaxShape::String,
                "Secret name for SSH private key (writes to temp file)",
                Some('k'),
            )
            .switch("verbose", "Show git output in real-time", Some('v'))
            .category(Category::FileSystem)
    }

    fn extra_description(&self) -> &str {
        r#"Runs git commands with credentials from the SEKS broker. The credentials
are injected via GIT_ASKPASS, so they never enter the shell's memory.

AUTHENTICATION METHODS:

1. Token auth (GitHub, GitLab, etc.):
   seksh-git clone https://github.com/user/repo --token GITHUB_PERSONAL_ACCESS_TOKEN

2. Username/password:
   seksh-git push --user GIT_USER --pass GIT_PASS

3. SSH key:
   seksh-git clone git@github.com:user/repo.git --ssh-key SSH_PRIVATE_KEY

SECURITY MODEL:
- Credentials go: Broker → temp askpass script → git
- Shell sees: Command output (scrubbed)
- Shell NEVER sees: Actual credentials

ENVIRONMENT VARIABLES:
  SEKS_BROKER_URL    - Broker URL (default: http://localhost:8787)
  SEKS_AGENT_TOKEN   - Agent bearer token (required)"#
    }

    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let span = call.head;

        // Parse arguments
        let git_command: String = call.req(engine_state, stack, 0)?;
        let git_args: Vec<String> = call.rest(engine_state, stack, 1)?;

        let token_secret: Option<String> = call.get_flag(engine_state, stack, "token")?;
        let user_secret: Option<String> = call.get_flag(engine_state, stack, "user")?;
        let pass_secret: Option<String> = call.get_flag(engine_state, stack, "pass")?;
        let ssh_key_secret: Option<String> = call.get_flag(engine_state, stack, "ssh-key")?;
        let verbose: bool = call.has_flag(engine_state, stack, "verbose")?;

        let broker = BrokerClient::new();

        // Build git command
        let mut cmd = StdCommand::new("git");
        cmd.arg(&git_command);
        cmd.args(&git_args);

        // Temp files we need to clean up
        let mut temp_files: Vec<std::path::PathBuf> = Vec::new();

        // Handle SSH key auth
        if let Some(key_secret) = ssh_key_secret {
            let ssh_key = fetch_secret(&broker, &key_secret, span)?;
            register_named_secret(&key_secret, &ssh_key);

            // Write key to temp file with restrictive permissions
            let key_path = write_temp_ssh_key(&ssh_key).map_err(|e| ShellError::GenericError {
                error: "Failed to write SSH key".into(),
                msg: e,
                span: Some(span),
                help: None,
                inner: vec![],
            })?;

            temp_files.push(key_path.clone());

            // Configure git to use this key
            cmd.env(
                "GIT_SSH_COMMAND",
                format!(
                    "ssh -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new",
                    key_path.display()
                ),
            );
        }

        // Handle token auth (GitHub/GitLab style)
        if let Some(token_name) = &token_secret {
            let token = fetch_secret(&broker, token_name, span)?;
            register_named_secret(token_name, &token);

            // Create askpass script with default username for token auth
            // GitHub/GitLab accept "x-access-token" as username when using PAT
            let askpass_path =
                write_askpass_script(&token, Some("x-access-token")).map_err(|e| {
                    ShellError::GenericError {
                        error: "Failed to create askpass script".into(),
                        msg: e,
                        span: Some(span),
                        help: None,
                        inner: vec![],
                    }
                })?;

            temp_files.push(askpass_path.clone());

            cmd.env("GIT_ASKPASS", &askpass_path);
            cmd.env("GIT_TERMINAL_PROMPT", "0");
        }

        // Handle user/pass auth
        if let Some(user_name) = &user_secret {
            let pass_name = pass_secret
                .as_ref()
                .ok_or_else(|| ShellError::GenericError {
                    error: "Password required".into(),
                    msg: "--user requires --pass".into(),
                    span: Some(span),
                    help: None,
                    inner: vec![],
                })?;

            let username = fetch_secret(&broker, user_name, span)?;
            let password = fetch_secret(&broker, pass_name, span)?;

            register_named_secret(user_name, &username);
            register_named_secret(pass_name, &password);

            // Create askpass script that provides both user and pass
            let askpass_path = write_askpass_script(&password, Some(&username)).map_err(|e| {
                ShellError::GenericError {
                    error: "Failed to create askpass script".into(),
                    msg: e,
                    span: Some(span),
                    help: None,
                    inner: vec![],
                }
            })?;

            temp_files.push(askpass_path.clone());

            cmd.env("GIT_ASKPASS", &askpass_path);
            cmd.env("GIT_TERMINAL_PROMPT", "0");
        }

        // Run git command
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let output = cmd.output().map_err(|e| ShellError::GenericError {
            error: "Failed to run git".into(),
            msg: e.to_string(),
            span: Some(span),
            help: Some("Make sure git is installed and in PATH".into()),
            inner: vec![],
        })?;

        // Clean up temp files
        for path in temp_files {
            let _ = std::fs::remove_file(path);
        }

        // Combine stdout and stderr
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        let mut result = String::new();
        if !stdout.is_empty() {
            result.push_str(&stdout);
        }
        if !stderr.is_empty() {
            if !result.is_empty() {
                result.push('\n');
            }
            result.push_str(&stderr);
        }

        // Check for errors
        if !output.status.success() {
            let scrubbed = scrub_output(&result);
            return Err(ShellError::GenericError {
                error: format!("git {} failed", git_command),
                msg: scrubbed,
                span: Some(span),
                help: None,
                inner: vec![],
            });
        }

        // Scrub output (defense-in-depth)
        let scrubbed = scrub_output(&result);

        if verbose {
            eprintln!("{}", scrubbed);
        }

        Ok(Value::string(scrubbed, span).into_pipeline_data())
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                description: "Clone a private GitHub repo using token",
                example: "seksh-git clone https://github.com/user/private-repo.git --token GITHUB_PERSONAL_ACCESS_TOKEN",
                result: None,
            },
            Example {
                description: "Push with username/password",
                example: "seksh-git push origin main --user GIT_USER --pass GIT_PASS",
                result: None,
            },
            Example {
                description: "Clone via SSH with key from broker",
                example: "seksh-git clone git@github.com:user/repo.git --ssh-key SSH_PRIVATE_KEY",
                result: None,
            },
            Example {
                description: "Pull with verbose output",
                example: "seksh-git pull --token GITHUB_TOKEN --verbose",
                result: None,
            },
        ]
    }
}

fn fetch_secret(broker: &BrokerClient, name: &str, span: Span) -> Result<String, ShellError> {
    broker
        .get_secret(name)
        .map_err(|e| ShellError::GenericError {
            error: format!("Failed to get secret '{}'", name),
            msg: e.to_string(),
            span: Some(span),
            help: Some("Make sure the SEKS broker is running and the secret exists".into()),
            inner: vec![],
        })
}

/// Write an askpass script that echoes the credential
/// This is how we inject credentials without exposing them to the shell
fn write_askpass_script(
    password: &str,
    username: Option<&str>,
) -> Result<std::path::PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = std::env::temp_dir();
    let script_path = temp_dir.join(format!("seksh-askpass-{}", std::process::id()));

    // Create script that responds to git's credential prompts
    // Git askpass receives prompts like "Username for 'https://github.com': " or "Password for ..."
    let script = if let Some(user) = username {
        format!(
            r#"#!/bin/bash
case "$1" in
    *[Uu]sername*|*[Uu]ser*) echo "{}";;
    *) echo "{}";;
esac
"#,
            user, password
        )
    } else {
        // Token-only: respond with token for any prompt
        format!(
            r#"#!/bin/bash
echo "{}"
"#,
            password
        )
    };

    let mut file = std::fs::File::create(&script_path)
        .map_err(|e| format!("Failed to create askpass script: {}", e))?;

    file.write_all(script.as_bytes())
        .map_err(|e| format!("Failed to write askpass script: {}", e))?;

    // Make executable (700)
    let mut perms = file
        .metadata()
        .map_err(|e| format!("Failed to get file metadata: {}", e))?
        .permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(&script_path, perms)
        .map_err(|e| format!("Failed to set permissions: {}", e))?;

    Ok(script_path)
}

/// Write SSH private key to a temp file with secure permissions
fn write_temp_ssh_key(key: &str) -> Result<std::path::PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = std::env::temp_dir();
    let key_path = temp_dir.join(format!("seksh-ssh-key-{}", std::process::id()));

    let mut file = std::fs::File::create(&key_path)
        .map_err(|e| format!("Failed to create key file: {}", e))?;

    file.write_all(key.as_bytes())
        .map_err(|e| format!("Failed to write key file: {}", e))?;

    // SSH requires 600 permissions on key files
    let mut perms = file
        .metadata()
        .map_err(|e| format!("Failed to get file metadata: {}", e))?
        .permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&key_path, perms)
        .map_err(|e| format!("Failed to set permissions: {}", e))?;

    Ok(key_path)
}
