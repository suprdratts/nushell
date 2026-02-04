//! The `getseks` command - fetch a secret from the broker and register it for scrubbing

use nu_engine::command_prelude::*;
use nu_seks::{BrokerClient, register_named_secret};

#[derive(Clone)]
pub struct GetSeks;

impl Command for GetSeks {
    fn name(&self) -> &str {
        "getseks"
    }

    fn description(&self) -> &str {
        "Fetch a secret from the SEKS broker and register it for output scrubbing."
    }

    fn signature(&self) -> Signature {
        Signature::build("getseks")
            .input_output_types(vec![(Type::Nothing, Type::String)])
            .required("name", SyntaxShape::String, "The name of the secret to fetch.")
            .category(Category::Env)
    }

    fn extra_description(&self) -> &str {
        r#"Fetches a secret value from the SEKS broker daemon. The secret is:
1. Retrieved from the broker over a Unix socket
2. Registered for output scrubbing (any output containing the secret will show <secret:name> instead)
3. Returned as a string for use in commands

The broker must be running (seks-broker) and have the secret configured in ~/.seksh/secrets.json.

This command is the core of SEKS shell's security model - it allows agents to use secrets
in commands without ever seeing the actual secret values."#
    }

    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let name: String = call.req(engine_state, stack, 0)?;
        let span = call.head;

        // Connect to the broker and fetch the secret
        let client = BrokerClient::new();

        let secret = client.get_secret(&name).map_err(|e| ShellError::GenericError {
            error: "Failed to get secret".into(),
            msg: e.to_string(),
            span: Some(span),
            help: Some("Make sure the SEKS broker is running (seks-broker) and the secret exists in ~/.seksh/secrets.json".into()),
            inner: vec![],
        })?;

        // Register the secret for scrubbing
        register_named_secret(&name, &secret);

        // Return the secret value
        Ok(Value::string(secret, span).into_pipeline_data())
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                description: "Fetch a GitHub token and use it in a curl command",
                example: r#"^curl -H $"Authorization: Bearer (getseks 'github_token')" https://api.github.com/user"#,
                result: None,
            },
            Example {
                description: "Use a secret in environment variable",
                example: r#"with-env { API_KEY: (getseks 'api_key') } { ^some-command }"#,
                result: None,
            },
            Example {
                description: "Echo a secret (output will be scrubbed)",
                example: r#"echo (getseks 'test_token')"#,
                result: None,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_getseks_signature() {
        let cmd = GetSeks;
        assert_eq!(cmd.name(), "getseks");
        assert!(cmd.description().contains("secret"));
    }
}
