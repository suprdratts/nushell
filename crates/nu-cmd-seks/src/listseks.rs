//! The `listseks` command - list available secrets from the broker

use nu_engine::command_prelude::*;
use nu_seks::BrokerClient;

#[derive(Clone)]
pub struct ListSeks;

impl Command for ListSeks {
    fn name(&self) -> &str {
        "listseks"
    }

    fn description(&self) -> &str {
        "List available secrets from the SEKS broker (names only, not values)."
    }

    fn signature(&self) -> Signature {
        Signature::build("listseks")
            .input_output_types(vec![(Type::Nothing, Type::List(Box::new(Type::String)))])
            .category(Category::Env)
    }

    fn extra_description(&self) -> &str {
        r#"Lists the names of all secrets available in the SEKS broker.
Only names are returned, never the actual secret values.

ENVIRONMENT VARIABLES:
  SEKS_BROKER_URL    - Broker URL (default: http://localhost:8787)
  SEKS_AGENT_TOKEN   - Agent bearer token (required)

This is useful for discovering what secrets are configured without
exposing any sensitive data."#
    }

    fn run(
        &self,
        _engine_state: &EngineState,
        _stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let span = call.head;

        let client = BrokerClient::new();

        let names = client
            .list_secrets()
            .map_err(|e| ShellError::GenericError {
                error: "Failed to list secrets".into(),
                msg: e.to_string(),
                span: Some(span),
                help: Some("Make sure the SEKS broker is running (seks-broker)".into()),
                inner: vec![],
            })?;

        let values: Vec<Value> = names
            .into_iter()
            .map(|name| Value::string(name, span))
            .collect();

        Ok(Value::list(values, span).into_pipeline_data())
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                description: "List all available secrets",
                example: "listseks",
                result: None,
            },
            Example {
                description: "Check if a specific secret exists",
                example: "listseks | any {|name| $name == 'github_token'}",
                result: None,
            },
        ]
    }
}
