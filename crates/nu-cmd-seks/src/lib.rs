//! SEKS Commands for Nushell
//!
//! This crate provides commands for working with secrets securely:
//!
//! - `getseks` - Fetch a secret (DEPRECATED: exposes secret to shell memory)
//! - `listseks` - List available secrets (names only)
//! - `seksh-http` - Make HTTP requests with secrets injected internally (SECURE)
//! - `seksh-git` - Run git commands with credentials injected internally (SECURE)
//!
//! ## Security Model
//!
//! The `seksh-*` commands are the recommended way to use secrets. Unlike `getseks`,
//! they never expose the actual secret value to the shell's memory space. The secret
//! goes directly from the broker to the external command.
//!
//! ```text
//! UNSAFE (getseks):
//!   getseks → shell memory → command args → external command
//!   (secret can be exfiltrated via string ops, file writes, etc.)
//!
//! SAFE (seksh-http, seksh-git):
//!   broker → seksh-* internal → external command
//!   (shell only sees secret NAME, never VALUE)
//! ```

mod getseks;
mod listseks;
mod seksh_git;
mod seksh_http;

pub use getseks::GetSeks;
pub use listseks::ListSeks;
pub use seksh_git::SekshGit;
pub use seksh_http::SekshHttp;

use nu_protocol::engine::{EngineState, StateWorkingSet};

/// Add SEKS commands to the engine state
pub fn add_seks_command_context(mut engine_state: EngineState) -> EngineState {
    let delta = {
        let mut working_set = StateWorkingSet::new(&engine_state);
        working_set.add_decl(Box::new(GetSeks));
        working_set.add_decl(Box::new(ListSeks));
        working_set.add_decl(Box::new(SekshGit));
        working_set.add_decl(Box::new(SekshHttp));
        working_set.render()
    };

    if let Err(err) = engine_state.merge_delta(delta) {
        eprintln!("Error adding SEKS context: {err:?}");
    }

    engine_state
}
