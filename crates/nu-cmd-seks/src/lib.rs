//! SEKS Commands for Nushell
//!
//! This crate provides the `getseks` command and other SEKS-related commands.

mod getseks;

pub use getseks::GetSeks;

use nu_protocol::engine::{EngineState, StateWorkingSet};

/// Add SEKS commands to the engine state
pub fn add_seks_command_context(mut engine_state: EngineState) -> EngineState {
    let delta = {
        let mut working_set = StateWorkingSet::new(&engine_state);
        working_set.add_decl(Box::new(GetSeks));
        working_set.render()
    };

    if let Err(err) = engine_state.merge_delta(delta) {
        eprintln!("Error adding SEKS context: {err:?}");
    }

    engine_state
}
