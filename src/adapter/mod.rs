pub mod ghidra;
pub mod process;
pub mod schema;

use crate::error::Result;
use schema::{AdapterCapability, ToolCommand, ToolEvent};

pub trait ToolAdapter {
    fn name(&self) -> &'static str;
    fn parser_version(&self) -> &'static str;
    fn capabilities(&self) -> Vec<AdapterCapability>;
    fn command(&self, _target: &str) -> Option<ToolCommand> {
        None
    }
    fn run(&self, target: &str) -> Result<Vec<ToolEvent>>;
}
