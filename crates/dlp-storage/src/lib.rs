//! SQLite persistence: schema migrations, rule/policy CRUD, atomic version snapshots, rollback,
//! and the importers (gitleaks TOML, built-in TOML).
pub mod builtin;
pub mod gitleaks;
mod store;

pub use store::*;
