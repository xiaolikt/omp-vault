//! ai-vault — one machine-wide encrypted secret store, shared by every agent.
//!
//! The store lives at `~/.ai-vault/store.json` (override with `AI_VAULT_DIR`),
//! encrypted with ChaCha20-Poly1305, keyed by scrypt from the master password.
//! An agent (pi, omp, anything else) never holds the master password: it asks
//! this binary to unlock, gets a short-lived session token, and passes that
//! token back on every later call.

mod audit;
mod sealed;
mod cli;
mod config;
mod crypto;
mod dialog;
mod import;
mod paths;
mod session;
mod store;

fn main() {
    let code = cli::run();
    std::process::exit(code);
}
