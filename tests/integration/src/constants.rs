pub const SAFE_ALLOWANCE: &str = "100 wxHOPR";
pub const SAFE_FUNDING: &str = "100 wxHOPR";

/// wxHOPR credited to the *node* address in PIX scenarios.
///
/// PIX deposits are plain token transfers signed by the node key, and the state
/// emulator debits the transaction signer — not the Safe — so the node address
/// itself has to hold the funds a deposit draws on.
pub const NODE_FUNDING: &str = "100 wxHOPR";
