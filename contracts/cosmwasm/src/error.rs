use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("unauthorized: only admin can perform this action")]
    Unauthorized {},

    #[error("invalid hex encoding: {detail}")]
    InvalidHex { detail: String },

    #[error("invalid commitment: must be exactly 32 bytes (64 hex chars)")]
    InvalidCommitment {},

    #[error("invalid nullifier: must be exactly 32 bytes (64 hex chars)")]
    InvalidNullifier {},

    #[error("nullifier already spent: {nullifier}")]
    NullifierAlreadySpent { nullifier: String },

    #[error("merkle root mismatch: expected {expected}, got {got}")]
    MerkleRootMismatch { expected: String, got: String },

    #[error("invalid proof: {detail}")]
    InvalidProof { detail: String },

    #[error("insufficient pool balance: need {required}, have {available}")]
    InsufficientBalance { required: String, available: String },

    #[error("no funds sent: deposit requires attached tokens")]
    NoFundsSent {},

    #[error("multiple denoms sent: deposit supports single denom only")]
    MultipleDenoms {},

    #[error("wrong denom: expected {expected}, got {got}")]
    WrongDenom { expected: String, got: String },

    #[error("epoch mismatch: expected {expected}, got {got}")]
    EpochMismatch { expected: u64, got: u64 },

    #[error("unexpected funds: transfers and withdrawals must not carry extra tokens")]
    UnexpectedFunds {},
}
