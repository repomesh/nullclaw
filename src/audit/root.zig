//! Audit subsystem — privacy-preserving secret triage.
//!
//! Sub-modules:
//!   envelope.zig    — privacy-safe metadata envelopes for findings
//!   llm_client.zig  — provider-vtable envelope triage prompt/parser
//!   audit_log.zig   — append-only log of LLM-triage requests
//!   triager.zig     — orchestration: envelope → LLM → log → verdict

pub const envelope = @import("envelope.zig");
pub const llm_client = @import("llm_client.zig");
pub const audit_log = @import("audit_log.zig");
pub const triager = @import("triager.zig");

pub const Envelope = envelope.Envelope;
pub const BuildInput = envelope.BuildInput;
pub const Charset = envelope.Charset;
pub const TokenTypeFingerprint = envelope.TokenTypeFingerprint;
pub const Verdict = llm_client.Verdict;
pub const Decision = llm_client.Decision;
pub const AuditLog = audit_log.AuditLog;
pub const TriageStats = triager.TriageStats;

test {
    _ = envelope;
    _ = llm_client;
    _ = audit_log;
}
