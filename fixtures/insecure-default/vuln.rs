// PLANTED LEAD (CWE-1188, insecure default): the plugin signature verifier is fully implemented
// (Strict / Permissive), but its config default is `Disabled` — so an out-of-the-box deployment
// installs and discovers plugins with NO signature check, removing the only gate in front of the
// plugin-install path. The control exists and is testable; the shipped default neutralises it.
// Intentional — the insecure-default static lane surfaces this as a lead about the default posture.
// The safe form defaults to the enforcing value (`Strict`).

pub enum SignatureMode {
    Strict,
    Permissive,
    Disabled,
}

fn default_signature_mode() -> SignatureMode {
    SignatureMode::Disabled
}

pub fn enforce(mode: &SignatureMode, plugin: &Plugin) -> Result<(), Error> {
    if let SignatureMode::Disabled = mode {
        return Ok(()); // shipped default skips the check entirely
    }
    verify_signature(plugin)
}
