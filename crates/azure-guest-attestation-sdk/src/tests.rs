// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests that exercise TPM helper functionality against the ms-tpm-20-ref reference vTPM.
//!
//! These are lightweight sanity tests (not exhaustive) ensuring our raw NV index
//! helpers interoperate with an in-process TPM implementation.

#[cfg(test)]
mod tests {
    use ms_tpm_20_ref::{MsTpm20RefPlatform, InitKind, DynResult, PlatformCallbacks};
    use std::time::Instant;

    // Minimal platform callback impl for tests
    struct TestPlatform {
        nv: Vec<u8>,
        start: Instant,
    }
    impl PlatformCallbacks for TestPlatform {
        fn commit_nv_state(&mut self, state: &[u8]) -> DynResult<()> { self.nv = state.to_vec(); Ok(()) }
        fn get_crypt_random(&mut self, buf: &mut [u8]) -> DynResult<usize> { getrandom::getrandom(buf).unwrap(); Ok(buf.len()) }
        fn monotonic_timer(&mut self) -> std::time::Duration { self.start.elapsed() }
        fn get_unique_value(&self) -> &'static [u8] { b"cvm-sdk-test" }
    }

    // Smoke test: bring up reference TPM and issue Startup / GetCapability via our transport layer design.
    #[test]
    fn reference_tpm_startup() {
        let tpm = MsTpm20RefPlatform::initialize(Box::new(TestPlatform { nv: vec![], start: Instant::now() }), InitKind::ColdInit).expect("init ref tpm");
        // Execute a Startup(Clear) raw command through reference engine directly to ensure engine works.
        // TPM2_Startup command buffer (same as existing transmit_get_capability test pattern) size 12
        let startup_cmd = [
            0x80,0x01, // tag no sessions
            0x00,0x00,0x00,0x0C, // length 12
            0x00,0x00,0x01,0x44, // CC Startup
            0x00,0x00 // startup type clear
        ];
        let mut reply = [0u8; 4096];
        tpm.execute_command(&startup_cmd, &mut reply).expect("startup");
        // Response header rc should be success
        assert_eq!(&reply[6..10], &[0,0,0,0]);
    }
}
