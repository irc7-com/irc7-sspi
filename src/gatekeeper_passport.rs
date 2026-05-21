//! GateKeeper + Passport Security Provider implementation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::types::{SspiError, CredHandle, CtxtHandle, SecBufferType, SecBuffer, SecurityProvider, CombinedContext};
use crate::default::DefaultSecurityProvider;
use crate::gatekeeper::GateKeeperSecurityProvider;
use crate::passport::PassportSecurityProvider;

/// GateKeeperPassport Security Provider corresponding to VTable at 0x37204278.
/// State machine combines both authentication layers.
pub struct GateKeeperPassportSecurityProvider {
    pub base: DefaultSecurityProvider,
    pub sub_gk: GateKeeperSecurityProvider,
    pub sub_passport: PassportSecurityProvider,
    pub sessions: Arc<Mutex<HashMap<CtxtHandle, CombinedContext>>>,
    pub next_handle_id: Arc<Mutex<usize>>,
}

impl GateKeeperPassportSecurityProvider {
    pub fn new() -> Self {
        Self {
            base: DefaultSecurityProvider {
                name: "GateKeeperPassport".to_string(),
                creds: Mutex::new(CredHandle { dw_lower: 0x5001, dw_upper: 0xAAAA }),
            },
            sub_gk: GateKeeperSecurityProvider::new(),
            sub_passport: PassportSecurityProvider::new(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            next_handle_id: Arc::new(Mutex::new(1)),
        }
    }
}

impl Default for GateKeeperPassportSecurityProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityProvider for GateKeeperPassportSecurityProvider {
    fn name(&self) -> &str {
        self.base.name()
    }

    fn initialize(&self) -> Result<(), SspiError> {
        self.sub_gk.initialize()?;
        self.sub_passport.initialize()?;
        Ok(())
    }

    fn shutdown(&self) -> Result<(), SspiError> {
        self.sub_gk.shutdown()?;
        self.sub_passport.shutdown()?;
        Ok(())
    }

    fn acquire_credentials_handle(
        &self,
        principal: Option<&str>,
        package: &str,
        cred_use: u32,
        auth_data: Option<&[u8]>,
        handle: &mut CredHandle,
    ) -> Result<(), SspiError> {
        self.base.acquire_credentials_handle(principal, package, cred_use, auth_data, handle)
    }

    fn free_credentials_handle(&self, handle: &CredHandle) -> Result<(), SspiError> {
        self.base.free_credentials_handle(handle)
    }

    fn initialize_security_context(
        &self,
        _credential: &CredHandle,
        context: Option<&CtxtHandle>,
        target_name: Option<&str>,
        context_req: u32,
        target_data_rep: u32,
        input_buffers: &[SecBuffer],
        new_context: &mut CtxtHandle,
        output_buffers: &mut [SecBuffer],
        context_attr: &mut u32,
    ) -> Result<SspiError, SspiError> {
        let mut sessions = self.sessions.lock().unwrap();

        match context {
            None => {
                // Start sequence in State 160
                let mut handle_id = self.next_handle_id.lock().unwrap();
                let ctxt = CtxtHandle { dw_lower: *handle_id, dw_upper: 0x4000 };
                *handle_id += 1;
                *new_context = ctxt;

                let mut comb = CombinedContext {
                    h_context: ctxt,
                    state: 160,
                    slot0_context: None,
                    slot1_context: None,
                };

                let mut sub_new_ctx = CtxtHandle::default();
                let sub_gk_creds = *self.sub_gk.base.creds.lock().unwrap();
                let res = self.sub_gk.initialize_security_context(
                    &sub_gk_creds,
                    None,
                    target_name,
                    context_req,
                    target_data_rep,
                    input_buffers,
                    &mut sub_new_ctx,
                    output_buffers,
                    context_attr,
                )?;

                comb.slot0_context = Some(sub_new_ctx);
                comb.state = 161;
                sessions.insert(ctxt, comb);

                Ok(res)
            }
            Some(ctxt) => {
                let comb = sessions.get_mut(ctxt).ok_or(SspiError::InvalidHandle)?;
                match comb.state {
                    161 => {
                        let input_tok = input_buffers.iter()
                            .find(|b| b.buffer_type == SecBufferType::Token);

                        let is_ok_tok = if let Some(tok) = input_tok {
                            tok.bytes.len() == 2 && tok.bytes[0] == b'O' && tok.bytes[1] == b'K'
                        } else {
                            false
                        };

                        if is_ok_tok {
                            // GateKeeper completed successfully (Server sent "OK")!
                            // Immediately start Slot 1 (Passport) phase.
                            let passport_buf = input_buffers.iter()
                                .find(|b| b.bytes != b"OK")
                                .ok_or(SspiError::InvalidToken)?;

                            let mut sub_new_ctx = CtxtHandle::default();
                            let sub_passport_creds = *self.sub_passport.base.creds.lock().unwrap();
                            let passport_input = vec![
                                SecBuffer { buffer_type: SecBufferType::Token, bytes: passport_buf.bytes.clone() }
                            ];
                            let res = self.sub_passport.initialize_security_context(
                                &sub_passport_creds,
                                None,
                                target_name,
                                context_req,
                                target_data_rep,
                                &passport_input,
                                &mut sub_new_ctx,
                                output_buffers,
                                context_attr,
                            )?;
                            comb.slot1_context = Some(sub_new_ctx);
                            comb.state = 163;
                            Ok(res)
                        } else {
                            // Still in GateKeeper phase (Challenge token received from server)
                            let mut sub_new_ctx = comb.slot0_context.unwrap();
                            let sub_ctx_arg = sub_new_ctx;
                            let sub_gk_creds = *self.sub_gk.base.creds.lock().unwrap();
                            let _res = self.sub_gk.initialize_security_context(
                                &sub_gk_creds,
                                Some(&sub_ctx_arg),
                                target_name,
                                context_req,
                                target_data_rep,
                                input_buffers,
                                &mut sub_new_ctx,
                                output_buffers,
                                context_attr,
                            )?;
                            comb.slot0_context = Some(sub_new_ctx);
                            Ok(SspiError::ContinueNeeded)
                        }
                    }
                    162 => {
                        let mut sub_new_ctx = CtxtHandle::default();
                        let sub_passport_creds = *self.sub_passport.base.creds.lock().unwrap();
                        let res = self.sub_passport.initialize_security_context(
                            &sub_passport_creds,
                            None,
                            target_name,
                            context_req,
                            target_data_rep,
                            input_buffers,
                            &mut sub_new_ctx,
                            output_buffers,
                            context_attr,
                        )?;
                        comb.slot1_context = Some(sub_new_ctx);
                        comb.state = 163;
                        Ok(res)
                    }
                    163 => {
                        let mut sub_new_ctx = comb.slot1_context.unwrap();
                        let sub_ctx_arg = sub_new_ctx;
                        let sub_passport_creds = *self.sub_passport.base.creds.lock().unwrap();
                        let res = self.sub_passport.initialize_security_context(
                            &sub_passport_creds,
                            Some(&sub_ctx_arg),
                            target_name,
                            context_req,
                            target_data_rep,
                            input_buffers,
                            &mut sub_new_ctx,
                            output_buffers,
                            context_attr,
                        )?;
                        comb.slot1_context = Some(sub_new_ctx);
                        Ok(res)
                    }
                    _ => Err(SspiError::InvalidHandle),
                }
            }
        }
    }

    fn accept_security_context(
        &self,
        _credential: &CredHandle,
        context: Option<&CtxtHandle>,
        input_buffers: &[SecBuffer],
        context_req: u32,
        target_data_rep: u32,
        new_context: &mut CtxtHandle,
        output_buffers: &mut [SecBuffer],
        context_attr: &mut u32,
    ) -> Result<SspiError, SspiError> {
        let mut sessions = self.sessions.lock().unwrap();

        match context {
            None => {
                let mut handle_id = self.next_handle_id.lock().unwrap();
                let ctxt = CtxtHandle { dw_lower: *handle_id, dw_upper: 0xA000 };
                *handle_id += 1;
                *new_context = ctxt;

                let mut comb = CombinedContext {
                    h_context: ctxt,
                    state: 160,
                    slot0_context: None,
                    slot1_context: None,
                };

                let mut sub_new_ctx = CtxtHandle::default();
                let sub_gk_creds = *self.sub_gk.base.creds.lock().unwrap();
                let res = self.sub_gk.accept_security_context(
                    &sub_gk_creds,
                    None,
                    input_buffers,
                    context_req,
                    target_data_rep,
                    &mut sub_new_ctx,
                    output_buffers,
                    context_attr,
                )?;

                comb.slot0_context = Some(sub_new_ctx);
                comb.state = 161;
                sessions.insert(ctxt, comb);

                Ok(res)
            }
            Some(ctxt) => {
                let comb = sessions.get_mut(ctxt).ok_or(SspiError::InvalidHandle)?;
                match comb.state {
                    161 => {
                        let mut sub_new_ctx = comb.slot0_context.unwrap();
                        let sub_ctx_arg = sub_new_ctx;
                        let sub_gk_creds = *self.sub_gk.base.creds.lock().unwrap();
                        let res = self.sub_gk.accept_security_context(
                            &sub_gk_creds,
                            Some(&sub_ctx_arg),
                            input_buffers,
                            context_req,
                            target_data_rep,
                            &mut sub_new_ctx,
                            output_buffers,
                            context_attr,
                        )?;
                        comb.slot0_context = Some(sub_new_ctx);

                        if res == SspiError::Ok {
                            // GK success! Proceed to state 162
                            comb.state = 162;
                            // Re-write "OK" to client to finish GKSSP
                            let output_tok = output_buffers.iter_mut()
                                .find(|b| b.buffer_type == SecBufferType::Token)
                                .ok_or(SspiError::InvalidToken)?;
                            output_tok.bytes = b"OK".to_vec();
                            Ok(SspiError::ContinueNeeded)
                        } else {
                            Ok(res)
                        }
                    }
                    162 => {
                        let mut sub_new_ctx = CtxtHandle::default();
                        let sub_passport_creds = *self.sub_passport.base.creds.lock().unwrap();
                        let res = self.sub_passport.accept_security_context(
                            &sub_passport_creds,
                            None,
                            input_buffers,
                            context_req,
                            target_data_rep,
                            &mut sub_new_ctx,
                            output_buffers,
                            context_attr,
                        )?;
                        comb.slot1_context = Some(sub_new_ctx);
                        comb.state = 163;
                        Ok(res)
                    }
                    163 => {
                        let mut sub_new_ctx = comb.slot1_context.unwrap();
                        let sub_ctx_arg = sub_new_ctx;
                        let sub_passport_creds = *self.sub_passport.base.creds.lock().unwrap();
                        let res = self.sub_passport.accept_security_context(
                            &sub_passport_creds,
                            Some(&sub_ctx_arg),
                            input_buffers,
                            context_req,
                            target_data_rep,
                            &mut sub_new_ctx,
                            output_buffers,
                            context_attr,
                        )?;
                        comb.slot1_context = Some(sub_new_ctx);
                        Ok(res)
                    }
                    _ => Err(SspiError::InvalidHandle),
                }
            }
        }
    }

    fn delete_security_context(&self, context: &CtxtHandle) -> Result<(), SspiError> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(comb) = sessions.remove(context) {
            if let Some(c0) = comb.slot0_context {
                let _ = self.sub_gk.delete_security_context(&c0);
            }
            if let Some(c1) = comb.slot1_context {
                let _ = self.sub_passport.delete_security_context(&c1);
            }
        }
        Ok(())
    }
}
