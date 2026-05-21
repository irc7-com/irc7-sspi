//! NTLM + Passport Security Provider implementation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::types::{SspiError, CredHandle, CtxtHandle, SecBufferType, SecBuffer, SecurityProvider, CombinedContext};
use crate::default::DefaultSecurityProvider;
use crate::ntlm::NtlmSecurityProvider;
use crate::passport::PassportSecurityProvider;

/// NTLMPassport Security Provider corresponding to VTable at 0x37204338.
/// State machine combines NTLM and Passport authentication steps.
pub struct NtlmPassportSecurityProvider {
    pub base: DefaultSecurityProvider,
    pub sub_ntlm: NtlmSecurityProvider,
    pub sub_passport: PassportSecurityProvider,
    pub sessions: Arc<Mutex<HashMap<CtxtHandle, CombinedContext>>>,
    pub next_handle_id: Arc<Mutex<usize>>,
}

impl NtlmPassportSecurityProvider {
    pub fn new() -> Self {
        Self {
            base: DefaultSecurityProvider {
                name: "NTLMPassport".to_string(),
                creds: Mutex::new(CredHandle { dw_lower: 0x6001, dw_upper: 0xBBBB }),
            },
            sub_ntlm: NtlmSecurityProvider::new(),
            sub_passport: PassportSecurityProvider::new(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            next_handle_id: Arc::new(Mutex::new(1)),
        }
    }
}

impl Default for NtlmPassportSecurityProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityProvider for NtlmPassportSecurityProvider {
    fn name(&self) -> &str {
        self.base.name()
    }

    fn initialize(&self) -> Result<(), SspiError> {
        self.sub_ntlm.initialize()?;
        self.sub_passport.initialize()?;
        Ok(())
    }

    fn shutdown(&self) -> Result<(), SspiError> {
        self.sub_ntlm.shutdown()?;
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
                // State 160: Start Slot 0 (NTLM)
                let mut handle_id = self.next_handle_id.lock().unwrap();
                let ctxt = CtxtHandle { dw_lower: *handle_id, dw_upper: 0x7000 };
                *handle_id += 1;
                *new_context = ctxt;

                let mut comb = CombinedContext {
                    h_context: ctxt,
                    state: 160,
                    slot0_context: None,
                    slot1_context: None,
                };

                let mut sub_new_ctx = CtxtHandle::default();
                let sub_ntlm_creds = *self.sub_ntlm.base.creds.lock().unwrap();
                let res = self.sub_ntlm.initialize_security_context(
                    &sub_ntlm_creds,
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
                            // NTLM completed successfully (Server sent "OK")!
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
                            // Still in NTLM phase (Challenge token received from server)
                            let mut sub_new_ctx = comb.slot0_context.unwrap();
                            let sub_ctx_arg = sub_new_ctx;
                            let sub_ntlm_creds = *self.sub_ntlm.base.creds.lock().unwrap();
                            let _res = self.sub_ntlm.initialize_security_context(
                                &sub_ntlm_creds,
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
                    163 => {
                        // Subsequent Passport chunks on client side
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
                // State 160: Start Slot 0 (NTLM)
                let mut handle_id = self.next_handle_id.lock().unwrap();
                let ctxt = CtxtHandle { dw_lower: *handle_id, dw_upper: 0x8000 };
                *handle_id += 1;
                *new_context = ctxt;

                let mut comb = CombinedContext {
                    h_context: ctxt,
                    state: 160,
                    slot0_context: None,
                    slot1_context: None,
                };

                let mut sub_new_ctx = CtxtHandle::default();
                let sub_ntlm_creds = *self.sub_ntlm.base.creds.lock().unwrap();
                let res = self.sub_ntlm.accept_security_context(
                    &sub_ntlm_creds,
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
                        let sub_ntlm_creds = *self.sub_ntlm.base.creds.lock().unwrap();
                        let res = self.sub_ntlm.accept_security_context(
                            &sub_ntlm_creds,
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
                            // NTLM completed successfully!
                            comb.state = 162; // Transition to state 162 (Ready for Passport on Server side)
                            // Write "OK" to client to finish Slot 0
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
                        // Start Passport on server side
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
                        // Subsequent Passport chunks on server side
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
                let _ = self.sub_ntlm.delete_security_context(&c0);
            }
            if let Some(c1) = comb.slot1_context {
                let _ = self.sub_passport.delete_security_context(&c1);
            }
        }
        Ok(())
    }
}
