// Copyright (C) 2018-2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::io::Write;
use std::sync::Arc;

use crate::crypto;
use crate::packet;
use crate::ConnectionError;
use crate::Error;
use crate::Result;

pub struct Context {
    provider: Arc<::rustls::crypto::CryptoProvider>,
}

impl Context {
    pub fn new() -> Result<Context> {
        keep_crypto_symbols_live();

        Ok(Context {
            provider: Arc::new(rustls_aws_lc_rs::DEFAULT_TLS13_PROVIDER),
        })
    }

    pub fn new_handshake(&mut self) -> Result<Handshake> {
        Ok(Handshake {
            provider: Arc::clone(&self.provider),
            local_transport_params: Vec::new(),
        })
    }

    pub fn load_verify_locations_from_file(&mut self, _file: &str) -> Result<()> {
        Err(Error::TlsFail)
    }

    pub fn load_verify_locations_from_directory(
        &mut self, _path: &str,
    ) -> Result<()> {
        Err(Error::TlsFail)
    }

    pub fn use_certificate_chain_file(&mut self, _file: &str) -> Result<()> {
        Err(Error::TlsFail)
    }

    pub fn use_privkey_file(&mut self, _file: &str) -> Result<()> {
        Err(Error::TlsFail)
    }

    pub fn set_verify(&mut self, _verify: bool) {}

    pub fn enable_keylog(&mut self) {}

    pub fn set_alpn(&mut self, _v: &[&[u8]]) -> Result<()> {
        Ok(())
    }

    pub fn set_ticket_key(&mut self, _key: &[u8]) -> Result<()> {
        Err(Error::TlsFail)
    }

    pub fn set_early_data_enabled(&mut self, _enabled: bool) {}
}

pub struct Handshake {
    provider: Arc<::rustls::crypto::CryptoProvider>,
    local_transport_params: Vec<u8>,
}

impl Handshake {
    pub fn init(&mut self, _is_server: bool) -> Result<()> {
        let _ = &self.provider;

        Ok(())
    }

    pub fn use_legacy_codepoint(&mut self, _use_legacy: bool) {}

    pub fn set_host_name(&mut self, _name: &str) -> Result<()> {
        Err(Error::TlsFail)
    }

    pub fn set_quic_transport_params(
        &mut self, params: &crate::TransportParams, is_server: bool,
    ) -> Result<()> {
        let mut raw_params = [0; 128];

        let raw_params =
            crate::TransportParams::encode(params, is_server, &mut raw_params)?;

        self.local_transport_params.clear();
        self.local_transport_params.extend_from_slice(raw_params);

        Ok(())
    }

    pub fn quic_transport_params(&self) -> &[u8] {
        &[]
    }

    pub fn alpn_protocol(&self) -> &[u8] {
        &[]
    }

    pub fn server_name(&self) -> Option<&str> {
        None
    }

    pub fn provide_data(
        &mut self, _level: crypto::Level, _buf: &[u8],
    ) -> Result<()> {
        Err(Error::TlsFail)
    }

    pub fn do_handshake(&mut self, ex_data: &mut ExData) -> Result<()> {
        observe_ex_data(ex_data);

        Err(Error::TlsFail)
    }

    pub fn process_post_handshake(
        &mut self, _ex_data: &mut ExData,
    ) -> Result<()> {
        Ok(())
    }

    pub fn write_level(&self) -> crypto::Level {
        crypto::Level::Initial
    }

    pub fn cipher(&self) -> Option<crypto::Algorithm> {
        None
    }

    #[cfg(test)]
    pub fn set_options(&mut self, _opts: u32) {}

    pub fn is_completed(&self) -> bool {
        false
    }

    pub fn is_resumed(&self) -> bool {
        false
    }

    pub fn clear(&mut self) -> Result<()> {
        Err(Error::TlsFail)
    }

    pub fn set_session(&mut self, _session: &[u8]) -> Result<()> {
        Err(Error::TlsFail)
    }

    pub fn curve(&self) -> Option<String> {
        None
    }

    pub fn sigalg(&self) -> Option<String> {
        None
    }

    pub fn peer_cert_chain(&self) -> Option<Vec<&[u8]>> {
        None
    }

    pub fn peer_cert(&self) -> Option<&[u8]> {
        None
    }

    #[cfg(test)]
    pub fn set_failing_private_key_method(&mut self) {}

    pub fn is_in_early_data(&self) -> bool {
        false
    }

    pub fn early_data_reason(&self) -> u32 {
        0
    }
}

pub struct ExData<'a> {
    pub application_protos: &'a Vec<Vec<u8>>,

    pub crypto_ctx: &'a mut [packet::CryptoContext; packet::Epoch::count()],

    pub session: &'a mut Option<Vec<u8>>,

    pub local_error: &'a mut Option<ConnectionError>,

    pub keylog: Option<&'a mut Box<dyn Write + Send + Sync>>,

    pub trace_id: &'a str,

    pub local_transport_params: crate::TransportParams,

    pub recovery_config: crate::recovery::RecoveryConfig,

    pub tx_cap_factor: f64,

    /// PMTUD configuration: (enable, max_probes)
    pub pmtud: Option<(bool, u8)>,

    pub is_server: bool,
}

fn keep_crypto_symbols_live() {
    let _ = crypto::Level::ZeroRTT;
    let _ = crypto::Algorithm::AES256_GCM;
    let _ = crypto::Algorithm::ChaCha20_Poly1305;
}

fn observe_ex_data(ex_data: &mut ExData) {
    let _ = ex_data.application_protos.len();
    let _ = ex_data.crypto_ctx.len();
    let _ = ex_data.session.is_some();
    let _ = ex_data.local_error.is_some();
    let _ = ex_data.keylog.is_some();
    let _ = ex_data.trace_id.len();
    let _ = &ex_data.local_transport_params;
    let _ = ex_data.recovery_config;
    let _ = ex_data.tx_cap_factor;
    let _ = ex_data.pmtud;
    let _ = ex_data.is_server;
}
