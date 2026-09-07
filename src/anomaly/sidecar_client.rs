// LogCrab - GPL-3.0-or-later
// This file is part of LogCrab.
//
// Copyright (C) 2026 Daniel Freiermuth
//
// LogCrab is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// LogCrab is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with LogCrab.  If not, see <https://www.gnu.org/licenses/>.

//! Sidecar client — V2 gRPC protocol.
//!
//! All three unary RPCs (`Health`, `ListModels`, `SubmitSample`) block the
//! calling thread via `Runtime::block_on`.  The bidirectional streaming
//! `ScoreStream` RPC also uses `block_on` for the scoring phase; the optional
//! explain phase is driven by a background thread that reuses the same tokio
//! runtime handle via `Arc<Runtime>`.
//!
//! The public API (struct names, method signatures, `ExplainSession`,
//! `ExplainPollStatus`) is identical to the V1 WebSocket client so that the
//! rest of the codebase requires zero changes.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{mpsc, Arc};
use std::time::Duration;
use tokio_stream::wrappers::UnboundedReceiverStream;

// ── Proto generated code ──────────────────────────────────────────────────────

#[allow(
    clippy::derive_partial_eq_without_eq,
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::result_large_err,
    reason = "tonic-build generates this module from proto/sidecar_v2.proto"
)]
pub mod proto {
    tonic::include_proto!("sidecar.v2");
}

use proto::{
    score_stream_client_message::Payload as ClientPayload,
    score_stream_server_message::Payload as ServerPayload,
    sidecar_client::SidecarClient as GrpcClient, CloseFrame, EndFrame, ExplainFrame, HealthRequest,
    LinesFrame, ListModelsRequest, ScoreStreamClientMessage, ScoreStreamServerMessage, StartFrame,
    SubmitSampleRequest,
};

// ── Constants ─────────────────────────────────────────────────────────────────

const DEFAULT_PORT: u16 = 8765;
const DEFAULT_HOST: &str = "127.0.0.1";

/// Lines per `LinesFrame` sent to the sidecar.
const LINES_PER_CHUNK: usize = 512;

// ── Public data types (identical API to V1) ───────────────────────────────────

#[derive(Debug, Clone)]
pub struct HealthResponse {
    pub api_version: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingCorpus {
    pub filter_profile: String,
    pub description: String,
    pub normalization_versions: HashMap<String, u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkPolicy {
    pub recommended_lines_per_chunk: usize,
    pub max_lines_per_chunk: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputInfo {
    pub score_kind: String,
    pub higher_is_more_anomalous: bool,
    pub supports_explanations: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub id: String,
    #[serde(alias = "display_name")]
    pub name: String,
    pub architecture: String,
    pub kind: String,
    pub version: String,
    pub input_mode: String,
    pub training_corpus: TrainingCorpus,
    pub chunk_policy: ChunkPolicy,
    pub output: OutputInfo,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FilterProfileInfo {
    pub id: String,
    pub description: String,
}

// ── InputLine ─────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct LineId {
    source_id: u16,
    line_number: usize,
    timestamp_unix_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct InputLine {
    pub line_id: LineId,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filetype: Option<String>,
}

impl InputLine {
    #[must_use]
    pub const fn new(
        source_id: u16,
        line_number: usize,
        timestamp_unix_ms: u64,
        message: String,
        template_key: Option<String>,
        source_file: Option<String>,
        filetype: Option<String>,
    ) -> Self {
        Self {
            line_id: LineId {
                source_id,
                line_number,
                timestamp_unix_ms,
            },
            message,
            template_key,
            source_file,
            filetype,
        }
    }
}

// ── Manual classification ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleLabel {
    Benign,
    Anomalous,
}

impl SampleLabel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Benign => "benign",
            Self::Anomalous => "anomalous",
        }
    }
}

impl std::fmt::Display for SampleLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Score stream result ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ScoreEntry {
    pub score: f64,
    pub target_is_unk: bool,
    pub target_is_rare: bool,
}

#[derive(Debug, Default)]
pub struct ScoreStreamResult {
    /// Keyed by `line_number` from `InputLine.line_id`.
    pub scored: HashMap<usize, ScoreEntry>,
    pub warnings: Vec<String>,
}

// ── Explain result types ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AttentionEntry {
    pub line_number: usize,
    pub weight: f32,
}

#[derive(Debug, Clone)]
pub struct TemplateEntry {
    pub template: String,
    pub probability: f32,
}

#[derive(Debug, Clone)]
pub struct ExplainResult {
    pub target_line_number: usize,
    pub target_in_corpus: bool,
    pub target_score: Option<f64>,
    pub target_is_unk: bool,
    pub target_is_rare: bool,
    pub attention: Vec<AttentionEntry>,
    pub top_templates: Vec<TemplateEntry>,
}

pub enum ExplainPollStatus {
    Pending,
    Ready(ExplainResult),
    /// The background thread has exited; no further results will arrive.
    Dead,
}

// ── ExplainSession ────────────────────────────────────────────────────────────

/// Handle to the explain phase of an active `ScoreStream` gRPC session.
///
/// The gRPC stream is kept alive by a background thread that drives it via
/// the shared tokio runtime.  Dropping this struct sends a `Close` frame and
/// exits the thread.
pub struct ExplainSession {
    request_tx: mpsc::SyncSender<usize>,
    result_rx: mpsc::Receiver<ExplainResult>,
    /// Keep the runtime alive as long as the session is alive.
    _rt: Arc<tokio::runtime::Runtime>,
}

impl ExplainSession {
    pub(crate) fn spawn(
        rt: Arc<tokio::runtime::Runtime>,
        req_tx: tokio::sync::mpsc::UnboundedSender<ScoreStreamClientMessage>,
        stream: tonic::codec::Streaming<ScoreStreamServerMessage>,
    ) -> Self {
        let (explain_req_tx, explain_req_rx) = mpsc::sync_channel::<usize>(1);
        let (explain_res_tx, explain_res_rx) = mpsc::sync_channel::<ExplainResult>(4);
        let rt_clone = Arc::clone(&rt);
        std::thread::spawn(move || {
            Self::run_loop(&rt_clone, &req_tx, stream, &explain_req_rx, &explain_res_tx);
        });
        Self {
            request_tx: explain_req_tx,
            result_rx: explain_res_rx,
            _rt: rt,
        }
    }

    /// Request an explanation for `target_line_number`.
    /// Returns `false` if the session has ended or the queue is full.
    #[must_use]
    pub fn request(&self, target_line_number: usize) -> bool {
        self.request_tx.try_send(target_line_number).is_ok()
    }

    /// Poll for a completed explanation without blocking.
    #[must_use]
    pub fn try_recv(&self) -> Option<ExplainResult> {
        self.result_rx.try_recv().ok()
    }

    #[must_use]
    pub fn poll_status(&self) -> ExplainPollStatus {
        match self.result_rx.try_recv() {
            Ok(result) => ExplainPollStatus::Ready(result),
            Err(mpsc::TryRecvError::Empty) => ExplainPollStatus::Pending,
            Err(mpsc::TryRecvError::Disconnected) => ExplainPollStatus::Dead,
        }
    }

    fn run_loop(
        rt: &Arc<tokio::runtime::Runtime>,
        req_tx: &tokio::sync::mpsc::UnboundedSender<ScoreStreamClientMessage>,
        mut stream: tonic::codec::Streaming<ScoreStreamServerMessage>,
        explain_req_rx: &mpsc::Receiver<usize>,
        explain_res_tx: &mpsc::SyncSender<ExplainResult>,
    ) {
        tracing::debug!("explain session: started");
        loop {
            // Wait for an explain request with 50 ms polling so we detect
            // session drop (Disconnected) promptly.
            let target_ln = loop {
                match explain_req_rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(ln) => break ln,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        tracing::debug!("explain session: all senders dropped — sending close");
                        let _ = req_tx.send(ScoreStreamClientMessage {
                            payload: Some(ClientPayload::Close(CloseFrame {})),
                        });
                        return;
                    }
                }
            };

            tracing::debug!("explain session: requesting line {target_ln}");
            let _ = req_tx.send(ScoreStreamClientMessage {
                payload: Some(ClientPayload::Explain(ExplainFrame {
                    target_line_number: target_ln as u64,
                })),
            });

            // Drive the stream on this thread via the shared runtime until the
            // explanation for this request arrives.
            loop {
                match rt.block_on(stream.message()) {
                    Ok(Some(msg)) => {
                        if let Some(ServerPayload::Explanation(e)) = msg.payload {
                            tracing::debug!(
                                "explain session: got result for line {} (in_corpus={})",
                                e.target_line_number,
                                e.target_in_corpus
                            );
                            let result = ExplainResult {
                                target_line_number: e.target_line_number as usize,
                                target_in_corpus: e.target_in_corpus,
                                target_score: e.target_score,
                                target_is_unk: e.target_is_unk,
                                target_is_rare: e.target_is_rare,
                                attention: e
                                    .attention
                                    .into_iter()
                                    .map(|a| AttentionEntry {
                                        line_number: a.line_number as usize,
                                        weight: a.weight,
                                    })
                                    .collect(),
                                top_templates: e
                                    .top_templates
                                    .into_iter()
                                    .map(|t| TemplateEntry {
                                        template: t.template,
                                        probability: t.probability,
                                    })
                                    .collect(),
                            };
                            let _ = explain_res_tx.send(result);
                            break;
                        }
                        // Ignore interleaved warnings or other non-explanation frames.
                    }
                    Ok(None) => {
                        tracing::warn!("explain session: stream ended unexpectedly");
                        return;
                    }
                    Err(e) => {
                        tracing::warn!("explain session: stream error: {e}");
                        return;
                    }
                }
            }
        }
    }
}

// ── Proto conversion helpers ──────────────────────────────────────────────────

fn input_line_to_proto(line: &InputLine) -> proto::InputLine {
    proto::InputLine {
        line_id: Some(proto::LineId {
            source_id: u32::from(line.line_id.source_id),
            line_number: line.line_id.line_number as u64,
            timestamp_unix_ms: line.line_id.timestamp_unix_ms,
        }),
        message: line.message.clone(),
        template_key: line.template_key.clone(),
        source_file: line.source_file.clone(),
        filetype: line.filetype.clone(),
    }
}

fn proto_to_model_info(m: proto::ModelInfo) -> ModelInfo {
    let tc = m.training_corpus.unwrap_or_default();
    let cp = m.chunk_policy.unwrap_or_default();
    let out = m.output.unwrap_or_default();
    ModelInfo {
        id: m.id,
        name: m.name,
        architecture: m.architecture,
        kind: m.kind,
        version: m.version,
        input_mode: m.input_mode,
        training_corpus: TrainingCorpus {
            filter_profile: tc.filter_profile,
            description: tc.description,
            normalization_versions: tc.normalization_versions,
        },
        chunk_policy: ChunkPolicy {
            recommended_lines_per_chunk: cp.recommended_lines_per_chunk as usize,
            max_lines_per_chunk: cp.max_lines_per_chunk as usize,
        },
        output: OutputInfo {
            score_kind: out.score_kind,
            higher_is_more_anomalous: out.higher_is_more_anomalous,
            supports_explanations: out.supports_explanations,
        },
    }
}

// ── SidecarClient ─────────────────────────────────────────────────────────────

/// gRPC client for the `LogBERT` sidecar — V2 protocol.
pub struct SidecarClient {
    rt: Arc<tokio::runtime::Runtime>,
    channel: tonic::transport::Channel,
}

impl SidecarClient {
    #[must_use]
    pub const fn default_host() -> &'static str {
        DEFAULT_HOST
    }

    #[must_use]
    pub const fn default_port() -> u16 {
        DEFAULT_PORT
    }

    /// Connect to the sidecar at `host:port`.
    ///
    /// Creates a dedicated tokio runtime (2 worker threads) and establishes a
    /// lazy gRPC channel.  The actual TCP handshake happens on the first RPC.
    /// # Errors
    ///
    /// Returns an error when the requested operation cannot be completed.
    pub fn connect(host: &str, port: u16) -> Result<Self> {
        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .context("failed to build tokio runtime for sidecar client")?,
        );
        let endpoint = tonic::transport::Channel::from_shared(format!("http://{host}:{port}"))
            .context("invalid sidecar endpoint")?;
        // `connect_lazy()` internally calls `tokio::spawn` to start its
        // background connection-management task, so it must be called from
        // within the runtime context.
        let channel = rt.block_on(async move { endpoint.connect_lazy() });
        Ok(Self { rt, channel })
    }

    fn client(&self) -> GrpcClient<tonic::transport::Channel> {
        // Channel is cheaply cloneable (shared connection pool internally).
        GrpcClient::new(self.channel.clone())
            .max_decoding_message_size(256 * 1024 * 1024)
            .max_encoding_message_size(256 * 1024 * 1024)
    }

    // ── Unary RPCs ────────────────────────────────────────────────────────────

    /// `Health` — liveness / readiness probe.
    /// # Errors
    ///
    /// Returns an error when the requested operation cannot be completed.
    pub fn health_check(&self) -> Result<HealthResponse> {
        let resp = self
            .rt
            .block_on(self.client().health(HealthRequest {}))
            .context("Health RPC failed")?
            .into_inner();
        Ok(HealthResponse {
            api_version: resp.api_version,
            status: resp.status,
        })
    }

    /// `ListModels` — discover available models and filter profiles.
    /// # Errors
    ///
    /// Returns an error when the requested operation cannot be completed.
    pub fn list_models(&self) -> Result<Vec<ModelInfo>> {
        let resp = self
            .rt
            .block_on(self.client().list_models(ListModelsRequest {}))
            .context("ListModels RPC failed")?
            .into_inner();
        Ok(resp.models.into_iter().map(proto_to_model_info).collect())
    }

    /// `SubmitSample` — upload a manually labelled log sample.
    /// # Errors
    ///
    /// Returns an error when the requested operation cannot be completed.
    pub fn submit_sample(
        &self,
        model_id: &str,
        label: SampleLabel,
        classified_line_number: usize,
        lines: &[InputLine],
    ) -> Result<()> {
        let req = SubmitSampleRequest {
            model_id: model_id.to_string(),
            label: label.as_str().to_string(),
            classified_line_number: classified_line_number as u64,
            lines: lines.iter().map(input_line_to_proto).collect(),
        };
        self.rt
            .block_on(self.client().submit_sample(req))
            .context("SubmitSample RPC failed")?;
        Ok(())
    }

    // ── ScoreStream ───────────────────────────────────────────────────────────

    /// Score lines; discard the explain session.
    /// # Errors
    ///
    /// Returns an error when the requested operation cannot be completed.
    pub fn score_stream(
        &self,
        model_id: &str,
        normalization_versions: &HashMap<&str, u32>,
        lines: &[InputLine],
    ) -> Result<ScoreStreamResult> {
        let (result, _session) = self.open_score_stream(
            model_id,
            normalization_versions,
            lines,
            &|| false,
            &mut |_, _| {},
        )?;
        Ok(result)
    }

    /// Like [`score_stream`], keeping the stream open for explain requests.
    /// # Errors
    ///
    /// Returns an error when the requested operation cannot be completed.
    pub fn score_stream_with_explain(
        &self,
        model_id: &str,
        normalization_versions: &HashMap<&str, u32>,
        lines: &[InputLine],
    ) -> Result<(ScoreStreamResult, ExplainSession)> {
        self.open_score_stream(
            model_id,
            normalization_versions,
            lines,
            &|| false,
            &mut |_, _| {},
        )
    }

    /// Like [`score_stream_with_explain`], invoking `on_scores` incrementally
    /// after each GPU batch so the UI can update as scores arrive.
    /// # Errors
    ///
    /// Returns an error when the requested operation cannot be completed.
    #[allow(
        clippy::type_complexity,
        reason = "the callback is single-use and an alias would obscure its scoring contract"
    )]
    pub fn score_stream_streaming(
        &self,
        model_id: &str,
        normalization_versions: &HashMap<&str, u32>,
        lines: &[InputLine],
        is_cancelled: &dyn Fn() -> bool,
        on_scores: &mut dyn FnMut(&HashMap<usize, ScoreEntry>, &ScoreStreamResult, usize),
    ) -> Result<(ScoreStreamResult, ExplainSession)> {
        let total = lines.len();
        self.open_score_stream(
            model_id,
            normalization_versions,
            lines,
            is_cancelled,
            &mut |new_entries, result| on_scores(new_entries, result, total),
        )
    }

    /// Core implementation: runs the scoring phase to completion, then wraps
    /// the live stream in an `ExplainSession`.
    ///
    /// `on_frame` is invoked on the **calling thread** after each `Scores`
    /// message.  The message loop runs outside any `async` block so the
    /// callback can be called directly without unsafe code.
    fn open_score_stream(
        &self,
        model_id: &str,
        normalization_versions: &HashMap<&str, u32>,
        lines: &[InputLine],
        is_cancelled: &dyn Fn() -> bool,
        on_frame: &mut dyn FnMut(&HashMap<usize, ScoreEntry>, &ScoreStreamResult),
    ) -> Result<(ScoreStreamResult, ExplainSession)> {
        profiling::scope!("SidecarClient::open_score_stream");
        let norm_map: HashMap<String, u32> = normalization_versions
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect();
        let mut proto_lines = Vec::with_capacity(lines.len());
        for (index, line) in lines.iter().enumerate() {
            if index % 1_000 == 0 && is_cancelled() {
                bail!("score stream cancelled");
            }
            proto_lines.push(input_line_to_proto(line));
        }
        let model_id = model_id.to_string();
        let n_chunks = proto_lines.len().div_ceil(LINES_PER_CHUNK.max(1));

        let rt = Arc::clone(&self.rt);
        let mut client = self.client();

        // Phase 1: queue all frames and open the RPC. The cancellation future
        // races the response-header wait; dropping that RPC future sends a
        // cancellation to tonic's underlying HTTP/2 stream.
        let (req_tx, mut stream) = self.rt.block_on(async {
            if is_cancelled() {
                bail!("score stream cancelled");
            }

            let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<ScoreStreamClientMessage>();
            tx.send(ScoreStreamClientMessage {
                payload: Some(ClientPayload::Start(StartFrame {
                    api_version: "2".to_string(),
                    model_id: model_id.clone(),
                    filtering_mode: "backend_authoritative".to_string(),
                    normalization_versions: norm_map,
                })),
            })?;

            tracing::info!(
                "Sending {} lines ({n_chunks} chunks, model={model_id}) to sidecar",
                proto_lines.len()
            );
            for (chunk_index, chunk) in proto_lines.chunks(LINES_PER_CHUNK).enumerate() {
                if chunk_index % 16 == 0 && is_cancelled() {
                    bail!("score stream cancelled");
                }
                tx.send(ScoreStreamClientMessage {
                    payload: Some(ClientPayload::Lines(LinesFrame {
                        chunk_index: chunk_index as u32,
                        lines: chunk.to_vec(),
                    })),
                })?;
                if chunk_index % 500 == 499 {
                    tracing::debug!("sent {}/{n_chunks} chunks", chunk_index + 1);
                }
            }
            tx.send(ScoreStreamClientMessage {
                payload: Some(ClientPayload::End(EndFrame {})),
            })?;
            tracing::info!("all {n_chunks} chunks + End frame sent — waiting for Complete");

            let cancellation = async {
                while !is_cancelled() {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            };
            let stream = tokio::select! {
                response = client.score_stream(UnboundedReceiverStream::new(rx)) => {
                    response.context("ScoreStream RPC failed")?.into_inner()
                }
                () = cancellation => bail!("score stream cancelled"),
            };

            Ok::<_, anyhow::Error>((tx, stream))
        })?;

        // Phase 2: drive the response stream on the calling thread.
        // `on_frame` is called directly — no async capture, no unsafe needed.
        let mut result = ScoreStreamResult::default();
        loop {
            if is_cancelled() {
                bail!("score stream cancelled");
            }

            let message = match self.rt.block_on(tokio::time::timeout(
                Duration::from_millis(100),
                stream.message(),
            )) {
                Ok(message) => message.context("stream read error")?,
                Err(_) => continue,
            };
            match message {
                Some(msg) => {
                    if Self::handle_server_msg(msg, &mut result, on_frame)? {
                        break;
                    }
                }
                None => bail!("sidecar stream closed before Complete frame"),
            }
        }

        let session = ExplainSession::spawn(rt, req_tx, stream);
        Ok((result, session))
    }

    /// Handle one inbound server message.
    /// Returns `true` when a `Complete` frame signals end of scoring.
    fn handle_server_msg(
        msg: ScoreStreamServerMessage,
        result: &mut ScoreStreamResult,
        on_frame: &mut dyn FnMut(&HashMap<usize, ScoreEntry>, &ScoreStreamResult),
    ) -> Result<bool> {
        match msg.payload {
            Some(ServerPayload::Accepted(a)) => {
                tracing::info!(run_id = %a.run_id, "sidecar accepted the run");
            }
            Some(ServerPayload::Warning(w)) => {
                tracing::warn!("sidecar warning [{}]: {}", w.code, w.message);
                result.warnings.push(format!("[{}] {}", w.code, w.message));
            }
            Some(ServerPayload::Scores(s)) => {
                let chunk_index = s.chunk_index;
                let mut new_entries: HashMap<usize, ScoreEntry> =
                    HashMap::with_capacity(s.scored.len());
                for scored in s.scored {
                    let ln = scored
                        .line_id
                        .as_ref()
                        .map_or(0, |id| id.line_number as usize);
                    let entry = ScoreEntry {
                        score: scored.score,
                        target_is_unk: scored.target_is_unk,
                        target_is_rare: scored.target_is_rare,
                    };
                    new_entries.insert(ln, entry.clone());
                    result.scored.insert(ln, entry);
                }
                tracing::debug!(
                    "Scores frame #{chunk_index}: +{} scored, {} total so far",
                    new_entries.len(),
                    result.scored.len()
                );
                on_frame(&new_entries, result);
            }
            Some(ServerPayload::Complete(c)) => {
                let s = c.summary.unwrap_or_default();
                tracing::info!(
                    lines_received = s.lines_received,
                    lines_scored = s.lines_scored,
                    lines_filtered = s.lines_filtered,
                    "sidecar signalled complete",
                );
                return Ok(true);
            }
            Some(ServerPayload::Error(e)) => {
                bail!("sidecar error [{}]: {}", e.code, e.message);
            }
            Some(ServerPayload::Explanation(_)) => {
                tracing::warn!("unexpected Explanation frame during scoring phase — ignored");
            }
            None => {
                tracing::warn!("empty server message payload");
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::SidecarClient;
    use std::collections::HashMap;
    use std::net::TcpListener;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn streaming_cancellation_aborts_header_wait() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind test listener");
        let port = listener.local_addr().expect("read listener address").port();
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let (_connection, _) = listener.accept().expect("accept client connection");
            accepted_tx.send(()).expect("signal accepted connection");
            std::thread::sleep(Duration::from_secs(1));
        });
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancellation = Arc::clone(&cancelled);
        let cancellation_thread = std::thread::spawn(move || {
            accepted_rx
                .recv()
                .expect("wait for server to accept the connection");
            std::thread::sleep(Duration::from_millis(50));
            cancellation.store(true, Ordering::Relaxed);
        });
        let start = Instant::now();
        let result = {
            let client = SidecarClient::connect("127.0.0.1", port).expect("create lazy client");
            client.score_stream_streaming(
                "model",
                &HashMap::new(),
                &[],
                &|| cancelled.load(Ordering::Relaxed),
                &mut |_, _, _| {},
            )
        };

        assert!(result.is_err_and(|error| error.to_string() == "score stream cancelled"));
        assert!(start.elapsed() < Duration::from_millis(500));
        cancellation_thread.join().expect("join canceller");
        server.join().expect("join test server");
    }
}
