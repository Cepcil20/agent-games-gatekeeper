// Proof Gatekeeper agent core — portable handler (Node server + Vercel function).
// Spec sources: agentgames.zkverify.io/build, /events/proof-gatekeeper, /rules (read 2026-11-15).
import crypto from "crypto";
import * as snarkjs from "snarkjs";

const P = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617"); // BN254 scalar field
const CIRCUIT_URLS = {
  wasm: "https://agentgames.zkverify.io/circuits/gatekeeper.wasm",
  zkey: "https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey",
};

// ---------- secret / hmac ----------
function secretBytes() {
  const s = process.env.AGENT_GAMES_HMAC_SECRET || "";
  if (/^[0-9a-fA-F]{64}$/.test(s)) return Buffer.from(s, "hex");
  return Buffer.from(s, "utf8");
}
export function hmacHex(rawBody) {
  return crypto.createHmac("sha256", secretBytes()).update(rawBody).digest("hex");
}
function sigOk(headerVal, rawBody) {
  if (!headerVal) return false;
  const given = String(headerVal).replace(/^sha256=/, "").trim().toLowerCase();
  const want = hmacHex(rawBody);
  try {
    const a = Buffer.from(given, "utf8"), b = Buffer.from(want, "utf8");
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch { return false; }
}

// ---------- state store (Upstash REST if configured, else in-memory) ----------
const mem = new Map();
const U = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL, UT = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
async function storeGet(key) {
  if (U && UT) {
    const r = await fetch(`${U}/get/${encodeURIComponent(key)}`, { headers: { Authorization: `Bearer ${UT}` } });
    const j = await r.json();
    return j.result ?? null;
  }
  return mem.get(key) ?? null;
}
async function storeSet(key, val) {
  if (U && UT) {
    await fetch(`${U}/set/${encodeURIComponent(key)}/${encodeURIComponent(val)}`, { method: "POST", headers: { Authorization: `Bearer ${UT}` } });
    return;
  }
  mem.set(key, val);
}

// ---------- circuit artifacts (fetch once per cold start, cache in memory) ----------
let artifacts = null;
async function getArtifacts() {
  if (artifacts) return artifacts;
  const [w, z] = await Promise.all([
    fetch(CIRCUIT_URLS.wasm).then(r => r.arrayBuffer()),
    fetch(CIRCUIT_URLS.zkey).then(r => r.arrayBuffer()),
  ]);
  artifacts = { wasm: new Uint8Array(w), zkey: new Uint8Array(z) };
  return artifacts;
}

// ---------- field encoders ----------
function hexToField(hex) { return (BigInt(hex) % P).toString(); }
function addrToField(a) { return BigInt(a).toString(); }
// taskId encoding is configurable; practice mode arbitrates. Candidates: "keccak" | "digits" | "fnv"
function fnv1a64(str) {
  let hash = 0xcbf29ce484222325n;
  for (let i = 0; i < str.length; i++) { hash ^= BigInt(str.charCodeAt(i)); hash = (hash * 0x100000001b3n) % (1n << 64n); }
  return hash;
}
let keccak256 = null;
async function loadKeccak() {
  if (keccak256) return keccak256;
  try {
    const mod = await import("js-sha3");
    keccak256 = mod.keccak256;
  } catch { keccak256 = null; }
  return keccak256;
}
async function taskIdField(taskId) {
  const mode = process.env.ENC_TASKID || "keccak";
  if (/^\d+$/.test(taskId)) return taskId;
  if (mode === "digits") return (taskId.replace(/\D/g, "") || "0");
  if (mode === "fnv") return fnv1a64(taskId).toString();
  const k = await loadKeccak();
  if (k) return (BigInt("0x" + k(taskId)) % P).toString();
  return fnv1a64(taskId).toString();
}

// ---------- decision logic (deterministic; mirrors the documented trap list) ----------
export function decide(input, proofWasApprovedBefore) {
  const vkOk = String(input.proof_vk).toLowerCase() === String(input.registered_vk).toLowerCase();
  if (!vkOk) return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", provable: true };
  if (BigInt(input.public_balance) < BigInt(input.minimum)) return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH", provable: true };
  if (BigInt(input.current_block) > BigInt(input.expiry_block)) return { decision: "REJECT", reason_code: "EXPIRED_CONDITION", provable: true };
  if (String(input.recipient).toLowerCase() !== String(input.condition_recipient).toLowerCase()) return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH", provable: true };
  if (BigInt(input.amount) > BigInt(input.max_transfer)) return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW", provable: true };
  if (proofWasApprovedBefore) return { decision: "REJECT", reason_code: "PROOF_REUSED", provable: false };
  return { decision: "APPROVE", reason_code: "VALID_CONDITION", provable: true };
}

async function buildCircuitInput(task, decisionNum) {
  const i = task.input;
  return {
    taskId: await taskIdField(String(task.task_id)),
    registeredVkHash: hexToField(i.registered_vk),
    proofVkHash: hexToField(i.proof_vk),
    minimum: String(i.minimum),
    publicBalance: String(i.public_balance),
    expiryBlock: String(i.expiry_block),
    currentBlock: String(i.current_block),
    recipient: addrToField(i.recipient),
    conditionRecipient: addrToField(i.condition_recipient),
    amount: String(i.amount),
    maxTransfer: String(i.max_transfer),
    decision: decisionNum,
    salt: (BigInt("0x" + crypto.randomBytes(16).toString("hex"))).toString(),
  };
}

// ---------- main task handling ----------
export async function handleTask(task) {
  const taskId = String(task.task_id);
  const cached = await storeGet("resp:" + taskId);
  if (cached) return JSON.parse(cached);

  const proofTx = String(task.input.proof_tx || "");
  const seenBy = proofTx ? await storeGet("seen:" + proofTx.toLowerCase()) : null;
  const reused = !!(seenBy && seenBy !== taskId);
  const d = decide(task.input, reused);

  const out = { decision: d.decision, reason_code: d.reason_code, proof_tx: proofTx };
  if (d.provable) {
    try {
      const { wasm, zkey } = await getArtifacts();
      const input = await buildCircuitInput(task, d.decision === "APPROVE" ? 1 : 0);
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);
      out.proof = proof;
      out.public_signals = publicSignals;
    } catch (e) {
      console.error("prove failed:", e && e.message ? e.message.slice(0, 200) : e);
      // fail closed: keep the (deterministic) decision, omit proof rather than time out
    }
  }
  if (d.decision === "APPROVE" && proofTx) await storeSet("seen:" + proofTx.toLowerCase(), taskId);
  await storeSet("resp:" + taskId, JSON.stringify(out));
  return out;
}

// ---------- request handler: (rawBody: Buffer, sigHeader: string) -> { status, bodyObj } ----------
export async function handleRequest(rawBody, sigHeader) {
  if (!sigOk(sigHeader, rawBody)) return { status: 401, body: { error: "invalid signature" }, sign: false };
  let msg;
  try { msg = JSON.parse(rawBody.toString("utf8")); } catch { return { status: 400, body: { error: "bad json" }, sign: false }; }
  if (msg.type === "agent-games.preflight.v1") return { status: 200, body: { ok: true, protocolVersion: "v1" }, sign: true };
  if (msg.type === "agent-games.proof-gatekeeper.v1") {
    try {
      const body = await handleTask(msg);
      return { status: 200, body, sign: true };
    } catch (e) {
      console.error("task failed:", e && e.message ? e.message.slice(0, 200) : e);
      return { status: 200, body: { decision: "REJECT", reason_code: "INTERNAL_ERROR" }, sign: true };
    }
  }
  return { status: 400, body: { error: "unknown type" }, sign: false };
}

export function signedResponse({ status, body, sign }) {
  const text = JSON.stringify(body);
  const headers = { "content-type": "application/json" };
  if (sign) headers["x-agent-games-signature"] = hmacHex(Buffer.from(text, "utf8"));
  return { status, headers, text };
}
