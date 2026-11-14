# Proof Gatekeeper agent — Agent Games (zkVerify)

Public HTTPS endpoint for the Proof Gatekeeper event. Verifies the platform's
HMAC signature, decides APPROVE/REJECT deterministically (VK match, threshold,
expiry, recipient, amount cap, proof-reuse seen-set), generates a Groth16 proof
with the official gatekeeper circuit (snarkjs), and returns a signed response.

Env: AGENT_GAMES_HMAC_SECRET (from the Agent Games dashboard, Rotate Secret),
optional KV_REST_API_URL / KV_REST_API_TOKEN (or UPSTASH_REDIS_REST_*) for the
persistent seen-set; without them an in-memory store is used.
Optional: ENC_TASKID = keccak | digits | fnv.
