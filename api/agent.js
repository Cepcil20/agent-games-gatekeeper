import { handleRequest, signedResponse } from "../agent-core.js";

export const config = { api: { bodyParser: false } };

export default async function handler(req, res) {
  if (req.method === "GET") {
    res.status(200).json({ ok: true, protocolVersion: "v1", service: "proof-gatekeeper" });
    return;
  }
  try {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const raw = Buffer.concat(chunks);
    const out = signedResponse(await handleRequest(raw, req.headers["x-agent-games-signature"]));
    for (const [k, v] of Object.entries(out.headers)) res.setHeader(k, v);
    res.status(out.status).send(out.text);
  } catch (e) {
    res.status(500).json({ error: "server error" });
  }
}
