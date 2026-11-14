import { handleRequest, signedResponse } from "../../agent-core.js";

export default async (req) => {
  if (req.method === "GET") {
    return new Response(JSON.stringify({ ok: true, protocolVersion: "v1", service: "proof-gatekeeper" }), {
      status: 200, headers: { "content-type": "application/json" },
    });
  }
  try {
    const raw = Buffer.from(await req.arrayBuffer());
    const out = signedResponse(await handleRequest(raw, req.headers.get("x-agent-games-signature")));
    return new Response(out.text, { status: out.status, headers: out.headers });
  } catch (e) {
    return new Response(JSON.stringify({ error: "server error" }), { status: 500, headers: { "content-type": "application/json" } });
  }
};
