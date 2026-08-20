export interface Env {
  APP_ENDPOINT: string;
  FORWARDING_SECRET: string;
  FORWARD_TO?: string;
}

type ForwardableEmailMessage = {
  from: string;
  to: string;
  raw: ReadableStream<Uint8Array>;
  headers: Headers;
  forward: (address: string, headers?: Headers) => Promise<void>;
};

function bytesToBase64(bytes: Uint8Array): string {
  let output = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    output += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(output);
}

function hex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map((value) => value.toString(16).padStart(2, "0")).join("");
}

async function sign(secret: string, timestamp: string, body: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${timestamp}\n${body}`));
  return hex(signature);
}

export default {
  async email(message: ForwardableEmailMessage, env: Env, ctx: ExecutionContext): Promise<void> {
    if (!env.APP_ENDPOINT || !env.FORWARDING_SECRET) {
      throw new Error("APP_ENDPOINT and FORWARDING_SECRET must be configured");
    }

    const raw = new Uint8Array(await new Response(message.raw).arrayBuffer());
    const payload = JSON.stringify({
      from: message.from,
      to: message.to,
      message_id: message.headers.get("Message-ID") || "",
      raw_base64: bytesToBase64(raw),
    });
    const timestamp = String(Math.floor(Date.now() / 1000));
    const signature = await sign(env.FORWARDING_SECRET, timestamp, payload);
    const response = await fetch(env.APP_ENDPOINT, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-julong-forwarding-timestamp": timestamp,
        "x-julong-forwarding-signature": `sha256=${signature}`,
      },
      body: payload,
    });
    if (!response.ok) {
      const detail = (await response.text()).slice(0, 500);
      throw new Error(`矩龙邮箱接收接口返回 ${response.status}: ${detail}`);
    }

    if (env.FORWARD_TO) {
      // Forwarding is deliberately queued after local persistence. A failed
      // external forward should not discard the copy already stored locally.
      ctx.waitUntil(message.forward(env.FORWARD_TO));
    }
  },
};
