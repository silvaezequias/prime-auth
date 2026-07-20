import {
  log
} from "./chunk-XAE6UXTH.mjs";

// src/session.ts
import { createHmac, timingSafeEqual } from "crypto";
var SEP = ".";
function sign(payload, secret) {
  return createHmac("sha256", secret).update(payload).digest("base64url");
}
function encodeSession(data, secret) {
  const payload = Buffer.from(JSON.stringify(data)).toString("base64url");
  const sig = sign(payload, secret);
  log("debug", "Sess\xE3o codificada no cookie.", {
    expiresAt: new Date(data.expiresAt).toISOString(),
    hasRefreshToken: !!data.refreshToken
  });
  return `${payload}${SEP}${sig}`;
}
function decodeSession(cookie, secret) {
  const dotIdx = cookie.lastIndexOf(SEP);
  if (dotIdx === -1) {
    log("warn", "Cookie de sess\xE3o malformado (separador ausente). A sess\xE3o ser\xE1 ignorada.");
    return null;
  }
  const payload = cookie.slice(0, dotIdx);
  const sig = cookie.slice(dotIdx + 1);
  try {
    const expected = Buffer.from(sign(payload, secret));
    const sigBuf = Buffer.from(sig);
    if (expected.length !== sigBuf.length || !timingSafeEqual(expected, sigBuf)) {
      log("warn", "Assinatura do cookie de sess\xE3o inv\xE1lida. Poss\xEDvel adultera\xE7\xE3o ou clientSecret incorreto.");
      return null;
    }
  } catch (err) {
    log("error", "Erro ao verificar assinatura do cookie de sess\xE3o.", { error: String(err) });
    return null;
  }
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    log("debug", "Sess\xE3o decodificada com sucesso.", {
      expiresAt: new Date(data.expiresAt).toISOString(),
      expired: Date.now() >= data.expiresAt
    });
    return data;
  } catch (err) {
    log("error", "Erro ao desserializar dados da sess\xE3o.", { error: String(err) });
    return null;
  }
}

export {
  encodeSession,
  decodeSession
};
