// src/session.ts
import { createHmac, timingSafeEqual } from "crypto";
var SEP = ".";
function sign(payload, secret) {
  return createHmac("sha256", secret).update(payload).digest("base64url");
}
function encodeSession(data, secret) {
  const payload = Buffer.from(JSON.stringify(data)).toString("base64url");
  const sig = sign(payload, secret);
  return `${payload}${SEP}${sig}`;
}
function decodeSession(cookie, secret) {
  const dotIdx = cookie.lastIndexOf(SEP);
  if (dotIdx === -1) return null;
  const payload = cookie.slice(0, dotIdx);
  const sig = cookie.slice(dotIdx + 1);
  const expected = sign(payload, secret);
  try {
    const expectedBuf = Buffer.from(expected);
    const sigBuf = Buffer.from(sig);
    if (expectedBuf.length !== sigBuf.length) return null;
    if (!timingSafeEqual(expectedBuf, sigBuf)) return null;
  } catch {
    return null;
  }
  try {
    return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

export {
  encodeSession,
  decodeSession
};
