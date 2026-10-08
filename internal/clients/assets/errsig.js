// Reference implementation of the agents.ekaii.fr ErrSig algorithm (SPEC-v2 8.3, 27.1).
// ErrSig normalises an error message to a stable signature so /h/<sha256(ErrSig)> finds the fix.
// No dependencies; runs in Node (>=16) and the browser (crypto.subtle for the hash).
export const BASE = "https://agents.ekaii.fr";

const INVISIBLE =
  /[­͏؜ᅟᅠ឴឵ㅤ﻿ﾠ᠋-᠏​-‏‪-‮⁠-⁤⁦-⁯︀-️]/gu;

export function errsig(s) {
  s = s.normalize("NFKC").replace(INVISIBLE, "");
  s = s.replace(/[a-z][a-z0-9+.-]*:\/\/[^\s'"<>]+/g, "U");
  s = s.replace(/'[^'\n]*'|"[^"\n]*"/g, "'S'");
  s = s.replace(/(^|[^A-Za-z0-9])(?:0x[0-9a-fA-F]+|[0-9a-f]{8,})\b/g, "$1H");
  s = s.replace(/(^|[\s(\[=:,])\/(?:[^\s/:'"]+\/)*[^\s/:'"]+/g, "$1/P");
  s = s.replace(/:\d+:\d+\b/g, ":N:N");
  s = s.replace(/(^|[^A-Za-z0-9_.])\d{2,}\b/g, "$1N");
  s = s.split(/\s+/).filter(Boolean).join(" ");
  return [...s].slice(0, 160).join("");
}

export async function sigHash(s) {
  const bytes = new TextEncoder().encode(errsig(s));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function lookupURL(s) {
  return BASE + "/h/" + (await sigHash(s));
}
