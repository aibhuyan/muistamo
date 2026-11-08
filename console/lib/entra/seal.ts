import "server-only";

import { EncryptJWT, jwtDecrypt } from "jose";

import type { SessionKey } from "./config";

// HUMAN REVIEW REQUIRED (AGENTS.md): token handling. Cookies the console writes are encrypted and
// authenticated (JWE, dir + A256GCM, from jose). The protected header names the key id and the
// purpose, which is also a claim: a sign-in transaction never opens as a session, nor the reverse.

export type Purpose = "txn" | "session";

const ISSUER = "muistamo-console";
// Cookies are at most about 4 KB each; a sealed session is split into at most this many.
export const CHUNK = 3800;
export const MAX_CHUNKS = 3;

export async function seal(
  keys: SessionKey[],
  purpose: Purpose,
  claims: Record<string, unknown>,
  expiresAt: number,
): Promise<string> {
  const [current] = keys;
  if (!current) throw new Error("no session key");
  for (const reserved of ["exp", "iat", "iss", "nbf", "pur"]) {
    if (reserved in claims) throw new Error(`claim ${reserved} is reserved`);
  }
  return new EncryptJWT({ ...claims, pur: purpose })
    .setProtectedHeader({ alg: "dir", enc: "A256GCM", kid: current.id, typ: purpose })
    .setIssuer(ISSUER)
    .setIssuedAt()
    .setExpirationTime(Math.floor(expiresAt / 1000))
    .encrypt(current.key);
}

// The claims, or null for anything that is not a current, intact cookie of this purpose.
export async function unseal(
  keys: SessionKey[],
  purpose: Purpose,
  token: string | undefined,
): Promise<Record<string, unknown> | null> {
  if (!token) return null;
  try {
    const { payload, protectedHeader } = await jwtDecrypt(
      token,
      (header) => {
        const key = keys.find((k) => k.id === header.kid);
        if (!key) throw new Error("unknown key");
        return key.key;
      },
      {
        issuer: ISSUER,
        keyManagementAlgorithms: ["dir"],
        contentEncryptionAlgorithms: ["A256GCM"],
        typ: purpose,
        requiredClaims: ["exp", "iat", "pur"],
      },
    );
    if (protectedHeader.typ !== purpose || payload.pur !== purpose) return null;
    return payload as Record<string, unknown>;
  } catch {
    return null;
  }
}

// A sealed value split into cookie-sized parts; null when it would need more than MAX_CHUNKS.
export function chunk(sealed: string): string[] | null {
  const parts: string[] = [];
  for (let i = 0; i < sealed.length; i += CHUNK) parts.push(sealed.slice(i, i + CHUNK));
  return parts.length > MAX_CHUNKS ? null : parts;
}

export function cookieName(base: string, index: number): string {
  return `${base}.${index}`;
}

// The parts joined back, from a cookie lookup; a gap or more than MAX_CHUNKS is no value.
export function joinChunks(base: string, get: (name: string) => string | undefined): string | undefined {
  const parts: string[] = [];
  for (let i = 0; i < MAX_CHUNKS; i++) {
    const part = get(cookieName(base, i));
    if (part === undefined) break;
    parts.push(part);
  }
  if (parts.length === 0) return undefined;
  if (get(cookieName(base, MAX_CHUNKS)) !== undefined) return undefined;
  return parts.join("");
}
