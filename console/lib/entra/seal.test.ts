import { describe, expect, test } from "vitest";

import { chunk, cookieName, joinChunks, seal, unseal, MAX_CHUNKS } from "./seal";

const key = (id: string, fill: number) => ({ id, key: new Uint8Array(32).fill(fill) });
const K1 = key("k1", 1);
const K2 = key("k2", 2);
const later = () => Date.now() + 60_000;

describe("seal", () => {
  test("round trip, and the claims carry the purpose", async () => {
    const sealed = await seal([K1], "session", { person: "entra:x" }, later());
    expect(sealed).not.toContain("entra:x"); // encrypted, not just signed
    expect(await unseal([K1], "session", sealed)).toMatchObject({ person: "entra:x", pur: "session" });
  });

  test("a transaction cookie never opens as a session, nor the reverse", async () => {
    const txn = await seal([K1], "txn", { state: "s" }, later());
    expect(await unseal([K1], "session", txn)).toBeNull();
    const session = await seal([K1], "session", { person: "p" }, later());
    expect(await unseal([K1], "txn", session)).toBeNull();
  });

  test("the cookie's own claims cannot be set by the caller", async () => {
    for (const reserved of ["exp", "iat", "iss", "nbf", "pur"]) {
      await expect(seal([K1], "session", { [reserved]: 1 }, later())).rejects.toThrow("reserved");
    }
  });

  test("rotation: an older listed key still opens; an unlisted one does not", async () => {
    const old = await seal([K1], "session", { a: 1 }, later());
    expect(await unseal([K2, K1], "session", old)).toMatchObject({ a: 1 });
    expect(await unseal([K2], "session", old)).toBeNull();
  });

  test("expired, tampered or foreign values are no value", async () => {
    const expired = await seal([K1], "session", { a: 1 }, Date.now() - 120_000);
    expect(await unseal([K1], "session", expired)).toBeNull();
    const sealed = await seal([K1], "session", { a: 1 }, later());
    const tampered = sealed.slice(0, -3) + (sealed.endsWith("A") ? "BBB" : "AAA");
    expect(await unseal([K1], "session", tampered)).toBeNull();
    expect(await unseal([K1], "session", "not.a.jwe.at.all")).toBeNull();
    expect(await unseal([K1], "session", undefined)).toBeNull();
  });
});

describe("chunks", () => {
  test("split and joined back", () => {
    const value = "x".repeat(9000);
    const parts = chunk(value)!;
    expect(parts.length).toBe(3);
    const jar = new Map(parts.map((p, i) => [cookieName("s", i), p]));
    expect(joinChunks("s", (n) => jar.get(n))).toBe(value);
  });

  test("more than the cap is refused, both ways", () => {
    expect(chunk("x".repeat(3800 * MAX_CHUNKS + 1))).toBeNull();
    const jar = new Map([0, 1, 2, 3].map((i) => [cookieName("s", i), "x"]));
    expect(joinChunks("s", (n) => jar.get(n))).toBeUndefined();
  });

  test("a gap ends the value (a mixed set then fails to open)", () => {
    const jar = new Map([[cookieName("s", 0), "a"], [cookieName("s", 2), "c"]]);
    expect(joinChunks("s", (n) => jar.get(n))).toBe("a");
  });
});
