// src/passkey-spike.ts
var STORED_CREDENTIAL_KEY = "spike.passkey.credential_id";
var STORED_SPKI_KEY = "spike.passkey.spki";
function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
function toBase64Url(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromBase64Url(text) {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - text.length % 4) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}
function randomBytes(length) {
  const bytes = new Uint8Array(new ArrayBuffer(length));
  crypto.getRandomValues(bytes);
  return bytes;
}
function concatenate(first, second) {
  const joined = new Uint8Array(new ArrayBuffer(first.length + second.length));
  joined.set(first, 0);
  joined.set(second, first.length);
  return joined;
}
async function fingerprint8(rawId, spki) {
  const digest = await crypto.subtle.digest("SHA-256", concatenate(rawId, spki));
  return toHex(new Uint8Array(digest)).slice(0, 8);
}
function getElement(id) {
  const element = document.getElementById(id);
  if (element === null) {
    throw new Error(`missing element #${id}`);
  }
  return element;
}
function readChallengeFromFragment() {
  const params = new URLSearchParams(location.hash.replace(/^#/, ""));
  const value = params.get("c");
  return value !== null && /^[A-Za-z0-9_-]{16,128}$/.test(value) ? value : null;
}
var StatusLog = class {
  constructor(target) {
    this.target = target;
  }
  target;
  lines = [];
  add(label, value) {
    const time = (/* @__PURE__ */ new Date()).toLocaleTimeString("he-IL", { hour12: false });
    this.lines.push(`[${time}] ${label}: ${value}`);
    this.target.textContent = this.lines.join("\n");
  }
};
var PasskeySpike = class {
  constructor(log) {
    this.log = log;
  }
  log;
  async start() {
    this.log.add("origin", location.origin);
    this.log.add("rp.id (hostname)", location.hostname);
    this.log.add("PublicKeyCredential", typeof PublicKeyCredential === "undefined" ? "MISSING" : "present");
    this.log.add("crypto.subtle Ed25519", await this.probeEd25519());
    const fragment = readChallengeFromFragment();
    this.log.add("challenge from #c=", fragment === null ? "none (a random one is used)" : "present");
    const stored = localStorage.getItem(STORED_CREDENTIAL_KEY);
    this.log.add("registered credential in this browser", stored === null ? "none yet" : "yes");
    this.addButton("btn-register", "register (\u05D9\u05E6\u05D9\u05E8\u05EA passkey)", () => this.register());
    this.addButton("btn-assert", "assert (\u05D7\u05EA\u05D9\u05DE\u05D4 \u05E2\u05DC \u05D4\u05D0\u05EA\u05D2\u05E8)", () => this.assertChallenge(fragment));
    this.addButton("btn-copy", "\u05D4\u05E2\u05EA\u05E7 JSON", () => this.copyBlob());
  }
  addButton(id, label, handler) {
    const button = document.createElement("button");
    button.id = id;
    button.type = "button";
    button.className = "spike-button";
    button.textContent = label;
    button.addEventListener("click", () => {
      void this.guarded(label, handler);
    });
    getElement("buttons").appendChild(button);
  }
  async guarded(label, handler) {
    try {
      await handler();
    } catch (error) {
      const name = error instanceof Error ? error.name : "error";
      const message = error instanceof Error ? error.message : String(error);
      this.log.add(`${label} ERROR`, `${name}: ${message}`);
    }
  }
  async probeEd25519() {
    try {
      await crypto.subtle.importKey("raw", new Uint8Array(32), { name: "Ed25519" }, false, ["verify"]);
      return "supported";
    } catch (error) {
      return error instanceof Error ? `not usable (${error.name})` : "not usable";
    }
  }
  async register() {
    const credential = await navigator.credentials.create({
      publicKey: {
        rp: { id: location.hostname, name: "Fleet alerts spike" },
        user: { id: randomBytes(16), name: "owner-spike", displayName: "Owner (spike)" },
        challenge: randomBytes(32),
        pubKeyCredParams: [{ alg: -7, type: "public-key" }],
        authenticatorSelection: { userVerification: "required", residentKey: "discouraged" },
        attestation: "none",
        timeout: 12e4
      }
    });
    if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAttestationResponse)) {
      this.log.add("register", "no PublicKeyCredential returned");
      return;
    }
    const response = credential.response;
    const spkiBuffer = response.getPublicKey();
    if (spkiBuffer === null) {
      this.log.add("register", "getPublicKey() returned null");
      return;
    }
    const spki = new Uint8Array(spkiBuffer);
    const rawId = new Uint8Array(credential.rawId);
    localStorage.setItem(STORED_CREDENTIAL_KEY, toBase64Url(rawId));
    localStorage.setItem(STORED_SPKI_KEY, toBase64Url(spki));
    this.log.add("register", "credential created");
    this.log.add("getPublicKeyAlgorithm", String(response.getPublicKeyAlgorithm()));
    this.log.add("authenticatorAttachment", String(credential.authenticatorAttachment));
    this.log.add("transports", response.getTransports().join(",") || "none reported");
    this.log.add("fp8 (sha256(rawId || spki) first 8 hex)", await fingerprint8(rawId, spki));
  }
  async assertChallenge(fragmentChallenge) {
    const storedId = localStorage.getItem(STORED_CREDENTIAL_KEY);
    const storedSpki = localStorage.getItem(STORED_SPKI_KEY);
    if (storedId === null || storedSpki === null) {
      this.log.add("assert", "register first (no credential stored in this browser)");
      return;
    }
    const challenge = fragmentChallenge ?? toBase64Url(randomBytes(32));
    const credential = await navigator.credentials.get({
      publicKey: {
        rpId: location.hostname,
        challenge: fromBase64Url(challenge),
        allowCredentials: [{ type: "public-key", id: fromBase64Url(storedId) }],
        userVerification: "required",
        timeout: 12e4
      }
    });
    if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAssertionResponse)) {
      this.log.add("assert", "no assertion returned");
      return;
    }
    const response = credential.response;
    const blob = {
      rp_id: location.hostname,
      origin: location.origin,
      credential_id: toBase64Url(credential.rawId),
      spki_b64u: storedSpki,
      authenticator_data: toBase64Url(response.authenticatorData),
      client_data_json: toBase64Url(response.clientDataJSON),
      signature: toBase64Url(response.signature),
      challenge
    };
    getElement("blob").textContent = JSON.stringify(blob, null, 2);
    const flags = new Uint8Array(response.authenticatorData)[32] ?? 0;
    this.log.add("assert", "assertion produced; JSON shown below");
    this.log.add("flags byte", `0x${flags.toString(16).padStart(2, "0")} (UP=${flags & 1 ? "1" : "0"}, UV=${flags & 4 ? "1" : "0"})`);
    this.log.add("authenticatorAttachment", String(credential.authenticatorAttachment));
  }
  async copyBlob() {
    const text = getElement("blob").textContent ?? "";
    if (text === "") {
      this.log.add("copy", "nothing to copy yet, run assert first");
      return;
    }
    await navigator.clipboard.writeText(text);
    this.log.add("copy", "JSON copied to the clipboard");
  }
};
async function boot() {
  const log = new StatusLog(getElement("out"));
  await new PasskeySpike(log).start();
}
void boot();
export {
  PasskeySpike
};
