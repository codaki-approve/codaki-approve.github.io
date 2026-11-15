// src/miniapp-spike.ts
var BIOMETRIC_REASON = "\u05DB\u05E0\u05D9\u05E1\u05D4 \u05DC\u05DE\u05E8\u05DB\u05D6 \u05D4\u05D4\u05EA\u05E8\u05D0\u05D5\u05EA";
var STORED_PREFIX_KEY = "spike.biometric_token_sha8";
function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}
async function sha256Prefix(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return toHex(new Uint8Array(digest)).slice(0, 8);
}
function getElement(id) {
  const element = document.getElementById(id);
  if (element === null) {
    throw new Error(`missing element #${id}`);
  }
  return element;
}
var SpikeLog = class {
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
function waitForCallback(register, timeoutMs) {
  return new Promise((resolve) => {
    const timer = window.setTimeout(() => resolve("timeout"), timeoutMs);
    register((value) => {
      window.clearTimeout(timer);
      resolve(value);
    });
  });
}
var MiniAppSpike = class {
  constructor(webApp, log) {
    this.webApp = webApp;
    this.log = log;
  }
  webApp;
  log;
  start() {
    this.webApp.ready();
    const startParam = this.webApp.initDataUnsafe.start_param;
    this.log.add("S1 start_param", startParam === void 0 ? "ABSENT" : startParam);
    this.log.add("initData present", this.webApp.initData.length > 0 ? `yes, length ${this.webApp.initData.length}` : "no");
    this.log.add("platform", this.webApp.platform);
    this.log.add("version", this.webApp.version);
    this.log.add("isVersionAtLeast(7.2)", String(this.webApp.isVersionAtLeast("7.2")));
    const stored = localStorage.getItem(STORED_PREFIX_KEY);
    this.log.add("S6 stored token sha8 (localStorage)", stored === null ? "none yet" : stored);
    this.addButton("btn-init", "BiometricManager.init", () => this.init());
    this.addButton("btn-request", "requestAccess", () => this.requestAccess());
    this.addButton("btn-auth", "authenticate", () => this.authenticate());
    this.addButton("btn-update", "updateBiometricToken (\u05D7\u05D3\u05E9 \u05D0\u05E7\u05E8\u05D0\u05D9)", () => this.updateToken());
    this.addButton("btn-read", "\u05E7\u05E8\u05D0 \u05D8\u05D5\u05E7\u05DF (authenticate \u05D5\u05D4\u05E9\u05D5\u05D5\u05D0\u05D4)", () => this.readToken());
    this.addButton("btn-passkey", "\u05E4\u05EA\u05D7 \u05D0\u05EA \u05D3\u05E3 \u05D4-passkey (openLink)", () => this.openPasskeyPage());
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
      this.log.add(`${label} ERROR`, error instanceof Error ? error.message : String(error));
    }
  }
  async init() {
    const manager = this.webApp.BiometricManager;
    const result = await waitForCallback((done) => {
      manager.init(() => done(true));
    }, 15e3);
    this.log.add("init", result === "timeout" ? "TIMEOUT (no callback in 15 s)" : "callback fired");
    this.log.add("isInited", String(manager.isInited));
    this.log.add("isBiometricAvailable", String(manager.isBiometricAvailable));
    this.log.add("biometricType", manager.biometricType);
    this.log.add("isAccessRequested", String(manager.isAccessRequested));
    this.log.add("isAccessGranted", String(manager.isAccessGranted));
    this.log.add("isBiometricTokenSaved", String(manager.isBiometricTokenSaved));
  }
  async requestAccess() {
    const manager = this.webApp.BiometricManager;
    const result = await waitForCallback((done) => {
      manager.requestAccess({ reason: BIOMETRIC_REASON }, (granted) => done(granted));
    }, 6e4);
    this.log.add("requestAccess granted", String(result));
    this.log.add("isAccessGranted", String(manager.isAccessGranted));
  }
  async authenticate() {
    const outcome = await this.runAuthenticate();
    this.log.add("authenticate", outcome.authenticated ? "success" : "FAILED or cancelled");
    this.log.add("token returned", outcome.token === void 0 || outcome.token === "" ? "no" : "yes");
  }
  async updateToken() {
    const manager = this.webApp.BiometricManager;
    const token = toHex(randomBytes(16));
    const result = await waitForCallback((done) => {
      manager.updateBiometricToken(token, (updated) => done(updated));
    }, 3e4);
    this.log.add("updateBiometricToken updated", String(result));
    if (result === true) {
      const prefix = await sha256Prefix(token);
      localStorage.setItem(STORED_PREFIX_KEY, prefix);
      this.log.add("stored token sha8", prefix);
    }
    this.log.add("isBiometricTokenSaved", String(manager.isBiometricTokenSaved));
  }
  async readToken() {
    const outcome = await this.runAuthenticate();
    if (!outcome.authenticated) {
      this.log.add("read token", "authenticate FAILED or cancelled");
      return;
    }
    if (outcome.token === void 0 || outcome.token === "") {
      this.log.add("read token", "authenticated but NO token returned (token lost)");
      return;
    }
    const returned = await sha256Prefix(outcome.token);
    const stored = localStorage.getItem(STORED_PREFIX_KEY);
    this.log.add("returned token sha8", returned);
    this.log.add("stored token sha8", stored === null ? "none (run updateBiometricToken first)" : stored);
    this.log.add("token compare", stored === returned ? "MATCH, token survived" : "NO MATCH");
  }
  async runAuthenticate() {
    const manager = this.webApp.BiometricManager;
    const result = await waitForCallback((done) => {
      manager.authenticate({ reason: BIOMETRIC_REASON }, (authenticated, token) => done({ authenticated, token }));
    }, 6e4);
    return result === "timeout" ? { authenticated: false, token: void 0 } : result;
  }
  openPasskeyPage() {
    const challenge = toBase64Url(randomBytes(32));
    const target = `${location.origin}/spike/passkey.html#c=${challenge}`;
    this.log.add("openLink", target);
    this.webApp.openLink(target);
  }
};
function boot() {
  const log = new SpikeLog(getElement("out"));
  if (typeof Telegram === "undefined") {
    log.add("ERROR", "Telegram.WebApp is missing: open this page as a Mini App inside Telegram");
    return;
  }
  new MiniAppSpike(Telegram.WebApp, log).start();
}
boot();
export {
  MiniAppSpike
};
