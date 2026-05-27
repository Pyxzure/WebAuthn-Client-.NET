"use strict";

(() => {
  if (!navigator.credentials || navigator.credentials.__webAuthnClientDotNetPatched) {
    return;
  }

  const originalCreate = navigator.credentials.create.bind(navigator.credentials);
  const originalGet = navigator.credentials.get.bind(navigator.credentials);
  const pending = new Map();

  Object.defineProperty(navigator.credentials, "__webAuthnClientDotNetPatched", {
    value: true
  });

  navigator.credentials.create = function create(options) {
    if (!options || !options.publicKey) {
      return originalCreate(options);
    }

    return sendToHost("create", options.publicKey);
  };

  navigator.credentials.get = function get(options) {
    if (!options || !options.publicKey) {
      return originalGet(options);
    }

    return sendToHost("get", options.publicKey);
  };

  window.addEventListener("message", event => {
    if (event.source !== window ||
        !event.data ||
        event.data.source !== "webauthn-client-dotnet-content") {
      return;
    }

    const callbacks = pending.get(event.data.id);
    if (!callbacks) {
      return;
    }

    pending.delete(event.data.id);
    clearTimeout(callbacks.timeout);
    const response = event.data.response;
    if (!response || response.ok !== true) {
      callbacks.reject(new DOMException(
        response && response.error ? response.error : "WebAuthn native host failed.",
        "NotAllowedError"));
      return;
    }

    callbacks.resolve(toCredential(response.credential));
  });

  function sendToHost(operation, publicKey) {
    const id = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`;
    const request = {
      id,
      operation,
      origin: window.location.origin,
      publicKey: serializePublicKey(publicKey)
    };

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        pending.delete(id);
        reject(new DOMException("WebAuthn native host timed out.", "NotAllowedError"));
      }, 60000);
      pending.set(id, { resolve, reject, timeout });
      window.postMessage({
        source: "webauthn-client-dotnet-page",
        request
      }, "*");
    });
  }

  function serializePublicKey(publicKey) {
    const copy = {};
    for (const [key, value] of Object.entries(publicKey)) {
      copy[key] = serializeValue(value);
    }

    return copy;
  }

  function serializeValue(value) {
    if (value instanceof ArrayBuffer) {
      return base64UrlEncode(new Uint8Array(value));
    }

    if (ArrayBuffer.isView(value)) {
      return base64UrlEncode(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
    }

    if (Array.isArray(value)) {
      return value.map(serializeValue);
    }

    if (value && typeof value === "object") {
      const copy = {};
      for (const [key, child] of Object.entries(value)) {
        copy[key] = serializeValue(child);
      }

      return copy;
    }

    return value;
  }

  function toCredential(payload) {
    const response = {};
    for (const [key, value] of Object.entries(payload.response || {})) {
      if (key === "transports") {
        response[key] = value;
      } else {
        response[key] = typeof value === "string" ? base64UrlDecode(value) : value;
      }
    }

    if (Array.isArray(response.transports)) {
      response.getTransports = () => response.transports.slice();
    }

    return {
      id: payload.id,
      rawId: base64UrlDecode(payload.rawId),
      type: payload.type || "public-key",
      authenticatorAttachment: payload.authenticatorAttachment || null,
      response,
      getClientExtensionResults() {
        return payload.clientExtensionResults || {};
      },
      toJSON() {
        return payload;
      }
    };
  }

  function base64UrlEncode(bytes) {
    let binary = "";
    for (const byte of bytes) {
      binary += String.fromCharCode(byte);
    }

    return btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");
  }

  function base64UrlDecode(value) {
    const base64 = value
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "=");
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }

    return bytes.buffer;
  }
})();
