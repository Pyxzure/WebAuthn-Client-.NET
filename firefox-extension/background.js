"use strict";

const DEFAULT_SETTINGS = {
  transport: "http",
  httpEndpoint: "http://127.0.0.1:17896/webauthn",
  nativeHost: "webauthn_client_dotnet"
};

browser.runtime.onMessage.addListener((message, sender) => {
  if (!message || message.source !== "webauthn-client-dotnet-content") {
    return false;
  }

  return handleWebAuthnRequest(message.request, sender);
});

async function handleWebAuthnRequest(request, sender) {
  const settings = await getSettings();
  const origin = request.origin || sender.url && new URL(sender.url).origin;
  const bridgeRequest = {
    id: request.id,
    operation: request.operation,
    origin,
    publicKey: request.publicKey
  };

  if (settings.transport === "native") {
    return browser.runtime.sendNativeMessage(settings.nativeHost, bridgeRequest);
  }

  const response = await fetch(settings.httpEndpoint, {
    method: "POST",
    headers: {
      "content-type": "application/json"
    },
    body: JSON.stringify(bridgeRequest)
  });

  const payload = await response.json();
  if (!response.ok && payload && !payload.error) {
    payload.error = `HTTP ${response.status}`;
  }

  return payload;
}

async function getSettings() {
  const stored = await browser.storage.local.get(DEFAULT_SETTINGS);
  return {
    ...DEFAULT_SETTINGS,
    ...stored
  };
}
