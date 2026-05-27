"use strict";

const script = document.createElement("script");
script.src = browser.runtime.getURL("page-bridge.js");
script.onload = () => script.remove();
(document.documentElement || document.head).appendChild(script);

window.addEventListener("message", async event => {
  if (event.source !== window ||
      !event.data ||
      event.data.source !== "webauthn-client-dotnet-page") {
    return;
  }

  try {
    const response = await browser.runtime.sendMessage({
      source: "webauthn-client-dotnet-content",
      request: event.data.request
    });

    window.postMessage({
      source: "webauthn-client-dotnet-content",
      id: event.data.request.id,
      response
    }, "*");
  } catch (error) {
    window.postMessage({
      source: "webauthn-client-dotnet-content",
      id: event.data.request.id,
      response: {
        ok: false,
        error: error && error.message ? error.message : String(error)
      }
    }, "*");
  }
});
