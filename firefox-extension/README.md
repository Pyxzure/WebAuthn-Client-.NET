# Firefox Extension Bridge

This extension intercepts page calls to `navigator.credentials.create({ publicKey })`
and `navigator.credentials.get({ publicKey })`, converts browser `ArrayBuffer`
values to base64url JSON, and forwards the request to the .NET bridge host.

## Debug HTTP Mode

Run the host:

```powershell
dotnet run --project .\WebAuthn.Client.NativeHost -- --http 127.0.0.1:17896
```

Load `firefox-extension` as a temporary extension from `about:debugging`.
The default extension settings use:

```text
http://127.0.0.1:17896/webauthn
```
For Windows, credential is saved at `%LOCALAPPDATA%\WebAuthnClientDotNet\`

## Native Messaging Mode

Publish or build the native host, then install a Firefox native messaging
manifest named `webauthn_client_dotnet`.

Windows per-user manifest registration:

```powershell
New-Item -Force HKCU:\Software\Mozilla\NativeMessagingHosts\webauthn_client_dotnet
Set-ItemProperty HKCU:\Software\Mozilla\NativeMessagingHosts\webauthn_client_dotnet `
  -Name '(default)' `
  -Value 'D:\absolute\path\to\webauthn_client_dotnet.windows.json'
```

Linux per-user manifest location:

```text
~/.mozilla/native-messaging-hosts/webauthn_client_dotnet.json
```

Then set extension storage to use native transport from the extension console:

```javascript
await browser.storage.local.set({ transport: "native" });
```

Switch back to debug HTTP mode:

```javascript
await browser.storage.local.set({ transport: "http" });
```

## Notes

The returned credential is a JavaScript object shaped like a `PublicKeyCredential`.
Most WebAuthn libraries consume the fields directly. Pages that require
`credential instanceof PublicKeyCredential` may reject it because extensions
cannot construct real browser-native WebAuthn credential instances.
