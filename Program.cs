using System.Text.Json;
using WebAuthn_Client_.NET;
using WebAuthnClient;

FIDOWebAuthn fido = new();
fido.CredLen = 32;

//Test with WebAuthn.io
var webauth = new WebAuthnIO("test-session");

// Registration
var opts = await webauth.GetRegistrationOptionsAsync(webauth.GetUser());
var fidostr = fido.Create(opts);
string teststr = JsonSerializer.Serialize(fidostr, new JsonSerializerOptions { WriteIndented = true });

Console.WriteLine("Registration");
Console.WriteLine(teststr);

await webauth.GetRegistrationVerificationAsync(webauth.GetUser(), teststr);

// Authentication
opts = await webauth.GetAuthenticationOptionsAsync();
Console.WriteLine();
Console.WriteLine("Authentication");

var authResp = fido.Get(opts);
var authObj = new AuthenticationResponseJSON()
{
    Id = authResp.Id,
    RawId = authResp.RawId,
    Type = authResp.Type,
    Response = authResp.Response
};

Console.WriteLine(JsonSerializer.Serialize(authResp));

await webauth.GetAuthenticationVerificationAsync(authObj);

Console.WriteLine("--- Test Completed ---");