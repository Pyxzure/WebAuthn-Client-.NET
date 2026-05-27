using System.Buffers.Binary;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using WebAuthn_Client_.NET;
using WebAuthn_Client_.NET.Storage;

var settings = HostSettings.Parse(args);
var host = new WebAuthnBridgeHost(settings);

if (settings.Mode == HostMode.NativeMessaging)
{
    await host.RunNativeMessagingAsync();
}
else
{
    await host.RunHttpAsync();
}

internal enum HostMode
{
    Http,
    NativeMessaging
}

internal sealed class HostSettings
{
    public HostMode Mode { get; private init; } = HostMode.NativeMessaging;
    public string Url { get; private init; } = "http://127.0.0.1:17896/";
    public string StoragePath { get; private init; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "WebAuthnClientDotNet",
        "credentials.csv");

    public static HostSettings Parse(string[] args)
    {
        var mode = HostMode.NativeMessaging;
        var url = "http://127.0.0.1:17896/";
        string? storagePath = null;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--native-host":
                    mode = HostMode.NativeMessaging;
                    break;
                case "--http":
                    mode = HostMode.Http;
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
                    {
                        url = NormalizeHttpUrl(args[++i]);
                    }
                    break;
                case "--storage":
                    if (i + 1 >= args.Length)
                    {
                        throw new ArgumentException("--storage requires a file path.");
                    }
                    storagePath = args[++i];
                    break;
                case "--help":
                case "-h":
                    PrintHelp();
                    Environment.Exit(0);
                    break;
            }
        }

        return new HostSettings
        {
            Mode = mode,
            Url = url,
            StoragePath = storagePath ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "WebAuthnClientDotNet",
                "credentials.csv")
        };
    }

    private static string NormalizeHttpUrl(string value)
    {
        if (!value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !value.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            value = $"http://{value}";
        }

        return value.EndsWith('/') ? value : $"{value}/";
    }

    private static void PrintHelp()
    {
        Console.WriteLine("Usage:");
        Console.WriteLine("  WebAuthn.Client.NativeHost --http 127.0.0.1:17896 [--storage credentials.csv]");
        Console.WriteLine("  WebAuthn.Client.NativeHost [--native-host] [--storage credentials.csv]");
    }
}

internal sealed class WebAuthnBridgeHost
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly FIDOWebAuthn _fido;
    private readonly HostSettings _settings;

    public WebAuthnBridgeHost(HostSettings settings)
    {
        _settings = settings;
        var storageDirectory = Path.GetDirectoryName(settings.StoragePath);
        if (!string.IsNullOrWhiteSpace(storageDirectory))
        {
            Directory.CreateDirectory(storageDirectory);
        }

        _fido = new FIDOWebAuthn(new CsvCredentialStorage(settings.StoragePath));
    }

    public async Task RunHttpAsync()
    {
        using var listener = new HttpListener();
        listener.Prefixes.Add(_settings.Url);
        listener.Start();

        Console.WriteLine($"WebAuthn debug host listening at {_settings.Url}");
        Console.WriteLine("POST JSON requests to /webauthn.");

        while (true)
        {
            var context = await listener.GetContextAsync();
            _ = Task.Run(() => HandleHttpContextAsync(context));
        }
    }

    public async Task RunNativeMessagingAsync()
    {
        var input = Console.OpenStandardInput();
        var output = Console.OpenStandardOutput();

        while (true)
        {
            var lengthBuffer = new byte[4];
            if (!await ReadExactlyOrEndAsync(input, lengthBuffer))
            {
                return;
            }

            var length = BinaryPrimitives.ReadUInt32LittleEndian(lengthBuffer);
            if (length == 0 || length > 1024 * 1024)
            {
                await WriteNativeResponseAsync(output, BridgeResponse.Fail(null, $"Invalid native message length: {length}."));
                continue;
            }

            var payload = new byte[length];
            if (!await ReadExactlyOrEndAsync(input, payload))
            {
                return;
            }

            BridgeResponse response;
            try
            {
                var requestJson = Encoding.UTF8.GetString(payload);
                response = HandleRequest(requestJson);
            }
            catch (Exception ex)
            {
                response = BridgeResponse.Fail(null, ex.Message);
            }

            await WriteNativeResponseAsync(output, response);
        }
    }

    private async Task HandleHttpContextAsync(HttpListenerContext context)
    {
        try
        {
            AddCorsHeaders(context.Response);

            if (context.Request.HttpMethod == "OPTIONS")
            {
                context.Response.StatusCode = 204;
                context.Response.Close();
                return;
            }

            if (context.Request.HttpMethod != "POST" || context.Request.Url?.AbsolutePath != "/webauthn")
            {
                context.Response.StatusCode = 404;
                await WriteHttpJsonAsync(context.Response, BridgeResponse.Fail(null, "Use POST /webauthn."));
                return;
            }

            using var reader = new StreamReader(context.Request.InputStream, context.Request.ContentEncoding);
            var requestJson = await reader.ReadToEndAsync();
            var response = HandleRequest(requestJson);
            context.Response.StatusCode = response.Ok ? 200 : 400;
            await WriteHttpJsonAsync(context.Response, response);
        }
        catch (Exception ex)
        {
            context.Response.StatusCode = 500;
            await WriteHttpJsonAsync(context.Response, BridgeResponse.Fail(null, ex.Message));
        }
    }

    private BridgeResponse HandleRequest(string requestJson)
    {
        var request = JsonSerializer.Deserialize<BridgeRequest>(requestJson, JsonOptions)
            ?? throw new ArgumentException("Request body is empty.");

        if (string.IsNullOrWhiteSpace(request.Operation))
        {
            return BridgeResponse.Fail(request.Id, "Missing operation.");
        }

        if (string.IsNullOrWhiteSpace(request.Origin))
        {
            return BridgeResponse.Fail(request.Id, "Missing origin.");
        }

        try
        {
            var publicKeyJson = request.PublicKey.GetRawText();
            var credential = request.Operation switch
            {
                "create" => Create(publicKeyJson, request.Origin),
                "get" => Get(publicKeyJson, request.Origin),
                _ => throw new NotSupportedException($"Unsupported operation '{request.Operation}'.")
            };

            return BridgeResponse.Success(request.Id, credential);
        }
        catch (Exception ex)
        {
            return BridgeResponse.Fail(request.Id, ex.Message);
        }
    }

    private PublicKeyCredential Create(string publicKeyJson, string origin)
    {
        var options = JsonSerializer.Deserialize<PublicKeyCredentialCreationOptions>(publicKeyJson, JsonOptions)
            ?? throw new ArgumentException("Invalid create options.");

        var rpId = GetEffectiveRpId(options.Rp.Id, origin);
        ValidateRpForOrigin(rpId, origin);
        return _fido.Create(options, origin);
    }

    private PublicKeyCredential Get(string publicKeyJson, string origin)
    {
        var options = JsonSerializer.Deserialize<PublicKeyCredentialRequestOptions>(publicKeyJson, JsonOptions)
            ?? throw new ArgumentException("Invalid get options.");

        var rpId = GetEffectiveRpId(options.RpId, origin);
        ValidateRpForOrigin(rpId, origin);
        return _fido.Get(options, origin);
    }

    private static void ValidateRpForOrigin(string rpId, string origin)
    {
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var originUri))
        {
            throw new UnauthorizedAccessException("Invalid origin.");
        }

        if (originUri.Scheme != Uri.UriSchemeHttps &&
            !IsLocalhost(originUri.Host))
        {
            throw new UnauthorizedAccessException("WebAuthn origins must be HTTPS unless they are localhost.");
        }

        var host = originUri.IdnHost.TrimEnd('.').ToLowerInvariant();
        var normalizedRpId = rpId.TrimEnd('.').ToLowerInvariant();
        if (host != normalizedRpId && !host.EndsWith($".{normalizedRpId}", StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException($"RP ID '{rpId}' is not valid for origin '{origin}'.");
        }
    }

    private static string GetEffectiveRpId(string? rpId, string origin)
    {
        if (!string.IsNullOrWhiteSpace(rpId))
        {
            return rpId;
        }

        if (!Uri.TryCreate(origin, UriKind.Absolute, out var originUri) ||
            string.IsNullOrWhiteSpace(originUri.IdnHost))
        {
            throw new UnauthorizedAccessException("Invalid origin.");
        }

        return originUri.IdnHost.TrimEnd('.').ToLowerInvariant();
    }

    private static bool IsLocalhost(string host)
    {
        return host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
               host.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase) ||
               host.Equals("::1", StringComparison.OrdinalIgnoreCase);
    }

    private static void AddCorsHeaders(HttpListenerResponse response)
    {
        response.Headers["Access-Control-Allow-Origin"] = "*";
        response.Headers["Access-Control-Allow-Headers"] = "content-type";
        response.Headers["Access-Control-Allow-Methods"] = "POST, OPTIONS";
    }

    private static async Task WriteHttpJsonAsync(HttpListenerResponse response, BridgeResponse payload)
    {
        response.ContentType = "application/json; charset=utf-8";
        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
        response.ContentLength64 = bytes.Length;
        await response.OutputStream.WriteAsync(bytes);
        response.Close();
    }

    private static async Task WriteNativeResponseAsync(Stream output, BridgeResponse response)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions);
        var lengthBuffer = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(lengthBuffer, (uint)payload.Length);
        await output.WriteAsync(lengthBuffer);
        await output.WriteAsync(payload);
        await output.FlushAsync();
    }

    private static async Task<bool> ReadExactlyOrEndAsync(Stream input, byte[] buffer)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await input.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset));
            if (read == 0)
            {
                return offset != 0
                    ? throw new EndOfStreamException("Native message ended mid-frame.")
                    : false;
            }

            offset += read;
        }

        return true;
    }
}

internal sealed class BridgeRequest
{
    public string? Id { get; set; }
    public required string Operation { get; set; }
    public required string Origin { get; set; }
    public required JsonElement PublicKey { get; set; }
}

internal sealed class BridgeResponse
{
    public string? Id { get; init; }
    public bool Ok { get; init; }
    public PublicKeyCredential? Credential { get; init; }
    public string? Error { get; init; }

    public static BridgeResponse Success(string? id, PublicKeyCredential credential)
    {
        return new BridgeResponse
        {
            Id = id,
            Ok = true,
            Credential = credential
        };
    }

    public static BridgeResponse Fail(string? id, string error)
    {
        return new BridgeResponse
        {
            Id = id,
            Ok = false,
            Error = error
        };
    }
}
