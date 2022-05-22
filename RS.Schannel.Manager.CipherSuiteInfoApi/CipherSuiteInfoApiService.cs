namespace RS.Schannel.Manager.CipherSuiteInfoApi;

using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

internal sealed class CipherSuiteInfoApiService : ICipherSuiteInfoApiService
{
    private readonly IHttpClientFactory httpClientFactory;

    public CipherSuiteInfoApiService(IHttpClientFactory httpClientFactory)
    {
        this.httpClientFactory = httpClientFactory;
    }

    public async Task<Ciphersuite> GetCipherSuite(string cipherSuiteName, CancellationToken cancellationToken)
    {
        string cipherSuiteResponseJson = await httpClientFactory.CreateClient(ICipherSuiteInfoApiService.HttpClientName).GetStringAsync(FormattableString.Invariant($"cs/{cipherSuiteName}"), cancellationToken);
        var cipherSuiteResponseNode = JsonNode.Parse(cipherSuiteResponseJson);
        JsonObject cipherSuiteObject = cipherSuiteResponseNode![cipherSuiteName]!.AsObject();
        JsonArray tlsVersions = cipherSuiteObject["tls_version"]!.AsArray();
        var newTlsVersions = new JsonArray();

        foreach (JsonNode? tlsVersion in tlsVersions)
        {
            newTlsVersions.Add(JsonNode.Parse(tlsVersion!.ToJsonString().Replace('.', '_')));
        }

        cipherSuiteObject["tls_version"] = newTlsVersions;

        using var stream = new MemoryStream();
        await using var writer = new Utf8JsonWriter(stream);

        cipherSuiteObject.WriteTo(writer);
        await writer.FlushAsync(cancellationToken);

        stream.Position = 0L;

        var options = new JsonSerializerOptions
        {
            Converters = { new JsonStringEnumConverter() }
        };

        return await JsonSerializer.DeserializeAsync<Ciphersuite>(stream, options, cancellationToken);
    }
}