namespace CipherPunk.CipherSuiteInfoApi;

using System.Net;
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

    public async ValueTask<CipherSuite?> GetCipherSuiteAsync(string cipherSuiteName, CancellationToken cancellationToken = default)
    {
        string cipherSuiteResponseJson;

        try
        {
            cipherSuiteResponseJson = await httpClientFactory.CreateClient(ICipherSuiteInfoApiService.HttpClientName).GetStringAsync(FormattableString.Invariant($"cs/{cipherSuiteName}"), cancellationToken);
        }
        catch (HttpRequestException e) when (e.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        var cipherSuiteResponseNode = JsonNode.Parse(cipherSuiteResponseJson);
        JsonObject cipherSuiteObject = cipherSuiteResponseNode![cipherSuiteName]!.AsObject();
        JsonArray tlsVersions = cipherSuiteObject["tls_version"]!.AsArray();
        var newTlsVersions = new JsonArray();

        foreach (JsonNode? tlsVersion in tlsVersions)
        {
            newTlsVersions.Add(JsonNode.Parse(tlsVersion!.ToJsonString().Replace('.', '_')));
        }

        cipherSuiteObject["tls_version"] = newTlsVersions;

        cipherSuiteObject.Add("iana_name", cipherSuiteName);

        using var stream = new MemoryStream();
        await using var writer = new Utf8JsonWriter(stream);

        cipherSuiteObject.WriteTo(writer);
        await writer.FlushAsync(cancellationToken);

        stream.Position = 0L;

        var options = new JsonSerializerOptions
        {
            Converters = { new JsonStringEnumConverter() }
        };

        return await JsonSerializer.DeserializeAsync<CipherSuite>(stream, options, cancellationToken);
    }

    public async ValueTask<CipherSuite[]> GetAllCipherSuitesAsync(CancellationToken cancellationToken = default)
    {
        string cipherSuiteResponseJson = await httpClientFactory.CreateClient(ICipherSuiteInfoApiService.HttpClientName).GetStringAsync("cs", cancellationToken);
        var cipherSuitesResponseNode = JsonNode.Parse(cipherSuiteResponseJson);
        JsonArray cipherSuiteObjectsArray = cipherSuitesResponseNode!["ciphersuites"]!.AsArray();
        var resultArray = new JsonArray();

        foreach (KeyValuePair<string, JsonNode?> cipherSuiteObject in cipherSuiteObjectsArray.SelectMany(q => q!.AsObject()))
        {
            JsonArray tlsVersions = cipherSuiteObject.Value!["tls_version"]!.AsArray();
            var newTlsVersions = new JsonArray();

            foreach (JsonNode? tlsVersion in tlsVersions)
            {
                newTlsVersions.Add(JsonNode.Parse(tlsVersion!.ToJsonString().Replace('.', '_')));
            }

            cipherSuiteObject.Value["tls_version"] = newTlsVersions;

            var resultNode = JsonNode.Parse(cipherSuiteObject.Value.ToJsonString());

            resultNode!.AsObject().Add("iana_name", cipherSuiteObject.Key);

            resultArray.Add(resultNode);
        }

        using var stream = new MemoryStream();
        await using var writer = new Utf8JsonWriter(stream);

        resultArray.WriteTo(writer);
        await writer.FlushAsync(cancellationToken);

        stream.Position = 0L;

        var options = new JsonSerializerOptions
        {
            Converters = { new JsonStringEnumConverter() }
        };

        return (await JsonSerializer.DeserializeAsync<CipherSuite[]>(stream, options, cancellationToken))!;
    }
}