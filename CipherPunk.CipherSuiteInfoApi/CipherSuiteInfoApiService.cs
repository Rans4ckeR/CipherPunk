using System.Collections.Frozen;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace CipherPunk.CipherSuiteInfoApi;

internal sealed class CipherSuiteInfoApiService(IHttpClientFactory httpClientFactory)
    : ICipherSuiteInfoApiService
{
    private static readonly JsonSerializerOptions JsonSerializerOptions = new()
    {
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly IHttpClientFactory httpClientFactory = httpClientFactory;

    private FrozenDictionary<string, CipherSuite> cipherSuites = FrozenDictionary<string, CipherSuite>.Empty;

    public async ValueTask<CipherSuite?> GetCipherSuiteAsync(string cipherSuiteName, bool useCache = true, CancellationToken cancellationToken = default)
    {
        if (useCache && cipherSuites.Count is 0)
            cipherSuites = await GetAllCipherSuitesAsync(useCache, cancellationToken);

        if (useCache && cipherSuites.TryGetValue(cipherSuiteName, out CipherSuite cipherSuite))
            return cipherSuite;

        string cipherSuiteResponseJson;

        try
        {
            cipherSuiteResponseJson = await httpClientFactory.CreateClient(ICipherSuiteInfoApiService.HttpClientName).GetStringAsync(FormattableString.Invariant($"cs/{cipherSuiteName}"), cancellationToken);
        }
        catch (HttpRequestException e) when (e.StatusCode is HttpStatusCode.NotFound)
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

        return await JsonSerializer.DeserializeAsync<CipherSuite>(stream, JsonSerializerOptions, cancellationToken);
    }

    public async ValueTask<FrozenDictionary<string, CipherSuite>> GetAllCipherSuitesAsync(bool useCache = true, CancellationToken cancellationToken = default)
    {
        if (cipherSuites.Count is not 0 && useCache)
            return cipherSuites;

        string cipherSuiteResponseJson = await httpClientFactory.CreateClient(ICipherSuiteInfoApiService.HttpClientName).GetStringAsync("cs", cancellationToken);
        var cipherSuitesResponseNode = JsonNode.Parse(cipherSuiteResponseJson);
        JsonArray cipherSuiteObjectsArray = cipherSuitesResponseNode!["ciphersuites"]!.AsArray();
        var resultArray = new JsonArray();

        foreach (KeyValuePair<string, JsonNode?> cipherSuiteObject in cipherSuiteObjectsArray.SelectMany(static q => q!.AsObject()))
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

        cipherSuites = (await JsonSerializer.DeserializeAsync<IEnumerable<CipherSuite>>(stream, JsonSerializerOptions, cancellationToken))!.ToFrozenDictionary(static q => q.IanaName);

        return cipherSuites;
    }
}