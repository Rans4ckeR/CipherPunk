namespace RS.Schannel.Manager.CipherSuiteInfoApi;

using System.Net;
using Microsoft.Extensions.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddCipherSuiteInfoApi(this IServiceCollection serviceCollection)
    {
        _ = serviceCollection
            .AddSingleton<ICipherSuiteInfoApiService, CipherSuiteInfoApiService>()
            .AddHttpClient(ICipherSuiteInfoApiService.HttpClientName)
            .ConfigureHttpClient((_, httpClient) =>
            {
                httpClient.BaseAddress = new("https://ciphersuite.info/api/");
                httpClient.Timeout = TimeSpan.FromSeconds(10);
                httpClient.DefaultRequestVersion = Version.Parse("2.0");
            })
            .ConfigurePrimaryHttpMessageHandler(_ => new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.All
            });

        return serviceCollection;
    }
}