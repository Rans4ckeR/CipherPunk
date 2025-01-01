using System.Net;
using Microsoft.Extensions.DependencyInjection;

namespace CipherPunk.CipherSuiteInfoApi;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the services for the https://ciphersuite.info API to the specified <see cref="IServiceCollection"/>.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the service to.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public static IServiceCollection AddCipherSuiteInfoApi(this IServiceCollection services)
    {
        _ = services
            .AddSingleton<ICipherSuiteInfoApiService, CipherSuiteInfoApiService>()
            .AddHttpClient(ICipherSuiteInfoApiService.HttpClientName)
            .ConfigureHttpClient(static (_, httpClient) =>
            {
                httpClient.BaseAddress = new(FormattableString.Invariant($"{Uri.UriSchemeHttps}{Uri.SchemeDelimiter}ciphersuite.info/api/"));
                httpClient.Timeout = TimeSpan.FromSeconds(10);
                httpClient.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrHigher;
            })
            .ConfigurePrimaryHttpMessageHandler(static _ => new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.All
            });

        return services;
    }
}