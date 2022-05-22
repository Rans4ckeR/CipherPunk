namespace RS.Schannel.Manager.API;

using Microsoft.Extensions.DependencyInjection;
using RS.Schannel.Manager.CipherSuiteInfoApi;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSchannelApi(this IServiceCollection serviceCollection)
    {
        return serviceCollection.AddSingleton<ISchannelService, SchannelService>()
            .AddCipherSuiteInfoApiHttpClient();
    }
}