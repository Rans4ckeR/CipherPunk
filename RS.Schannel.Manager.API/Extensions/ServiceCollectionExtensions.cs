namespace RS.Schannel.Manager.API;

using Microsoft.Extensions.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSchannelApi(this IServiceCollection serviceCollection)
    {
        return serviceCollection
            .AddSingleton<ISchannelService, SchannelService>()
            .AddSingleton<IWindowsCipherSuiteDocumentationService, WindowsCipherSuiteDocumentationService>()
            .AddSingleton<IGroupPolicyService, GroupPolicyService>();
    }
}