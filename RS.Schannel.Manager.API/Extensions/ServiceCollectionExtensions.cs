﻿namespace RS.Schannel.Manager.API;

using Microsoft.Extensions.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSchannelApi(this IServiceCollection serviceCollection)
    {
        return serviceCollection
            .AddSingleton<ICipherSuiteService, CipherSuiteService>()
            .AddSingleton<IWindowsCipherSuiteDocumentationService, WindowsCipherSuiteDocumentationService>()
            .AddSingleton<IWindowsEllipticCurveDocumentationService, WindowsEllipticCurveDocumentationService>()
            .AddSingleton<IGroupPolicyService, GroupPolicyService>()
            .AddSingleton<IEllipticCurveIdentifierService, EllipticCurveIdentifierService>()
            .AddSingleton<IEllipticCurveService, EllipticCurveService>()
            .AddSingleton<ITlsService, TlsService>();
    }
}