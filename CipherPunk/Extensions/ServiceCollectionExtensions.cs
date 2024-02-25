namespace CipherPunk;

using Microsoft.Extensions.DependencyInjection;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the CipherPunk services to the specified <see cref="IServiceCollection"/>.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the service to.</param>
    /// <returns>A reference to this instance after the operation has completed.</returns>
    public static IServiceCollection AddCipherPunk(this IServiceCollection services)
        => services
            .AddSingleton<ICipherSuiteService, CipherSuiteService>()
            .AddSingleton<IWindowsDocumentationService, WindowsDocumentationService>()
            .AddSingleton<IWindowsEllipticCurveDocumentationService, WindowsEllipticCurveDocumentationService>()
            .AddSingleton<IGroupPolicyService, GroupPolicyService>()
            .AddSingleton<IEllipticCurveIdentifierService, EllipticCurveIdentifierService>()
            .AddSingleton<IEllipticCurveService, EllipticCurveService>()
            .AddSingleton<ITlsService, TlsService>()
            .AddSingleton<ISchannelService, SchannelService>()
            .AddSingleton<ISchannelLogService, SchannelLogService>()
            .AddSingleton<IWindowsVersionService, WindowsVersionService>();
}