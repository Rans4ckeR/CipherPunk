﻿using System.Collections.Frozen;

namespace CipherPunk;

internal sealed class WindowsDocumentationService(IWindowsEllipticCurveDocumentationService windowsEllipticCurveDocumentationService) : IWindowsDocumentationService
{
    private readonly IWindowsEllipticCurveDocumentationService windowsEllipticCurveDocumentationService = windowsEllipticCurveDocumentationService;

    private FrozenSet<BaseWindowsDocumentationService>? windowsDocumentationServices;
    private FrozenDictionary<WindowsVersion, FrozenSet<SchannelProtocolSettings>>? windowsDocumentationProtocolConfigurations;
    private FrozenDictionary<WindowsVersion, FrozenSet<WindowsDocumentationCipherSuiteConfiguration>>? windowsDocumentationCipherSuiteConfigurations;
    private FrozenDictionary<WindowsVersion, FrozenSet<WindowsDocumentationEllipticCurveConfiguration>>? windowsDocumentationEllipticCurveConfigurations;

    public FrozenDictionary<WindowsVersion, FrozenSet<SchannelProtocolSettings>> GetProtocolConfigurations()
        => windowsDocumentationProtocolConfigurations ??= GetWindowsDocumentationServices().Select(static q => q.GetProtocolConfiguration()).ToFrozenDictionary();

    public FrozenSet<SchannelProtocolSettings> GetProtocolConfigurations(WindowsVersion windowsVersion)
        => GetProtocolConfigurations().Where(q => q.Key <= windowsVersion).MaxBy(static q => q.Key).Value;

    public FrozenDictionary<WindowsVersion, FrozenSet<WindowsDocumentationCipherSuiteConfiguration>> GetCipherSuiteConfigurations()
        => windowsDocumentationCipherSuiteConfigurations ??= GetWindowsDocumentationServices().Select(static q => q.GetCipherSuiteConfiguration()).ToFrozenDictionary();

    public FrozenSet<WindowsDocumentationCipherSuiteConfiguration> GetCipherSuiteConfigurations(WindowsVersion windowsVersion)
        => GetCipherSuiteConfigurations().Where(q => q.Key <= windowsVersion).MaxBy(static q => q.Key).Value;

    public FrozenDictionary<WindowsVersion, FrozenSet<WindowsDocumentationEllipticCurveConfiguration>> GetEllipticCurveConfigurations()
        => windowsDocumentationEllipticCurveConfigurations ??= GetWindowsDocumentationServices().Select(static q => q.GetEllipticCurveConfiguration()).ToFrozenDictionary();

    public FrozenSet<WindowsDocumentationEllipticCurveConfiguration> GetEllipticCurveConfigurations(WindowsVersion windowsVersion)
        => GetEllipticCurveConfigurations().Where(q => q.Key <= windowsVersion).MaxBy(static q => q.Key).Value;

    private FrozenSet<BaseWindowsDocumentationService> GetWindowsDocumentationServices() => windowsDocumentationServices ??= BuildWindowsDocumentationServices();

    private FrozenSet<BaseWindowsDocumentationService> BuildWindowsDocumentationServices() =>
    [
        new Windows11V22H2DocumentationService(windowsEllipticCurveDocumentationService),
        new Windows11V21H2DocumentationService(windowsEllipticCurveDocumentationService),
        new WindowsServer2022DocumentationService(windowsEllipticCurveDocumentationService),
        new Windows10V22H2DocumentationService(windowsEllipticCurveDocumentationService),
        new Windows10V1903DocumentationService(windowsEllipticCurveDocumentationService),
        new Windows10V1709DocumentationService(windowsEllipticCurveDocumentationService),
        new Windows10V1703DocumentationService(windowsEllipticCurveDocumentationService),
        new Windows10V1607DocumentationService(windowsEllipticCurveDocumentationService),
        new Windows10V1511DocumentationService(windowsEllipticCurveDocumentationService),
        new Windows10V1507DocumentationService(windowsEllipticCurveDocumentationService),
        new Windows81DocumentationService(windowsEllipticCurveDocumentationService),
        new Windows8DocumentationService(windowsEllipticCurveDocumentationService),
        new Windows7DocumentationService(windowsEllipticCurveDocumentationService),
        new WindowsVistaDocumentationService(windowsEllipticCurveDocumentationService)
    ];
}