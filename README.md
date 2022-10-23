# CipherPunk
Allows Windows Schannel CipherSuite and Elliptic Curve configuration.
Inspired by [IISCrypto](https://www.nartac.com/Products/IISCrypto/)

Supporting
* All protocols including TLS1.3
* Cipher Suite configuration
* Elliptic Curve configuration
* Windows 7 to 11 & Windows Server 2008 R2 to 2022
* Configuration using local Group Policy (IISCrypto style)
* Configuration using Schannel API

Available as a standalone Windows application ([UI](#rsschannelmanagerui)) and as a NuGet package ([API](#rsschannelmanagerapi)).

Note: not all applications use Schannel, most browsers for example require seperate configuration.

## CipherPunk.UI
A Windows .NET WPF application for x86, x64 and ARM64.

* [Releases](https://github.com/Rans4ckeR/RS.Schannel.Manager/releases)

## CipherPunk
A NuGet package to manage Windows Schannel.

* [NuGet](https://www.nuget.org/packages/CipherPunk)
* [GitHub](https://github.com/Rans4ckeR?tab=packages&repo_name=RS.Schannel.Manager)

### Usage Examples

```C#
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using CipherPunk;

// Register the Schannel services in the dependency container using AddCipherPunk()
using IHost host = Host.CreateDefaultBuilder(args)
    .ConfigureServices((_, services) => services.AddCipherPunk())
    .Build();

using IServiceScope serviceScope = host.Services.CreateScope();
ISchannelService schannelService = serviceScope.ServiceProvider.GetRequiredService<ISchannelService>();

// Retrieve the currently active cipher suites ordered by priority
List<WindowsApiCipherSuiteConfiguration> cipherSuites = schannelService.GetOperatingSystemActiveCipherSuiteList();
cipherSuites.ForEach(q => Console.WriteLine(q.CipherSuiteName));

// Retrieve the currently active elliptic curves ordered by priority
List<string> ellipticCurves = schannelService.GetOperatingSystemActiveEllipticCurveList();
ellipticCurves.ForEach(Console.WriteLine);

// Retrieve the default cipher suites ordered by priority for the current OS
cipherSuites = schannelService.GetOperatingSystemDefaultCipherSuiteList();
cipherSuites.ForEach(q => Console.WriteLine(q.CipherSuiteName));

// Retrieve the default elliptic curves ordered by priority for the current OS
List<WindowsDocumentationEllipticCurveConfiguration> defaultEllipticCurves = schannelService.GetOperatingSystemDefaultEllipticCurveList();
defaultEllipticCurves.ForEach(q => Console.WriteLine(q.EllipticCurveString));

// Add a cipher suite
schannelService.AddCipherSuite("TLS_AES_256_GCM_SHA384");

await host.RunAsync();
```