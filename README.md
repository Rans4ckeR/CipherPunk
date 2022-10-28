# CipherPunk
Allows Windows Schannel CipherSuite and Elliptic Curve configuration.
Inspired by [IISCrypto](https://www.nartac.com/Products/IISCrypto/)

Features
* Supports SSL/TLS protocols from SSL2.0 to TLS1.3
* Remote server probing
* Cipher Suite configuration
* Elliptic Curve configuration
* Windows 7 to 11 & Windows Server 2008 R2 to 2022
* Configuration using local Group Policy (IISCrypto style)
* Configuration using Schannel API

Available as a standalone Windows application ([UI](#cipherpunkui)) and as a NuGet package ([API](#cipherpunk-1)).

Note: not all applications use Schannel, most browsers for example require seperate configuration.

## CipherPunk.UI
A Windows .NET WPF application for x86, x64 and ARM64.

* [Releases](https://github.com/Rans4ckeR/CipherPunk/releases)

## CipherPunk
A NuGet package to manage Windows Schannel.

* [NuGet](https://www.nuget.org/packages/CipherPunk)
* [GitHub](https://github.com/Rans4ckeR?tab=packages&repo_name=CipherPunk)

### Usage Examples

```C#
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using CipherPunk;

// Register the CipherPunk services in the dependency container using AddCipherPunk()
using IHost host = Host.CreateDefaultBuilder(args)
    .ConfigureServices((_, services) => services.AddCipherPunk())
    .Build();

using IServiceScope serviceScope = host.Services.CreateScope();
ICipherSuiteService cipherSuiteService = serviceScope.ServiceProvider.GetRequiredService<ICipherSuiteService>();
IEllipticCurveService ellipticCurveService = serviceScope.ServiceProvider.GetRequiredService<IEllipticCurveService>();

// Retrieve the currently active cipher suites ordered by priority
List<WindowsApiCipherSuiteConfiguration> cipherSuites = cipherSuiteService.GetOperatingSystemActiveCipherSuiteList();
cipherSuites.ForEach(q => Console.WriteLine(q.CipherSuiteName));

// Retrieve the currently active elliptic curves ordered by priority
List<WindowsApiEllipticCurveConfiguration> ellipticCurves = ellipticCurveService.GetOperatingSystemActiveEllipticCurveList();
ellipticCurves.ForEach(q => Console.WriteLine(q.pwszName));

// Retrieve the default cipher suites ordered by priority for the current OS
List<WindowsDocumentationCipherSuiteConfiguration> defaultCipherSuites = cipherSuiteService.GetOperatingSystemDocumentationDefaultCipherSuiteList();
defaultCipherSuites.ForEach(q => Console.WriteLine(q.CipherSuite));

// Retrieve the default elliptic curves ordered by priority for the current OS
List<WindowsDocumentationEllipticCurveConfiguration> defaultEllipticCurves = ellipticCurveService.GetOperatingSystemDefaultEllipticCurveList();
defaultEllipticCurves.ForEach(q => Console.WriteLine(q.Name));

// Add a cipher suite
cipherSuiteService.AddCipherSuite("TLS_AES_256_GCM_SHA384");

await host.RunAsync();
```
