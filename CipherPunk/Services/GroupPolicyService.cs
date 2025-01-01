using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Win32.SafeHandles;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Com;
using Windows.Win32.System.GroupPolicy;
using Windows.Win32.System.Registry;

namespace CipherPunk;

internal sealed class GroupPolicyService : IGroupPolicyService
{
    private const string MicrosoftPoliciesCipherStrengthPolicyDefinitionResourcesFileXmlNamespace = "http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions";
    private const string SslConfigurationPolicyKey = @"SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002";
    private const string SslCipherSuiteOrderValueName = "Functions";
    private const string SslCurveOrderValueName = "EccCurves";
    private const ushort ListMaximumCharacters = 1023;

    private static readonly Guid CipherPunkGuid = new(0x929aa20, 0xaa5d, 0x4fd5, 0x83, 0x10, 0x85, 0x7a, 0x10, 0xf2, 0x45, 0xa9);
    private static readonly CompositeFormat MicrosoftPoliciesCipherStrengthPolicyDefinitionResourcesFile = CompositeFormat.Parse(@"{0}\PolicyDefinitions\{1}\CipherSuiteOrder.adml");

    [SupportedOSPlatform("windows")]
    public async ValueTask<string[]> GetSslCipherSuiteOrderPolicyWindowsDefaultsAsync(CancellationToken cancellationToken = default)
    {
        string windowsFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string microsoftPoliciesCipherStrengthPolicyDefinitionResourcesFile = string.Format(CultureInfo.InvariantCulture, MicrosoftPoliciesCipherStrengthPolicyDefinitionResourcesFile, windowsFolder, CultureInfo.CurrentUICulture);
        await using FileStream stream = new FileInfo(microsoftPoliciesCipherStrengthPolicyDefinitionResourcesFile).Open(new FileStreamOptions { Access = FileAccess.Read, Mode = FileMode.Open, Options = FileOptions.Asynchronous });
        using var xmlReader = XmlReader.Create(stream, new() { Async = true });
        XDocument xDocument = await XDocument.LoadAsync(xmlReader, LoadOptions.SetBaseUri, cancellationToken);
        XNamespace ns = MicrosoftPoliciesCipherStrengthPolicyDefinitionResourcesFileXmlNamespace;
        string sslCipherSuiteOrderPolicyWindowsDefaults = xDocument
            .Elements(ns + "policyDefinitionResources").Single()
            .Elements(ns + "resources").Single()
            .Elements(ns + "presentationTable").Single()
            .Elements(ns + "presentation").Single(static q => "SSLCipherSuiteOrder".Equals(q.Attribute("id")!.Value, StringComparison.OrdinalIgnoreCase))
            .Elements(ns + "textBox").Single(static q => "Pol_SSLCipherSuiteOrder".Equals(q.Attribute("refId")!.Value, StringComparison.OrdinalIgnoreCase))
            .Elements(ns + "defaultValue").Single().Value;

        return sslCipherSuiteOrderPolicyWindowsDefaults.Split(',');
    }

    [SupportedOSPlatform("windows")]
    public async ValueTask<string[]> GetSslCurveOrderPolicyWindowsDefaultsAsync(CancellationToken cancellationToken = default)
    {
        string windowsFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string microsoftPoliciesCipherStrengthPolicyDefinitionResourcesFile = string.Format(CultureInfo.InvariantCulture, MicrosoftPoliciesCipherStrengthPolicyDefinitionResourcesFile, windowsFolder, CultureInfo.CurrentUICulture);
        await using FileStream stream = new FileInfo(microsoftPoliciesCipherStrengthPolicyDefinitionResourcesFile).Open(new FileStreamOptions { Access = FileAccess.Read, Mode = FileMode.Open, Options = FileOptions.Asynchronous });
        using var xmlReader = XmlReader.Create(stream, new() { Async = true });
        XDocument xDocument = await XDocument.LoadAsync(xmlReader, LoadOptions.SetBaseUri, cancellationToken);
        XNamespace ns = MicrosoftPoliciesCipherStrengthPolicyDefinitionResourcesFileXmlNamespace;
        string sslCurveOrderPolicyHelpText = xDocument
            .Elements(ns + "policyDefinitionResources").Single()
            .Elements(ns + "resources").Single()
            .Elements(ns + "stringTable").Single()
            .Elements(ns + "string").Single(static q => "SSLCurveOrder_Help".Equals(q.Attribute("id")!.Value, StringComparison.OrdinalIgnoreCase)).Value;
        int sslCurveOrderStartIndex = sslCurveOrderPolicyHelpText.IndexOf("============\n", StringComparison.OrdinalIgnoreCase) + "============\n".Length;
        string sslCurveOrderData = sslCurveOrderPolicyHelpText[sslCurveOrderStartIndex..];

        sslCurveOrderData = sslCurveOrderData[..sslCurveOrderData.IndexOf("\n\n", StringComparison.OrdinalIgnoreCase)].Replace('\n', ',');

        return sslCurveOrderData.Split(',');
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public void UpdateSslCipherSuiteOrderPolicy(IEnumerable<string> cipherSuites)
    {
        string cipherSuitesString = FormattableString.Invariant($"{string.Join(',', cipherSuites)}\0");

        UpdateOrderPolicy(cipherSuitesString, SslCipherSuiteOrderValueName, REG_VALUE_TYPE.REG_SZ);
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public void UpdateEccCurveOrderPolicy(IEnumerable<string> ellipticCurves)
    {
        string ellipticCurvesString = FormattableString.Invariant($"{string.Join('\0', ellipticCurves)}\0\0");

        UpdateOrderPolicy(ellipticCurvesString, SslCurveOrderValueName, REG_VALUE_TYPE.REG_MULTI_SZ);
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public string[] GetSslCipherSuiteOrderPolicy() => GetOrderPolicy(SslCipherSuiteOrderValueName, REG_ROUTINE_FLAGS.RRF_RT_REG_SZ)?[..^"\0".Length]?.Split(',') ?? [];

    [SupportedOSPlatform("windows6.0.6000")]
    public string[] GetEccCurveOrderPolicy() => GetOrderPolicy(SslCurveOrderValueName, REG_ROUTINE_FLAGS.RRF_RT_REG_MULTI_SZ)?.Split('\0', StringSplitOptions.RemoveEmptyEntries) ?? [];

    [SupportedOSPlatform("windows6.0.6000")]
    private static void UpdateOrderPolicy(string valueData, string valueName, REG_VALUE_TYPE valueType)
    {
        if (valueData.Length > ListMaximumCharacters)
            throw new GroupPolicyServiceException(FormattableString.Invariant($"Maximum list length exceeded ({valueData.Length}), the maximum is {ListMaximumCharacters}."));

        try
        {
            HRESULT coInitializeExResult = PInvoke.CoInitializeEx(COINIT.COINIT_APARTMENTTHREADED);

            if (coInitializeExResult.Failed)
                throw new Win32Exception(coInitializeExResult);

            HRESULT coCreateInstanceResult = PInvoke.CoCreateInstance(PInvoke.CLSID_GroupPolicyObject, null, CLSCTX.CLSCTX_INPROC_SERVER, out IGroupPolicyObject ppv);

            if (coCreateInstanceResult.Failed)
                throw new Win32Exception(coCreateInstanceResult);

            ppv.OpenLocalMachineGPO(GPO_OPEN_FLAGS.GPO_OPEN_LOAD_REGISTRY);

            HKEY machineKey = default;

            ppv.GetRegistryKey(GPO_SECTION.GPO_SECTION_MACHINE, ref machineKey);

            using var hKey = new SafeRegistryHandle(machineKey, true);

            unsafe
            {
                WIN32_ERROR regCreateKeyExResult = PInvoke.RegCreateKeyEx(hKey, SslConfigurationPolicyKey, null, REG_OPEN_CREATE_OPTIONS.REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS.KEY_SET_VALUE | REG_SAM_FLAGS.KEY_QUERY_VALUE, null, out SafeRegistryHandle phkResult, null);

                using (phkResult)
                {
                    if (regCreateKeyExResult is not WIN32_ERROR.ERROR_SUCCESS)
                        throw new Win32Exception((int)regCreateKeyExResult);

                    if (!string.IsNullOrWhiteSpace(valueData.Replace("\0", null, StringComparison.OrdinalIgnoreCase)))
                    {
                        fixed (char* lpData = valueData)
                        {
                            WIN32_ERROR regSetKeyValueResult = PInvoke.RegSetKeyValue(phkResult, null, valueName, (uint)valueType, lpData, (uint)(sizeof(char) * valueData.Length));

                            if (regSetKeyValueResult is not WIN32_ERROR.ERROR_SUCCESS)
                                throw new Win32Exception((int)regSetKeyValueResult);
                        }
                    }
                    else
                    {
                        WIN32_ERROR regDeleteValueResult = PInvoke.RegDeleteValue(phkResult, valueName);

                        if (regDeleteValueResult is not WIN32_ERROR.ERROR_SUCCESS and not WIN32_ERROR.ERROR_FILE_NOT_FOUND)
                            throw new Win32Exception((int)regDeleteValueResult);
                    }
                }
            }

            const bool isComputerPolicySettings = true;
            const bool isAddOperation = true;

            ppv.Save(isComputerPolicySettings, isAddOperation, PInvoke.REGISTRY_EXTENSION_GUID, CipherPunkGuid);
        }
        finally
        {
            PInvoke.CoUninitialize();
        }
    }

    [SupportedOSPlatform("windows6.0.6000")]
    private static string? GetOrderPolicy(string valueName, REG_ROUTINE_FLAGS valueType)
    {
        try
        {
            HRESULT coInitializeExResult = PInvoke.CoInitializeEx(COINIT.COINIT_APARTMENTTHREADED);

            if (coInitializeExResult.Failed)
                throw new Win32Exception(coInitializeExResult);

            HRESULT coCreateInstanceResult = PInvoke.CoCreateInstance(PInvoke.CLSID_GroupPolicyObject, null, CLSCTX.CLSCTX_INPROC_SERVER, out IGroupPolicyObject ppv);

            if (coCreateInstanceResult.Failed)
                throw new Win32Exception(coCreateInstanceResult);

            ppv.OpenLocalMachineGPO(GPO_OPEN_FLAGS.GPO_OPEN_LOAD_REGISTRY);

            HKEY machineKey = default;

            ppv.GetRegistryKey(GPO_SECTION.GPO_SECTION_MACHINE, ref machineKey);

            using var hKey = new SafeRegistryHandle(machineKey, true);
            WIN32_ERROR regOpenKeyExResult = PInvoke.RegOpenKeyEx(hKey, SslConfigurationPolicyKey, 0U, REG_SAM_FLAGS.KEY_QUERY_VALUE, out SafeRegistryHandle phkResult);
            uint pcbData;
            char[] buffer;
            WIN32_ERROR regGetValueResult;

            using (phkResult)
            {
                if (regOpenKeyExResult is WIN32_ERROR.ERROR_FILE_NOT_FOUND)
                    return null;

                if (regOpenKeyExResult is not WIN32_ERROR.ERROR_SUCCESS)
                    throw new Win32Exception((int)regOpenKeyExResult);

                pcbData = ListMaximumCharacters * sizeof(char);
                buffer = new char[pcbData];

                unsafe
                {
                    fixed (char* pvData = buffer)
                    {
                        regGetValueResult = PInvoke.RegGetValue(phkResult, null, valueName, valueType, null, pvData, &pcbData);
                    }
                }
            }

            return regGetValueResult switch
            {
                WIN32_ERROR.ERROR_FILE_NOT_FOUND => null,
                not WIN32_ERROR.ERROR_SUCCESS => throw new Win32Exception((int)regGetValueResult),
                _ => new(buffer[..(int)(pcbData / sizeof(char))])
            };
        }
        finally
        {
            PInvoke.CoUninitialize();
        }
    }
}