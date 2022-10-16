namespace RS.Schannel.Manager.API;

using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Win32.SafeHandles;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Com;
using Windows.Win32.System.Registry;
using Windows.Win32.System.GroupPolicy;

internal sealed class GroupPolicyService : IGroupPolicyService
{
    private const string MicrosoftPoliciesCipherStrengthPolicyDefinitionResourcesFile = "{0}\\PolicyDefinitions\\en-US\\CipherSuiteOrder.adml";
    private const string MicrosoftPoliciesCipherStrengthPolicyDefinitionResourcesFileXmlNamespace = "http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions";
    private const string SslConfigurationPolicyKey = "SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002";
    private const string SslCipherSuiteOrderValueName = "Functions";
    private const string SslCurveOrderValueName = "EccCurves";
    private const ushort ListMaximumCharacters = 1023;

    private readonly Guid rsSchannelManagerGuid = new(0x929aa20, 0xaa5d, 0x4fd5, 0x83, 0x10, 0x85, 0x7a, 0x10, 0xf2, 0x45, 0xa9);

    [SupportedOSPlatform("windows")]
    public async Task<string> GetSslCipherSuiteOrderPolicyWindowsDefaultsAsync(CancellationToken cancellationToken = default)
    {
        string windowsFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string microsoftPoliciesCypherStrengthPolicyDefinitionResourcesFile = string.Format(CultureInfo.InvariantCulture, MicrosoftPoliciesCipherStrengthPolicyDefinitionResourcesFile, windowsFolder);
        await using FileStream stream = new FileInfo(microsoftPoliciesCypherStrengthPolicyDefinitionResourcesFile).Open(new FileStreamOptions { Access = FileAccess.Read, Mode = FileMode.Open, Options = FileOptions.Asynchronous });
        using var xmlReader = XmlReader.Create(stream, new() { Async = true });
        XDocument xDocument = await XDocument.LoadAsync(xmlReader, LoadOptions.SetBaseUri, cancellationToken);
        XNamespace ns = MicrosoftPoliciesCipherStrengthPolicyDefinitionResourcesFileXmlNamespace;
        string sslCipherSuiteOrderPolicyWindowsDefaults = xDocument
            .Elements(ns + "policyDefinitionResources").Single()
            .Elements(ns + "resources").Single()
            .Elements(ns + "presentationTable").Single()
            .Elements(ns + "presentation").Single(q => "SSLCipherSuiteOrder".Equals(q.Attribute("id")!.Value, StringComparison.OrdinalIgnoreCase))
            .Elements(ns + "textBox").Single(q => "Pol_SSLCipherSuiteOrder".Equals(q.Attribute("refId")!.Value, StringComparison.OrdinalIgnoreCase))
            .Elements(ns + "defaultValue").Single().Value;

        return sslCipherSuiteOrderPolicyWindowsDefaults;
    }

    [SupportedOSPlatform("windows")]
    public async Task<string> GetSslCurveOrderPolicyWindowsDefaultsAsync(CancellationToken cancellationToken = default)
    {
        string windowsFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string microsoftPoliciesCypherStrengthPolicyDefinitionResourcesFile = string.Format(CultureInfo.InvariantCulture, MicrosoftPoliciesCipherStrengthPolicyDefinitionResourcesFile, windowsFolder);
        await using FileStream stream = new FileInfo(microsoftPoliciesCypherStrengthPolicyDefinitionResourcesFile).Open(new FileStreamOptions { Access = FileAccess.Read, Mode = FileMode.Open, Options = FileOptions.Asynchronous });
        using var xmlReader = XmlReader.Create(stream, new() { Async = true });
        XDocument xDocument = await XDocument.LoadAsync(xmlReader, LoadOptions.SetBaseUri, cancellationToken);
        XNamespace ns = MicrosoftPoliciesCipherStrengthPolicyDefinitionResourcesFileXmlNamespace;
        string sslCurveOrderPolicyHelpText = xDocument
            .Elements(ns + "policyDefinitionResources").Single()
            .Elements(ns + "resources").Single()
            .Elements(ns + "stringTable").Single()
            .Elements(ns + "string").Single(q => "SSLCurveOrder_Help".Equals(q.Attribute("id")!.Value, StringComparison.OrdinalIgnoreCase)).Value;
        int sslCurveOrderStartIndex = sslCurveOrderPolicyHelpText.IndexOf("============\n", StringComparison.OrdinalIgnoreCase) + "============\n".Length;
        string sslCurveOrderData = sslCurveOrderPolicyHelpText[sslCurveOrderStartIndex..];

        sslCurveOrderData = sslCurveOrderData[..sslCurveOrderData.IndexOf("\n\n", StringComparison.OrdinalIgnoreCase)].Replace('\n', ',');

        return sslCurveOrderData;
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public void UpdateSslCipherSuiteOrderPolicy(string[] cipherSuites)
    {
        string cipherSuitesString = string.Join(',', cipherSuites);

        UpdateOrderPolicy(cipherSuitesString, SslCipherSuiteOrderValueName, REG_VALUE_TYPE.REG_SZ);
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public void UpdateEccCurveOrderPolicy(string[] ellipticCurves)
    {
        string ellipticCurvesString = string.Join('\n', ellipticCurves);

        UpdateOrderPolicy(ellipticCurvesString, SslCurveOrderValueName, REG_VALUE_TYPE.REG_MULTI_SZ);
    }

    [SupportedOSPlatform("windows6.0.6000")]
    private void UpdateOrderPolicy(string valueData, string valueName, REG_VALUE_TYPE valueType)
    {
        if (valueData.Length > ListMaximumCharacters)
            throw new GroupPolicyServiceException(FormattableString.Invariant($"Maximum list length exceeded ({valueData.Length}), the maximum is {ListMaximumCharacters}."));

        unsafe
        {
            try
            {
                HRESULT coInitializeExResult = PInvoke.CoInitializeEx(null, COINIT.COINIT_APARTMENTTHREADED);

                if (coInitializeExResult.Failed)
                    throw Marshal.GetExceptionForHR(coInitializeExResult)!;

                HRESULT coCreateInstanceResult = PInvoke.CoCreateInstance(PInvoke.CLSID_GroupPolicyObject, null, CLSCTX.CLSCTX_INPROC_SERVER, out IGroupPolicyObject ppv);

                if (coCreateInstanceResult.Failed)
                    throw Marshal.GetExceptionForHR(coCreateInstanceResult)!;

                ppv.OpenLocalMachineGPO((uint)GPO_OPEN.GPO_OPEN_LOAD_REGISTRY);

                HKEY machineKey = default;

                ppv.GetRegistryKey((uint)GPO_SECTION.GPO_SECTION_MACHINE, ref machineKey);

                using var hKey = new SafeRegistryHandle(machineKey, true);
                WIN32_ERROR regCreateKeyExResult = PInvoke.RegCreateKeyEx(hKey, SslConfigurationPolicyKey, 0U, null, REG_OPEN_CREATE_OPTIONS.REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS.KEY_SET_VALUE | REG_SAM_FLAGS.KEY_QUERY_VALUE, null, out SafeRegistryHandle phkResult, null);

                if (regCreateKeyExResult is not WIN32_ERROR.ERROR_SUCCESS)
                    throw new Win32Exception((int)regCreateKeyExResult);

                if (!string.IsNullOrWhiteSpace(valueData))
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
                    WIN32_ERROR regDeleteValueResult = PInvoke.RegDeleteValue(hKey, valueName);

                    if (regDeleteValueResult is not WIN32_ERROR.ERROR_SUCCESS)
                        throw new Win32Exception((int)regDeleteValueResult);
                }

                const bool isComputerPolicySettings = true;
                const bool isAddOperation = true;

                ppv.Save(isComputerPolicySettings, isAddOperation, PInvoke.REGISTRY_EXTENSION_GUID, rsSchannelManagerGuid);
            }
            finally
            {
                PInvoke.CoUninitialize();
            }
        }
    }
}