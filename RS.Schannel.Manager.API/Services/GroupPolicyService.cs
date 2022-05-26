namespace RS.Schannel.Manager.API;

using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Xml;
using System.Xml.Linq;
using Windows.Win32;
using Microsoft.Win32.SafeHandles;
using winmdroot = global::Windows.Win32;

internal sealed class GroupPolicyService : IGroupPolicyService
{
    private readonly Guid CLSID_GroupPolicyObject = new(0xea502722, 0xa23d, 0x11d1, 0xa7, 0xd3, 0x0, 0x0, 0xf8, 0x75, 0x71, 0xe3);
    private readonly Guid REGISTRY_EXTENSION_GUID = new(0x35378EAC, 0x683F, 0x11D2, 0xA8, 0x9A, 0x00, 0xC0, 0x4F, 0xBB, 0xCF, 0xA2);
    private readonly Guid Rs_Schannel_Manager_Guid = new(0x929aa20, 0xaa5d, 0x4fd5, 0x83, 0x10, 0x85, 0x7a, 0x10, 0xf2, 0x45, 0xa9);

    // Group Policy Object open / creation flags
    private const uint GPO_OPEN_LOAD_REGISTRY = 0x00000001U; // Load the registry files
    private const uint GPO_OPEN_READ_ONLY = 0x00000002U; // Open the GPO as read only

    // Group Policy Object Section flags
    private const uint GPO_SECTION_ROOT = 0U; // Root
    private const uint GPO_SECTION_USER = 1U; // User
    private const uint GPO_SECTION_MACHINE = 2U; // Machine

    // Predefined Value Types.
    private const uint REG_NONE = 0U; // No value type
    private const uint REG_SZ = 1U; // Unicode nul terminated string
                                    //#define REG_EXPAND_SZ               ( 2ul ) // Unicode nul terminated string
                                    //    // (with environment variable references)
                                    //#define REG_BINARY                  ( 3ul ) // Free form binary
                                    //#define REG_DWORD                   ( 4ul ) // 32-bit number
                                    //#define REG_DWORD_LITTLE_ENDIAN     ( 4ul ) // 32-bit number (same as REG_DWORD)
                                    //#define REG_DWORD_BIG_ENDIAN        ( 5ul ) // 32-bit number
                                    //#define REG_LINK                    ( 6ul ) // Symbolic Link (unicode)
                                    //#define REG_MULTI_SZ                ( 7ul ) // Multiple Unicode strings
                                    //#define REG_RESOURCE_LIST           ( 8ul ) // Resource list in the resource map
                                    //#define REG_FULL_RESOURCE_DESCRIPTOR ( 9ul ) // Resource list in the hardware description
                                    //#define REG_RESOURCE_REQUIREMENTS_LIST ( 10ul )
                                    //#define REG_QWORD                   ( 11ul ) // 64-bit number
                                    //#define REG_QWORD_LITTLE_ENDIAN     ( 11ul ) // 64-bit number (same as REG_QWORD)

    private const string MicrosoftPoliciesCypherStrengthPolicyDefinitionResourcesFile = "{0}\\PolicyDefinitions\\en-US\\CipherSuiteOrder.adml";
    private const string MicrosoftPoliciesCypherStrengthPolicyDefinitionResourcesFileXmlNamespace = "http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions";
    private const string SSLConfigurationPolicyKey = "SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002";
    private const string SSLCipherSuiteOrderValueName = "Functions";
    private const string SSLCurveOrderValueName = "EccCurves";

    private const uint CipherSuitesListMaximumCharacters = 1023U;

    public async Task<string> GetSslCipherSuiteOrderPolicyWindowsDefaultsAsync(CancellationToken cancellationToken = default)
    {
        string windowsFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string microsoftPoliciesCypherStrengthPolicyDefinitionResourcesFile = string.Format(CultureInfo.InvariantCulture, MicrosoftPoliciesCypherStrengthPolicyDefinitionResourcesFile, windowsFolder);
        await using FileStream stream = new FileInfo(microsoftPoliciesCypherStrengthPolicyDefinitionResourcesFile).Open(new FileStreamOptions { Access = FileAccess.Read, Mode = FileMode.Open, Options = FileOptions.Asynchronous });
        using var xmlReader = XmlReader.Create(stream, new XmlReaderSettings { Async = true });
        XDocument xDocument = await XDocument.LoadAsync(xmlReader, LoadOptions.SetBaseUri, cancellationToken);
        XNamespace ns = MicrosoftPoliciesCypherStrengthPolicyDefinitionResourcesFileXmlNamespace;
        string sslCipherSuiteOrderPolicyWindowsDefaults = xDocument
            .Elements(ns + "policyDefinitionResources").Single()
            .Elements(ns + "resources").Single()
            .Elements(ns + "presentationTable").Single()
            .Elements(ns + "presentation").Single(q => "SSLCipherSuiteOrder".Equals(q.Attribute("id")!.Value, StringComparison.OrdinalIgnoreCase))
            .Elements(ns + "textBox").Single(q => "Pol_SSLCipherSuiteOrder".Equals(q.Attribute("refId")!.Value, StringComparison.OrdinalIgnoreCase))
            .Elements(ns + "defaultValue").Single().Value;

        return sslCipherSuiteOrderPolicyWindowsDefaults;
    }

    public async Task<string> GetSslCurveOrderPolicyWindowsDefaultsAsync(CancellationToken cancellationToken = default)
    {
        string windowsFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string microsoftPoliciesCypherStrengthPolicyDefinitionResourcesFile = string.Format(CultureInfo.InvariantCulture, MicrosoftPoliciesCypherStrengthPolicyDefinitionResourcesFile, windowsFolder);
        await using FileStream stream = new FileInfo(microsoftPoliciesCypherStrengthPolicyDefinitionResourcesFile).Open(new FileStreamOptions { Access = FileAccess.Read, Mode = FileMode.Open, Options = FileOptions.Asynchronous });
        using var xmlReader = XmlReader.Create(stream, new XmlReaderSettings { Async = true });
        XDocument xDocument = await XDocument.LoadAsync(xmlReader, LoadOptions.SetBaseUri, cancellationToken);
        XNamespace ns = MicrosoftPoliciesCypherStrengthPolicyDefinitionResourcesFileXmlNamespace;
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

    public void UpdateSslCipherSuiteOrderPolicy(string[] cipherSuites)
    {
        string cipherSuitesString = string.Join(",", cipherSuites);

        unsafe
        {
            try
            {
                winmdroot.Foundation.HRESULT coInitializeExResult = PInvoke.CoInitializeEx(null, winmdroot.System.Com.COINIT.COINIT_APARTMENTTHREADED);

                if (coInitializeExResult.Failed)
                    throw Marshal.GetExceptionForHR(coInitializeExResult)!;

                winmdroot.Foundation.HRESULT coCreateInstanceResult = PInvoke.CoCreateInstance(CLSID_GroupPolicyObject, null, winmdroot.System.Com.CLSCTX.CLSCTX_INPROC_SERVER, out winmdroot.System.GroupPolicy.IGroupPolicyObject ppv);

                if (coCreateInstanceResult.Failed)
                    throw Marshal.GetExceptionForHR(coCreateInstanceResult)!;

                ppv.OpenLocalMachineGPO(GPO_OPEN_LOAD_REGISTRY);

                winmdroot.System.Registry.HKEY machineKey = default;

                ppv.GetRegistryKey(GPO_SECTION_MACHINE, ref machineKey);

                var hkey = new SafeRegistryHandle(machineKey, true);

                winmdroot.Foundation.WIN32_ERROR regCreateKeyExResult = PInvoke.RegCreateKeyEx(hkey, SSLConfigurationPolicyKey, 0U, null, winmdroot.System.Registry.REG_OPEN_CREATE_OPTIONS.REG_OPTION_NON_VOLATILE, winmdroot.System.Registry.REG_SAM_FLAGS.KEY_SET_VALUE | winmdroot.System.Registry.REG_SAM_FLAGS.KEY_QUERY_VALUE, null, out SafeRegistryHandle phkResult, null);

                if (regCreateKeyExResult is not winmdroot.Foundation.WIN32_ERROR.ERROR_SUCCESS)
                    throw new Win32Exception((int)regCreateKeyExResult);

                fixed (char* lpData = cipherSuitesString)
                {
                    winmdroot.Foundation.WIN32_ERROR regSetKeyValueResult = PInvoke.RegSetKeyValue(phkResult, null, SSLCipherSuiteOrderValueName, REG_SZ, lpData, (uint)(sizeof(char) * cipherSuitesString.Length));

                    if (regSetKeyValueResult is not winmdroot.Foundation.WIN32_ERROR.ERROR_SUCCESS)
                        throw new Win32Exception((int)regSetKeyValueResult);
                }

                const bool isComputerPolicySettings = true;
                const bool isAddOperation = true;

                ppv.Save(isComputerPolicySettings, isAddOperation, REGISTRY_EXTENSION_GUID, Rs_Schannel_Manager_Guid);
            }
            finally
            {
                PInvoke.CoUninitialize();
            }
        }
    }

    public void UpdateEccCurveOrderPolicy(string[] eccCurves)
    {
    }
}