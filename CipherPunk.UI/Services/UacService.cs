using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using Microsoft.Win32.SafeHandles;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security;
using Windows.Win32.UI.Shell;

namespace CipherPunk.UI;

internal sealed class UacService : IUacService
{
    [SupportedOSPlatform("windows6.0.6000")]
    public BitmapSource GetShieldIcon()
    {
        var psii = new SHSTOCKICONINFO
        {
            cbSize = (uint)Marshal.SizeOf<SHSTOCKICONINFO>()
        };
        BOOL destroyIconResult;
        BitmapSource bitmapSource;

        try
        {
            HRESULT shGetStockIconInfoResult = PInvoke.SHGetStockIconInfo(SHSTOCKICONID.SIID_SHIELD, SHGSI_FLAGS.SHGSI_ICON | SHGSI_FLAGS.SHGSI_SMALLICON, ref psii);

            if (shGetStockIconInfoResult.Failed)
                throw new Win32Exception(shGetStockIconInfoResult);

            bitmapSource = Imaging.CreateBitmapSourceFromHIcon(psii.hIcon, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
        }
        finally
        {
            destroyIconResult = PInvoke.DestroyIcon(psii.hIcon);
        }

        return destroyIconResult.Value is 0 ? throw new Win32Exception(Marshal.GetLastWin32Error()) : bitmapSource;
    }

    [SupportedOSPlatform("windows5.1.2600")]
    public (MandatoryLevel MandatoryLevel, bool Elevated) GetIntegrityLevel()
    {
        using SafeFileHandle processTokenHandle = PInvoke.GetCurrentProcessToken();
        BOOL getTokenInformationResult = PInvoke.GetTokenInformation(processTokenHandle, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, null, out uint tokenInformationLength);

        if (!getTokenInformationResult)
        {
            int getTokenInformationError = Marshal.GetLastWin32Error();

            if (getTokenInformationError is not (int)WIN32_ERROR.ERROR_INSUFFICIENT_BUFFER)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        ref uint integrityLevel = ref Unsafe.NullRef<uint>();
        Span<byte> tokenInformationBuffer = new byte[tokenInformationLength];

        unsafe
        {
            getTokenInformationResult = PInvoke.GetTokenInformation(processTokenHandle, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, tokenInformationBuffer, out tokenInformationLength);

            if (!getTokenInformationResult)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            TOKEN_MANDATORY_LABEL tokenMandatoryLabel = MemoryMarshal.AsRef<TOKEN_MANDATORY_LABEL>(tokenInformationBuffer);
            PSID sid = tokenMandatoryLabel.Label.Sid;
            byte* sidSubAuthorityCountPtr = PInvoke.GetSidSubAuthorityCount(sid);
            ref byte sidSubAuthorityCount = ref Unsafe.AsRef<byte>(sidSubAuthorityCountPtr);
            uint* sidLastSubAuthorityPtr = PInvoke.GetSidSubAuthority(sid, (uint)(sidSubAuthorityCount - 1));

            integrityLevel = ref Unsafe.AsRef<uint>(sidLastSubAuthorityPtr);
        }

        MandatoryLevel mandatoryLevel = integrityLevel switch
        {
            >= 28672 => MandatoryLevel.SecureProcess,
            >= PInvoke.SECURITY_MANDATORY_PROTECTED_PROCESS_RID => MandatoryLevel.ProtectedProcess,
            >= PInvoke.SECURITY_MANDATORY_SYSTEM_RID => MandatoryLevel.System,
            >= PInvoke.SECURITY_MANDATORY_HIGH_RID => MandatoryLevel.High,
            >= PInvoke.SECURITY_MANDATORY_MEDIUM_PLUS_RID => MandatoryLevel.MediumPlus,
            >= PInvoke.SECURITY_MANDATORY_MEDIUM_RID + 0x10 => MandatoryLevel.MediumUiAccess,
            >= PInvoke.SECURITY_MANDATORY_MEDIUM_RID => MandatoryLevel.Medium,
            >= PInvoke.SECURITY_MANDATORY_LOW_RID => MandatoryLevel.Low,
            _ => MandatoryLevel.Untrusted
        };

        return (mandatoryLevel, mandatoryLevel >= MandatoryLevel.High);
    }
}