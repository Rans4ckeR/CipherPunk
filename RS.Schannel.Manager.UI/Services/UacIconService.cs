namespace RS.Schannel.Manager.UI;

using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.UI.Shell;

internal sealed class UacIconService : IUacIconService
{
    public BitmapSource GetUacShieldIcon()
    {
        var psii = new SHSTOCKICONINFO
        {
            cbSize = (uint)Marshal.SizeOf(typeof(SHSTOCKICONINFO))
        };
        BOOL destroyIconResult = default;
        BitmapSource bitmapSource;

        try
        {
            HRESULT shGetStockIconInfoResult = PInvoke.SHGetStockIconInfo(SHSTOCKICONID.SIID_SHIELD, SHGSI_FLAGS.SHGSI_ICON | SHGSI_FLAGS.SHGSI_SMALLICON, ref psii);

            if (!shGetStockIconInfoResult.Succeeded)
                throw Marshal.GetExceptionForHR(shGetStockIconInfoResult)!;

            bitmapSource = Imaging.CreateBitmapSourceFromHIcon(psii.hIcon, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
        }
        finally
        {
            if (!psii.hIcon.IsNull)
                destroyIconResult = PInvoke.DestroyIcon(psii.hIcon);
        }

        if (destroyIconResult.Value == 0)
            throw new Win32Exception(Marshal.GetLastWin32Error());

        return bitmapSource;
    }
}