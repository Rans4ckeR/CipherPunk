namespace CipherPunk.UI;

using System.Windows.Media.Imaging;

internal interface IUacService
{
    BitmapSource GetShieldIcon();

    (MandatoryLevel MandatoryLevel, bool Elevated) GetIntegrityLevel();
}