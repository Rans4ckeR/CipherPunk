using System.Windows.Media.Imaging;

namespace CipherPunk.UI;

internal interface IUacService
{
    BitmapSource GetShieldIcon();

    (MandatoryLevel MandatoryLevel, bool Elevated) GetIntegrityLevel();
}