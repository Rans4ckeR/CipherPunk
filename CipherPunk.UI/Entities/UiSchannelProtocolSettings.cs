using CommunityToolkit.Mvvm.ComponentModel;

namespace CipherPunk.UI;

internal sealed partial class UiSchannelProtocolSettings(SchannelProtocolSettings schannelProtocolSettings) : ObservableObject
{
    [ObservableProperty]
    public partial SchannelProtocol Protocol { get; set; } = schannelProtocolSettings.Protocol;

    [ObservableProperty]
    public partial SchannelProtocolStatus ClientStatus { get; set; } = schannelProtocolSettings.ClientStatus;

    [ObservableProperty]
    public partial SchannelProtocolStatus ServerStatus { get; set; } = schannelProtocolSettings.ServerStatus;
}