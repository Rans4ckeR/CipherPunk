using CommunityToolkit.Mvvm.ComponentModel;

namespace CipherPunk.UI;

internal sealed class UiSchannelProtocolSettings : ObservableObject
{
    public UiSchannelProtocolSettings(SchannelProtocolSettings schannelProtocolSettings)
    {
        Protocol = schannelProtocolSettings.Protocol;
        ClientStatus = schannelProtocolSettings.ClientStatus;
        ServerStatus = schannelProtocolSettings.ServerStatus;
    }

    public SchannelProtocol Protocol
    {
        get;
        set => SetProperty(ref field, value);
    }

    public SchannelProtocolStatus ClientStatus
    {
        get;
        set => SetProperty(ref field, value);
    }

    public SchannelProtocolStatus ServerStatus
    {
        get;
        set => SetProperty(ref field, value);
    }
}