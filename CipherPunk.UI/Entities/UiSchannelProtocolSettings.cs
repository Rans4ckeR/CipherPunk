namespace CipherPunk.UI;

using CommunityToolkit.Mvvm.ComponentModel;

internal sealed class UiSchannelProtocolSettings : ObservableObject
{
    private SchannelProtocol protocol;
    private SchannelProtocolStatus clientStatus;
    private SchannelProtocolStatus serverStatus;

    public UiSchannelProtocolSettings(SchannelProtocolSettings schannelProtocolSettings)
    {
        Protocol = schannelProtocolSettings.Protocol;
        ClientStatus = schannelProtocolSettings.ClientStatus;
        ServerStatus = schannelProtocolSettings.ServerStatus;
    }

    public SchannelProtocol Protocol
    {
        get => protocol;
        set => SetProperty(ref protocol, value);
    }

    public SchannelProtocolStatus ClientStatus
    {
        get => clientStatus;
        set => SetProperty(ref clientStatus, value);
    }

    public SchannelProtocolStatus ServerStatus
    {
        get => serverStatus;
        set => SetProperty(ref serverStatus, value);
    }
}