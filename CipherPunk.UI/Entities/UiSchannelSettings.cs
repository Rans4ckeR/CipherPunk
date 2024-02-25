namespace CipherPunk.UI;

using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

internal sealed class UiSchannelSettings : ObservableObject
{
    private ObservableCollection<UiMemberStatus<SchannelEventLogging>>? eventLogging;
    private ObservableCollection<UiMemberStatus<SchannelCertificateMappingMethod>>? certificateMappingMethod;
    private int? clientCacheTime;
    private bool? enableOcspStaplingForSni;
    private int? issuerCacheSize;
    private int? issuerCacheTime;
    private bool? sendTrustedIssuerList;
    private int? serverCacheTime;
    private int? messageLimitClient;
    private int? messageLimitServer;
    private int? messageLimitServerClientAuth;

    public UiSchannelSettings(SchannelSettings schannelSettings)
    {
        EventLogging = new(Enum.GetValues<SchannelEventLogging>().Select(q => new UiMemberStatus<SchannelEventLogging>(q, schannelSettings.EventLogging!.Value.HasFlag(q))));
        CertificateMappingMethods = new(Enum.GetValues<SchannelCertificateMappingMethod>().Select(q => new UiMemberStatus<SchannelCertificateMappingMethod>(q, schannelSettings.CertificateMappingMethods!.Value.HasFlag(q))));
        ClientCacheTime = schannelSettings.ClientCacheTime;
        EnableOcspStaplingForSni = schannelSettings.EnableOcspStaplingForSni;
        IssuerCacheSize = schannelSettings.IssuerCacheSize;
        IssuerCacheTime = schannelSettings.IssuerCacheTime;
        MaximumCacheSize = schannelSettings.MaximumCacheSize;
        SendTrustedIssuerList = schannelSettings.SendTrustedIssuerList;
        ServerCacheTime = schannelSettings.ServerCacheTime;
        MessageLimitClient = schannelSettings.MessageLimitClient;
        MessageLimitServer = schannelSettings.MessageLimitServer;
        MessageLimitServerClientAuth = schannelSettings.MessageLimitServerClientAuth;
    }

    public ObservableCollection<UiMemberStatus<SchannelEventLogging>>? EventLogging
    {
        get => eventLogging;
        set => SetProperty(ref eventLogging, value);
    }

    public ObservableCollection<UiMemberStatus<SchannelCertificateMappingMethod>>? CertificateMappingMethods
    {
        get => certificateMappingMethod;
        set => SetProperty(ref certificateMappingMethod, value);
    }

    public int? ClientCacheTime
    {
        get => clientCacheTime;
        set => SetProperty(ref clientCacheTime, value);
    }

    public bool? EnableOcspStaplingForSni
    {
        get => enableOcspStaplingForSni;
        set => SetProperty(ref enableOcspStaplingForSni, value);
    }

    public int? IssuerCacheSize
    {
        get => issuerCacheSize;
        set => SetProperty(ref issuerCacheSize, value);
    }

    public int? IssuerCacheTime
    {
        get => issuerCacheTime;
        set => SetProperty(ref issuerCacheTime, value);
    }

    public int? MaximumCacheSize
    {
        get => clientCacheTime;
        set => SetProperty(ref clientCacheTime, value);
    }

    public bool? SendTrustedIssuerList
    {
        get => sendTrustedIssuerList;
        set => SetProperty(ref sendTrustedIssuerList, value);
    }

    public int? ServerCacheTime
    {
        get => serverCacheTime;
        set => SetProperty(ref serverCacheTime, value);
    }

    public int? MessageLimitClient
    {
        get => messageLimitClient;
        set => SetProperty(ref messageLimitClient, value);
    }

    public int? MessageLimitServer
    {
        get => messageLimitServer;
        set => SetProperty(ref messageLimitServer, value);
    }

    public int? MessageLimitServerClientAuth
    {
        get => messageLimitServerClientAuth;
        set => SetProperty(ref messageLimitServerClientAuth, value);
    }
}