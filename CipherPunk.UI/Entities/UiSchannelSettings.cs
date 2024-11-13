using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace CipherPunk.UI;

internal sealed class UiSchannelSettings : ObservableObject
{
    private int? clientCacheTime;

    public UiSchannelSettings(SchannelSettings schannelSettings)
    {
        EventLogging = [.. Enum.GetValues<SchannelEventLogging>().Select(q => new UiMemberStatus<SchannelEventLogging>(q, schannelSettings.EventLogging!.Value.HasFlag(q)))];
        CertificateMappingMethods = [.. Enum.GetValues<SchannelCertificateMappingMethod>().Select(q => new UiMemberStatus<SchannelCertificateMappingMethod>(q, schannelSettings.CertificateMappingMethods!.Value.HasFlag(q)))];
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
        get;
        set => SetProperty(ref field, value);
    }

    public ObservableCollection<UiMemberStatus<SchannelCertificateMappingMethod>>? CertificateMappingMethods
    {
        get;
        set => SetProperty(ref field, value);
    }

    public int? ClientCacheTime
    {
        get => clientCacheTime;
        set => SetProperty(ref clientCacheTime, value);
    }

    public bool? EnableOcspStaplingForSni
    {
        get;
        set => SetProperty(ref field, value);
    }

    public int? IssuerCacheSize
    {
        get;
        set => SetProperty(ref field, value);
    }

    public int? IssuerCacheTime
    {
        get;
        set => SetProperty(ref field, value);
    }

    public int? MaximumCacheSize
    {
        get => clientCacheTime;
        set => SetProperty(ref clientCacheTime, value);
    }

    public bool? SendTrustedIssuerList
    {
        get;
        set => SetProperty(ref field, value);
    }

    public int? ServerCacheTime
    {
        get;
        set => SetProperty(ref field, value);
    }

    public int? MessageLimitClient
    {
        get;
        set => SetProperty(ref field, value);
    }

    public int? MessageLimitServer
    {
        get;
        set => SetProperty(ref field, value);
    }

    public int? MessageLimitServerClientAuth
    {
        get;
        set => SetProperty(ref field, value);
    }
}