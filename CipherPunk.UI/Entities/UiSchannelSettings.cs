using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace CipherPunk.UI;

internal sealed partial class UiSchannelSettings(SchannelSettings schannelSettings) : ObservableObject
{
    [ObservableProperty]
    public partial ObservableCollection<UiMemberStatus<SchannelEventLogging>>? EventLogging { get; set; } = [.. Enum.GetValues<SchannelEventLogging>().Select(q => new UiMemberStatus<SchannelEventLogging>(q, schannelSettings.EventLogging!.Value.HasFlag(q)))];

    [ObservableProperty]
    public partial ObservableCollection<UiMemberStatus<SchannelCertificateMappingMethod>>? CertificateMappingMethods { get; set; } = [.. Enum.GetValues<SchannelCertificateMappingMethod>().Select(q => new UiMemberStatus<SchannelCertificateMappingMethod>(q, schannelSettings.CertificateMappingMethods!.Value.HasFlag(q)))];

    [ObservableProperty]
    public partial int? ClientCacheTime { get; set; } = schannelSettings.ClientCacheTime;

    [ObservableProperty]
    public partial bool? EnableOcspStaplingForSni { get; set; } = schannelSettings.EnableOcspStaplingForSni;

    [ObservableProperty]
    public partial int? IssuerCacheSize { get; set; } = schannelSettings.IssuerCacheSize;

    [ObservableProperty]
    public partial int? IssuerCacheTime { get; set; } = schannelSettings.IssuerCacheTime;

    [ObservableProperty]
    public partial int? MaximumCacheSize { get; set; } = schannelSettings.MaximumCacheSize;

    [ObservableProperty]
    public partial bool? SendTrustedIssuerList { get; set; } = schannelSettings.SendTrustedIssuerList;

    [ObservableProperty]
    public partial int? ServerCacheTime { get; set; } = schannelSettings.ServerCacheTime;

    [ObservableProperty]
    public partial int? MessageLimitClient { get; set; } = schannelSettings.MessageLimitClient;

    [ObservableProperty]
    public partial int? MessageLimitServer { get; set; } = schannelSettings.MessageLimitServer;

    [ObservableProperty]
    public partial int? MessageLimitServerClientAuth { get; set; } = schannelSettings.MessageLimitServerClientAuth;
}