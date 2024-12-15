using CommunityToolkit.Mvvm.ComponentModel;

namespace CipherPunk.UI;

internal sealed partial class UiMemberStatus<T>(T member, bool enabled) : ObservableObject
{
    [ObservableProperty]
    public partial T Member { get; set; } = member;

    [ObservableProperty]
    public partial bool Enabled { get; set; } = enabled;
}