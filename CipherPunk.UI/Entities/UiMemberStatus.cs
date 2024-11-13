using CommunityToolkit.Mvvm.ComponentModel;

namespace CipherPunk.UI;

internal sealed class UiMemberStatus<T>(T member, bool enabled) : ObservableObject
{
    public T Member
    {
        get => member;
        set => SetProperty(ref member, value);
    }

    public bool Enabled
    {
        get => enabled;
        set => SetProperty(ref enabled, value);
    }
}