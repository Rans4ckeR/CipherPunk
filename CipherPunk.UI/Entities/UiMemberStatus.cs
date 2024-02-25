namespace CipherPunk.UI;

using CommunityToolkit.Mvvm.ComponentModel;

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