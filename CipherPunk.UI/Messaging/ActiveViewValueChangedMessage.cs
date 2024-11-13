using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Messaging.Messages;

namespace CipherPunk.UI;

internal sealed class ActiveViewValueChangedMessage(ObservableObject activeView) : ValueChangedMessage<ObservableObject>(activeView);