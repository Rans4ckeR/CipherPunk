using CommunityToolkit.Mvvm.Messaging.Messages;

namespace CipherPunk.UI;

internal sealed class UserMessageValueChangedMessage(UserMessage userMessage) : ValueChangedMessage<UserMessage>(userMessage);