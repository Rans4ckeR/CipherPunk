namespace CipherPunk;

public readonly record struct SchannelProtocolSettings(
    SchannelProtocol Protocol,
    SchannelProtocolStatus ClientStatus,
    SchannelProtocolStatus ServerStatus);