namespace CipherPunk;

public readonly record struct SchannelKeyExchangeAlgorithmSettings(
    SchannelKeyExchangeAlgorithm KeyExchangeAlgorithm,
    int? ClientMinKeyBitLength,
    int? ClientMaxKeyBitLength,
    int? ServerMinKeyBitLength,
    bool? Enabled);