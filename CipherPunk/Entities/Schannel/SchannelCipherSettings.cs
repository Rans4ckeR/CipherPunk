namespace CipherPunk;

public readonly record struct SchannelCipherSettings(
    SchannelCipher Cipher,
    bool? Enabled);