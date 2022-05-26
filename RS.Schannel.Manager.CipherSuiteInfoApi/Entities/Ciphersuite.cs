﻿namespace RS.Schannel.Manager.CipherSuiteInfoApi;

using System.Text.Json.Serialization;

public readonly record struct Ciphersuite(
    [property: JsonPropertyName("iana_name")] string IanaName,
    [property: JsonPropertyName("gnutls_name")] string GnuTlsName,
    [property: JsonPropertyName("openssl_name")] string OpenSslName,
    [property: JsonPropertyName("hex_byte_1")] string HexCodeByte1,
    [property: JsonPropertyName("hex_byte_2")] string HexCodeByte2,
    [property: JsonPropertyName("protocol_version")] string Protocol,
    [property: JsonPropertyName("kex_algorithm")] string KeyExchangeAlgorithm,
    [property: JsonPropertyName("auth_algorithm")] string AuthenticationAlgorithm,
    [property: JsonPropertyName("enc_algorithm")] string EncryptionAlgorithm,
    [property: JsonPropertyName("hash_algorithm")] string HashAlgorithm,
    [property: JsonPropertyName("security")] Security Security,
    [property: JsonPropertyName("tls_version")] CipherSuiteTlsVersion[] TlsVersions);