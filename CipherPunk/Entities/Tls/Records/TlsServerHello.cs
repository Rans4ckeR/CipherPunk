﻿namespace CipherPunk;

using Windows.Win32;

public readonly record struct TlsServerHello(SslProviderCipherSuiteId SslProviderCipherSuiteId, TlsCompressionMethodIdentifier TlsCompressionMethodIdentifier);