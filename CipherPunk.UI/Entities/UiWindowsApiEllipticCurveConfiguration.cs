namespace CipherPunk.UI;

internal readonly record struct UiWindowsApiEllipticCurveConfiguration(
    ushort Priority,
    string? Id,
    string Name,
    uint? BitLength,
    string CngAlgorithms);