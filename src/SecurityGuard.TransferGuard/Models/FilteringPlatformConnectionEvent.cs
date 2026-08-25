using SecurityGuard.TransferGuard.Enums;

namespace SecurityGuard.TransferGuard.Models;

public sealed record FilteringPlatformConnectionEvent(
    DateTimeOffset DetectedAtUtc,
    int ProcessId,
    string? ApplicationPath,
    TransferProtocol Protocol,
    NetworkAddressFamily AddressFamily,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort);