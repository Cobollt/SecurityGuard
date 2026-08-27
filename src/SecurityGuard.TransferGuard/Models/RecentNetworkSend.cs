using SecurityGuard.TransferGuard.Enums;

namespace SecurityGuard.TransferGuard.Models;

public sealed record RecentNetworkSend(
    int ProcessId,
    TransferProtocol Protocol,
    NetworkAddressFamily AddressFamily,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    long ObservedSentBytes,
    DateTimeOffset FirstSendAtUtc,
    DateTimeOffset LastSendAtUtc);