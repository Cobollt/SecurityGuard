using SecurityGuard.TransferGuard.Enums;

namespace SecurityGuard.TransferGuard.Models;

public sealed record NetworkSendActivity(
    int ProcessId,
    TransferProtocol Protocol,
    NetworkAddressFamily AddressFamily,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    long BytesSent,
    DateTimeOffset SentAtUtc,
    TransferProcessInstanceId? ProcessInstance = null);