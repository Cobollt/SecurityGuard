using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Enums;

namespace SecurityGuard.TransferGuard.Models;

public sealed record NetworkConnectionObservation(
    Guid Id,
    DateTimeOffset DetectedAtUtc,
    TransferProtocol Protocol,
    NetworkAddressFamily AddressFamily,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    ProcessInfo? Process,
    string? ApplicationPath,
    TransferProcessInstanceId? ProcessInstance = null);