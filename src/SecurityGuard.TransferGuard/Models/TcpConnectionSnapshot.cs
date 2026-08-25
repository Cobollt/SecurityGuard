using SecurityGuard.TransferGuard.Enums;

namespace SecurityGuard.TransferGuard.Models;

public sealed record TcpConnectionSnapshot(
    int ProcessId,
    NetworkAddressFamily AddressFamily,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    TransferTcpState State);