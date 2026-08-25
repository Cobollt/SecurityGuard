using System.Net;
using System.Runtime.CompilerServices;
using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Monitoring;

public sealed class PollingTransferConnectionMonitor
    : ITransferConnectionMonitor
{
    private readonly ITcpConnectionSnapshotProvider _provider;
    private readonly TransferGuardOptions _options;

    public PollingTransferConnectionMonitor(
        ITcpConnectionSnapshotProvider provider,
        TransferGuardOptions options)
    {
        _provider =
            provider;

        _options =
            options;
    }

    public async IAsyncEnumerable<TcpConnectionSnapshot> WatchAsync(
        [EnumeratorCancellation]
        CancellationToken cancellationToken = default)
    {
        var known =
            new HashSet<ConnectionKey>();

        using var timer =
            new PeriodicTimer(
                _options.PollInterval);

        while (!cancellationToken.IsCancellationRequested)
        {
            var connections =
                await _provider.GetAsync(
                    cancellationToken);

            var current =
                new HashSet<ConnectionKey>();

            foreach (var connection in connections)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (!ShouldObserve(
                        connection))
                {
                    continue;
                }

                var key =
                    ConnectionKey.Create(
                        connection);

                current.Add(
                    key);

                if (known.Contains(
                        key))
                {
                    continue;
                }

                yield return connection;
            }

            known =
                current;

            if (!await timer.WaitForNextTickAsync(
                    cancellationToken))
            {
                yield break;
            }
        }
    }

    private bool ShouldObserve(
        TcpConnectionSnapshot connection)
    {
        if (connection.ProcessId <= 0)
        {
            return false;
        }

        if (connection.State is not
            TransferTcpState.SynSent and not
            TransferTcpState.SynReceived and not
            TransferTcpState.Established)
        {
            return false;
        }

        if (!IPAddress.TryParse(
                connection.RemoteAddress,
                out var remoteAddress))
        {
            return false;
        }

        if (remoteAddress.Equals(
                IPAddress.Any) ||
            remoteAddress.Equals(
                IPAddress.IPv6Any))
        {
            return false;
        }

        if (_options.IgnoreLoopback &&
            IPAddress.IsLoopback(
                remoteAddress))
        {
            return false;
        }

        return true;
    }

    private sealed record ConnectionKey(
        int ProcessId,
        NetworkAddressFamily AddressFamily,
        string LocalAddress,
        int LocalPort,
        string RemoteAddress,
        int RemotePort)
    {
        public static ConnectionKey Create(
            TcpConnectionSnapshot connection)
        {
            return new ConnectionKey(
                connection.ProcessId,
                connection.AddressFamily,
                connection.LocalAddress,
                connection.LocalPort,
                connection.RemoteAddress,
                connection.RemotePort);
        }
    }
}