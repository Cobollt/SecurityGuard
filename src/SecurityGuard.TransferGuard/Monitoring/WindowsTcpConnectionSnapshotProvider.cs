using System.Net;
using System.Runtime.InteropServices;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Monitoring;

public sealed partial class WindowsTcpConnectionSnapshotProvider
    : ITcpConnectionSnapshotProvider
{
    private const uint AfInet = 2;
    private const uint AfInet6 = 23;

    private const uint ErrorInsufficientBuffer = 122;

    public Task<IReadOnlyList<TcpConnectionSnapshot>> GetAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var result =
            new List<TcpConnectionSnapshot>();

        ReadIPv4(
            result,
            cancellationToken);

        ReadIPv6(
            result,
            cancellationToken);

        return Task.FromResult<
            IReadOnlyList<TcpConnectionSnapshot>>(
            result);
    }

    private static void ReadIPv4(
        ICollection<TcpConnectionSnapshot> result,
        CancellationToken cancellationToken)
    {
        var bufferSize =
            0u;

        var firstResult =
            GetExtendedTcpTable(
                IntPtr.Zero,
                ref bufferSize,
                false,
                AfInet,
                TcpTableClass.OwnerPidConnections,
                0);

        if (firstResult !=
                ErrorInsufficientBuffer &&
            firstResult != 0)
        {
            throw new InvalidOperationException(
                $"GetExtendedTcpTable IPv4 failed with error {firstResult}.");
        }

        if (bufferSize == 0)
        {
            return;
        }

        var buffer =
            Marshal.AllocHGlobal(
                checked((int)bufferSize));

        try
        {
            var callResult =
                GetExtendedTcpTable(
                    buffer,
                    ref bufferSize,
                    false,
                    AfInet,
                    TcpTableClass.OwnerPidConnections,
                    0);

            if (callResult != 0)
            {
                throw new InvalidOperationException(
                    $"GetExtendedTcpTable IPv4 failed with error {callResult}.");
            }

            var count =
                Marshal.ReadInt32(
                    buffer);

            var rowSize =
                Marshal.SizeOf<MibTcpRowOwnerPid>();

            var rowPointer =
                IntPtr.Add(
                    buffer,
                    sizeof(uint));

            for (var index = 0;
                 index < count;
                 index++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var row =
                    Marshal.PtrToStructure<MibTcpRowOwnerPid>(
                        rowPointer);

                rowPointer =
                    IntPtr.Add(
                        rowPointer,
                        rowSize);

                if (row.OwningPid == 0)
                {
                    continue;
                }

                result.Add(
                    new TcpConnectionSnapshot(
                        checked((int)row.OwningPid),
                        NetworkAddressFamily.IPv4,
                        ToIPv4(row.LocalAddress),
                        ToPort(row.LocalPort),
                        ToIPv4(row.RemoteAddress),
                        ToPort(row.RemotePort),
                        ToState(row.State)));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(
                buffer);
        }
    }

    private static void ReadIPv6(
        ICollection<TcpConnectionSnapshot> result,
        CancellationToken cancellationToken)
    {
        var bufferSize =
            0u;

        var firstResult =
            GetExtendedTcpTable(
                IntPtr.Zero,
                ref bufferSize,
                false,
                AfInet6,
                TcpTableClass.OwnerPidConnections,
                0);

        if (firstResult !=
                ErrorInsufficientBuffer &&
            firstResult != 0)
        {
            throw new InvalidOperationException(
                $"GetExtendedTcpTable IPv6 failed with error {firstResult}.");
        }

        if (bufferSize == 0)
        {
            return;
        }

        var buffer =
            Marshal.AllocHGlobal(
                checked((int)bufferSize));

        try
        {
            var callResult =
                GetExtendedTcpTable(
                    buffer,
                    ref bufferSize,
                    false,
                    AfInet6,
                    TcpTableClass.OwnerPidConnections,
                    0);

            if (callResult != 0)
            {
                throw new InvalidOperationException(
                    $"GetExtendedTcpTable IPv6 failed with error {callResult}.");
            }

            var count =
                Marshal.ReadInt32(
                    buffer);

            var rowSize =
                Marshal.SizeOf<MibTcp6RowOwnerPid>();

            var rowPointer =
                IntPtr.Add(
                    buffer,
                    sizeof(uint));

            for (var index = 0;
                 index < count;
                 index++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var row =
                    Marshal.PtrToStructure<MibTcp6RowOwnerPid>(
                        rowPointer);

                rowPointer =
                    IntPtr.Add(
                        rowPointer,
                        rowSize);

                if (row.OwningPid == 0)
                {
                    continue;
                }

                result.Add(
                    new TcpConnectionSnapshot(
                        checked((int)row.OwningPid),
                        NetworkAddressFamily.IPv6,
                        new IPAddress(
                            row.LocalAddress,
                            row.LocalScopeId).ToString(),
                        ToPort(row.LocalPort),
                        new IPAddress(
                            row.RemoteAddress,
                            row.RemoteScopeId).ToString(),
                        ToPort(row.RemotePort),
                        ToState(row.State)));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(
                buffer);
        }
    }

    private static string ToIPv4(
        uint address)
    {
        var bytes =
            new[]
            {
                (byte)(address & 0xFF),
                (byte)((address >> 8) & 0xFF),
                (byte)((address >> 16) & 0xFF),
                (byte)((address >> 24) & 0xFF)
            };

        return new IPAddress(
            bytes).ToString();
    }

    private static int ToPort(
        uint value)
    {
        var networkPort =
            (ushort)(value & 0xFFFF);

        return (ushort)(
            (networkPort >> 8) |
            (networkPort << 8));
    }

    private static TransferTcpState ToState(
        uint state)
    {
        return Enum.IsDefined(
            typeof(TransferTcpState),
            (int)state)
                ? (TransferTcpState)state
                : TransferTcpState.Unknown;
    }

    [LibraryImport(
        "iphlpapi.dll",
        EntryPoint = "GetExtendedTcpTable")]
    private static partial uint GetExtendedTcpTable(
        IntPtr tcpTable,
        ref uint size,
        [MarshalAs(UnmanagedType.Bool)]
        bool order,
        uint addressFamily,
        TcpTableClass tableClass,
        uint reserved);

    private enum TcpTableClass
    {
        BasicListener = 0,
        BasicConnections = 1,
        BasicAll = 2,
        OwnerPidListener = 3,
        OwnerPidConnections = 4,
        OwnerPidAll = 5,
        OwnerModuleListener = 6,
        OwnerModuleConnections = 7,
        OwnerModuleAll = 8
    }

    [StructLayout(
        LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;

        public uint LocalAddress;

        public uint LocalPort;

        public uint RemoteAddress;

        public uint RemotePort;

        public uint OwningPid;
    }

    [StructLayout(
        LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPid
    {
        [MarshalAs(
            UnmanagedType.ByValArray,
            SizeConst = 16)]
        public byte[] LocalAddress;

        public uint LocalScopeId;

        public uint LocalPort;

        [MarshalAs(
            UnmanagedType.ByValArray,
            SizeConst = 16)]
        public byte[] RemoteAddress;

        public uint RemoteScopeId;

        public uint RemotePort;

        public uint State;

        public uint OwningPid;
    }
}