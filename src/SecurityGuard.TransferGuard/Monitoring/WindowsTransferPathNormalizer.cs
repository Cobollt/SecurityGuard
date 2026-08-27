using System.Runtime.InteropServices;
using SecurityGuard.TransferGuard.Contracts;

namespace SecurityGuard.TransferGuard.Monitoring;

public sealed partial class WindowsTransferPathNormalizer
    : ITransferPathNormalizer
{
    public string? Normalize(
        string? path)
    {
        if (string.IsNullOrWhiteSpace(
                path))
        {
            return null;
        }

        var value =
            path.Trim();

        if (value.StartsWith(
                @"\??\",
                StringComparison.OrdinalIgnoreCase))
        {
            value =
                value[4..];
        }

        if (value.StartsWith(
                @"\\?\",
                StringComparison.OrdinalIgnoreCase))
        {
            value =
                value[4..];
        }

        if (Path.IsPathFullyQualified(
                value) &&
            value.Length >= 3 &&
            char.IsLetter(
                value[0]) &&
            value[1] == ':')
        {
            return Path.GetFullPath(
                value);
        }

        if (!value.StartsWith(
                @"\Device\",
                StringComparison.OrdinalIgnoreCase))
        {
            return value;
        }

        foreach (var drive in
                 DriveInfo.GetDrives())
        {
            var root =
                drive.Name;

            if (root.Length < 2)
            {
                continue;
            }

            var driveName =
                root[..2];

            Span<char> buffer =
                stackalloc char[1024];

            uint length;

            unsafe
            {
                fixed (char* targetPath = buffer)
                {
                    length =
                        QueryDosDevice(
                            driveName,
                            targetPath,
                            buffer.Length);
                }
            }

            if (length == 0)
            {
                continue;
            }

            var resultLength =
                checked((int)length);

            var target =
                buffer[..resultLength];

            var nullIndex =
                target.IndexOf('\0');

            if (nullIndex >= 0)
            {
                target =
                    target[..nullIndex];
            }

            var devicePath =
                new string(
                    target);

            if (!value.StartsWith(
                    devicePath,
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var remainder =
                value[
                    devicePath.Length..];

            return driveName +
                   remainder;
        }

        return value;
    }

    [LibraryImport(
        "kernel32.dll",
        EntryPoint = "QueryDosDeviceW",
        SetLastError = true,
        StringMarshalling = StringMarshalling.Utf16)]
    private static unsafe partial uint QueryDosDevice(
        string deviceName,
        char* targetPath,
        int maximumLength);
}