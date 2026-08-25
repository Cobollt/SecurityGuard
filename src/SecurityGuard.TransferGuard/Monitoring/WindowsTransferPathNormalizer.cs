using System.Runtime.InteropServices;
using System.Text;
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

            var buffer =
                new StringBuilder(
                    1024);

            var length =
                QueryDosDevice(
                    driveName,
                    buffer,
                    buffer.Capacity);

            if (length == 0)
            {
                continue;
            }

            var devicePath =
                buffer.ToString();

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
    private static partial uint QueryDosDevice(
        string deviceName,
        StringBuilder targetPath,
        int maximumLength);
}