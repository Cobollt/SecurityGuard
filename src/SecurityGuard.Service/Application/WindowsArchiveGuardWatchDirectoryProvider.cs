using Microsoft.Win32;
using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Infrastructure.Configuration;

namespace SecurityGuard.Service.Application;

public sealed class WindowsArchiveGuardWatchDirectoryProvider
    : IArchiveGuardWatchDirectoryProvider
{
    private const string ProfileListPath =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

    private readonly SecurityGuardPaths _securityGuardPaths;

    public WindowsArchiveGuardWatchDirectoryProvider(
        SecurityGuardPaths securityGuardPaths)
    {
        _securityGuardPaths =
            securityGuardPaths;
    }

    public IReadOnlyList<string> GetDirectories(
        ArchiveGuardAutoScanSettings settings)
    {
        ArgumentNullException.ThrowIfNull(
            settings);

        var directories =
            new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

        if (settings.ScanUserDownloads &&
            OperatingSystem.IsWindows())
        {
            AddUserDownloadDirectories(
                directories);
        }

        foreach (var directory in
                 settings.AdditionalDirectories)
        {
            AddDirectory(
                directories,
                directory);
        }

        return directories
            .OrderBy(
                value =>
                    value,
                StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private void AddUserDownloadDirectories(
        ISet<string> directories)
    {
        try
        {
            using var root =
                Registry.LocalMachine.OpenSubKey(
                    ProfileListPath);

            if (root is null)
            {
                return;
            }

            foreach (var subKeyName in
                     root.GetSubKeyNames())
            {
                if (!subKeyName.StartsWith(
                        "S-1-5-21-",
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (subKeyName.EndsWith(
                        ".bak",
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                using var profileKey =
                    root.OpenSubKey(
                        subKeyName);

                var rawProfilePath =
                    profileKey?.GetValue(
                        "ProfileImagePath",
                        null,
                        RegistryValueOptions.DoNotExpandEnvironmentNames)
                    as string;

                if (string.IsNullOrWhiteSpace(
                        rawProfilePath))
                {
                    continue;
                }

                var profilePath =
                    Environment.ExpandEnvironmentVariables(
                        rawProfilePath);

                AddDirectory(
                    directories,
                    Path.Combine(
                        profilePath,
                        "Downloads"));
            }
        }
        catch
        {
        }
    }

    private void AddDirectory(
        ISet<string> directories,
        string directory)
    {
        if (string.IsNullOrWhiteSpace(
                directory))
        {
            return;
        }

        try
        {
            var fullPath =
                Path.GetFullPath(
                    directory);

            if (!Directory.Exists(
                    fullPath))
            {
                return;
            }

            if (IsSecurityGuardInternalDirectory(
                    fullPath))
            {
                return;
            }

            directories.Add(
                fullPath);
        }
        catch
        {
        }
    }

    private bool IsSecurityGuardInternalDirectory(
        string directory)
    {
        var securityGuardRoot =
            NormalizeDirectory(
                _securityGuardPaths.RootDirectory);

        var candidate =
            NormalizeDirectory(
                directory);

        return candidate.StartsWith(
            securityGuardRoot,
            StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeDirectory(
        string path)
    {
        return
            Path.GetFullPath(
                path)
            .TrimEnd(
                Path.DirectorySeparatorChar,
                Path.AltDirectorySeparatorChar) +
            Path.DirectorySeparatorChar;
    }
}