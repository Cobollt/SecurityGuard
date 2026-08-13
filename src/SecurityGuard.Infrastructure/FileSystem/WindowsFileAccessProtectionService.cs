using System.Runtime.Versioning;

using System.Security.AccessControl;
using System.Security.Principal;

namespace SecurityGuard.Infrastructure.FileSystem;

[SupportedOSPlatform("windows")]
public sealed class WindowsFileAccessProtectionService
    : IFileAccessProtectionService
{
    public void ProtectDirectory(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var directory =
            new DirectoryInfo(path);

        if (!directory.Exists)
        {
            throw new DirectoryNotFoundException(path);
        }

        var security =
            new DirectorySecurity();

        security.SetAccessRuleProtection(
            true,
            false);

        security.AddAccessRule(
            CreateDirectoryRule(
                WellKnownSidType.LocalSystemSid));

        security.AddAccessRule(
            CreateDirectoryRule(
                WellKnownSidType.BuiltinAdministratorsSid));

        directory.SetAccessControl(security);
    }

    public void ProtectFile(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var file =
            new FileInfo(path);

        if (!file.Exists)
        {
            throw new FileNotFoundException(
                "File was not found.",
                path);
        }

        var security =
            new FileSecurity();

        security.SetAccessRuleProtection(
            true,
            false);

        security.AddAccessRule(
            CreateFileRule(
                WellKnownSidType.LocalSystemSid));

        security.AddAccessRule(
            CreateFileRule(
                WellKnownSidType.BuiltinAdministratorsSid));

        file.SetAccessControl(security);
    }

    private static FileSystemAccessRule CreateDirectoryRule(
        WellKnownSidType sidType)
    {
        var sid =
            new SecurityIdentifier(
                sidType,
                null);

        return new FileSystemAccessRule(
            sid,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit |
            InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow);
    }

    private static FileSystemAccessRule CreateFileRule(
        WellKnownSidType sidType)
    {
        var sid =
            new SecurityIdentifier(
                sidType,
                null);

        return new FileSystemAccessRule(
            sid,
            FileSystemRights.FullControl,
            AccessControlType.Allow);
    }
}