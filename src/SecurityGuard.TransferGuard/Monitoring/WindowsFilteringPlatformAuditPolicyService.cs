using System.ComponentModel;
using System.Runtime.InteropServices;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Monitoring;

public sealed partial class WindowsFilteringPlatformAuditPolicyService
    : IFilteringPlatformAuditPolicyService
{
    private static readonly Guid FilteringPlatformConnection =
        new(
            "0CCE9226-69AE-11D9-BED3-505054503030");

    private const uint AuditSuccess = 0x00000001;
    private const uint AuditFailure = 0x00000002;

    public Task<FilteringPlatformAuditState> GetAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var state =
            Read();

        return Task.FromResult(
            new FilteringPlatformAuditState(
                (state.AuditingInformation & AuditSuccess) != 0,
                (state.AuditingInformation & AuditFailure) != 0,
                false));
    }

    public Task<FilteringPlatformAuditState> EnsureSuccessEnabledAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var current =
            Read();

        var successEnabled =
            (current.AuditingInformation &
             AuditSuccess) != 0;

        var failureEnabled =
            (current.AuditingInformation &
             AuditFailure) != 0;

        if (successEnabled)
        {
            return Task.FromResult(
                new FilteringPlatformAuditState(
                    true,
                    failureEnabled,
                    false));
        }

        EnablePrivilege(
            "SeSecurityPrivilege");



        var updated =
            new AuditPolicyInformation
            {
                AuditSubCategoryGuid =
                    FilteringPlatformConnection,

                AuditingInformation =
                    AuditSuccess |
                    (failureEnabled
                        ? AuditFailure
                        : 0),

                AuditCategoryGuid =
                    current.AuditCategoryGuid
            };

        if (!AuditSetSystemPolicy(
                ref updated,
                1))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error());
        }

        return Task.FromResult(
            new FilteringPlatformAuditState(
                true,
                failureEnabled,
                true));
    }

    private static AuditPolicyInformation Read()
    {
        var subCategory =
            FilteringPlatformConnection;

        if (!AuditQuerySystemPolicy(
                ref subCategory,
                1,
                out var buffer))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error());
        }

        if (buffer == IntPtr.Zero)
        {
            throw new InvalidOperationException(
                "Windows returned an empty audit policy.");
        }

        try
        {
            return Marshal.PtrToStructure<
                AuditPolicyInformation>(
                    buffer);
        }
        finally
        {
            AuditFree(
                buffer);
        }
    }

    private static void EnablePrivilege(
    string privilegeName)
    {
        const uint tokenAdjustPrivileges = 0x0020;
        const uint tokenQuery = 0x0008;
        const uint sePrivilegeEnabled = 0x00000002;
        const int errorNotAllAssigned = 1300;

        if (!OpenProcessToken(
                GetCurrentProcess(),
                tokenAdjustPrivileges | tokenQuery,
                out var token))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error());
        }

        try
        {
            if (!LookupPrivilegeValue(
                    null,
                    privilegeName,
                    out var luid))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error());
            }

            var privileges =
                new TokenPrivileges
                {
                    PrivilegeCount = 1,
                    Privileges =
                        new LuidAndAttributes
                        {
                            Luid = luid,
                            Attributes =
                                sePrivilegeEnabled
                        }
                };

            if (!AdjustTokenPrivileges(
                    token,
                    false,
                    ref privileges,
                    0,
                    IntPtr.Zero,
                    IntPtr.Zero))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error());
            }

            var error =
                Marshal.GetLastWin32Error();

            if (error == errorNotAllAssigned)
            {
                throw new Win32Exception(
                    error);
            }
        }
        finally
        {
            CloseHandle(
                token);
        }
    }

    [StructLayout(
        LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(
        LayoutKind.Sequential)]
    private struct LuidAndAttributes
    {
        public Luid Luid;
        public uint Attributes;
    }

    [StructLayout(
        LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public uint PrivilegeCount;
        public LuidAndAttributes Privileges;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AuditPolicyInformation
    {
        public Guid AuditSubCategoryGuid;

        public uint AuditingInformation;

        public Guid AuditCategoryGuid;
    }

    [LibraryImport(
    "kernel32.dll")]
    private static partial IntPtr GetCurrentProcess();

    [LibraryImport(
        "advapi32.dll",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out IntPtr tokenHandle);

    [LibraryImport(
        "advapi32.dll",
        EntryPoint = "LookupPrivilegeValueW",
        StringMarshalling = StringMarshalling.Utf16,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool LookupPrivilegeValue(
        string? systemName,
        string name,
        out Luid luid);

    [LibraryImport(
        "advapi32.dll",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AdjustTokenPrivileges(
        IntPtr tokenHandle,
        [MarshalAs(UnmanagedType.Bool)]
    bool disableAllPrivileges,
        ref TokenPrivileges newState,
        uint bufferLength,
        IntPtr previousState,
        IntPtr returnLength);

    [LibraryImport(
        "kernel32.dll",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(
        IntPtr handle);

    [LibraryImport(
        "advapi32.dll",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static partial bool AuditQuerySystemPolicy(
        ref Guid subCategoryGuids,
        uint policyCount,
        out IntPtr auditPolicy);

    [LibraryImport(
        "advapi32.dll",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static partial bool AuditSetSystemPolicy(
        ref AuditPolicyInformation auditPolicy,
        uint policyCount);

    [LibraryImport(
        "advapi32.dll")]
    private static partial void AuditFree(
        IntPtr buffer);
}