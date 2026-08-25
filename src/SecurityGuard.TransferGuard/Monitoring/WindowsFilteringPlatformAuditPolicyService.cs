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

    [StructLayout(
        LayoutKind.Sequential)]
    private struct AuditPolicyInformation
    {
        public Guid AuditSubCategoryGuid;

        public uint AuditingInformation;

        public Guid AuditCategoryGuid;
    }

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