using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.ArchiveGuard.Services;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Tests;

public sealed class ArchiveGuardDecisionRequestFactoryTests
{
    [Fact]
    public void Suspicious_scan_creates_archiveguard_request()
    {
        var result =
            CreateResult(
                ScanVerdict.Suspicious);

        var factory =
            new ArchiveGuardDecisionRequestFactory();

        var request =
            factory.Create(
                result);

        Assert.Equal(
            SecurityModuleKind.ArchiveGuard,
            request.Module);

        Assert.Equal(
            SecurityEventType.ArchiveScan,
            request.EventType);

        Assert.Contains(
            SecurityAction.AllowOnce,
            request.AvailableActions);

        Assert.Contains(
            SecurityAction.Quarantine,
            request.AvailableActions);

        Assert.Contains(
            SecurityAction.Delete,
            request.AvailableActions);

        Assert.NotNull(
            request.RuleContext);

        Assert.Equal(
            result.Sha256,
            request.RuleContext.FileHash);

        Assert.False(
            string.IsNullOrWhiteSpace(
                request.Identity));
    }

    [Fact]
    public void Clean_scan_has_no_actions()
    {
        var result =
            CreateResult(
                ScanVerdict.Clean);

        var factory =
            new ArchiveGuardDecisionRequestFactory();

        var request =
            factory.Create(
                result);

        Assert.Empty(
            request.AvailableActions);
    }

    private static ArchiveGuardScanResult CreateResult(
        ScanVerdict verdict)
    {
        return new ArchiveGuardScanResult(
            Guid.NewGuid(),
            Path.Combine(
                Path.GetTempPath(),
                "sample.exe"),
            new string(
                'A',
                64),
            1024,
            verdict,
            [],
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            DetectedFileType.Pe);
    }
}