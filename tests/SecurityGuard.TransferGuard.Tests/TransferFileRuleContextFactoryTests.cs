using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;
using SecurityGuard.TransferGuard.Services;

namespace SecurityGuard.TransferGuard.Tests;

public sealed class TransferFileRuleContextFactoryTests
{
    [Fact]
    public void Candidate_is_mapped_to_file_rule_context()
    {
        var candidate =
            new FileTransferCandidate(
                Guid.NewGuid(),
                DateTimeOffset.UtcNow,
                100,
                @"C:\Users\Ivan\Documents\report.pdf",
                "ABC123",
                1024 * 1024,
                1100 * 1024,
                1024 * 1024,
                TimeSpan.FromMilliseconds(400),
                0.93,
                TransferCorrelationConfidence.High,
                new TransferFileClassification(
                    TransferFileCategory.Document,
                    TransferFilePriority.High,
                    "Document"),
                new NetworkConnectionObservation(
                    Guid.NewGuid(),
                    DateTimeOffset.UtcNow,
                    TransferProtocol.Tcp,
                    NetworkAddressFamily.IPv4,
                    "192.168.1.20",
                    51000,
                    "1.1.1.1",
                    443,
                    new ProcessInfo(
                        100,
                        null,
                        "client.exe",
                        @"C:\Apps\client.exe",
                        null,
                        null,
                        null),
                    @"C:\Apps\client.exe"));

        var context =
            new TransferFileRuleContextFactory()
                .Create(
                    candidate);

        Assert.Equal(
            "ABC123",
            context.FileHash);

        Assert.Equal(
            @"C:\Users\Ivan\Documents\report.pdf",
            context.FilePath);

        Assert.Equal(
            "report.pdf",
            context.FileName);

        Assert.Equal(
            ".pdf",
            context.FileExtension);

        Assert.Equal(
            "Document",
            context.FileCategory);

        Assert.Equal(
            @"C:\Apps\client.exe",
            context.ProcessPath);

        Assert.Equal(
            "1.1.1.1",
            context.RemoteAddress);

        Assert.Equal(
            443,
            context.RemotePort);

        Assert.Equal(
            "FileTransfer",
            context.TransferActivityKind);
    }
}