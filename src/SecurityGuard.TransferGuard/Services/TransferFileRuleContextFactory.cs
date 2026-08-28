using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferFileRuleContextFactory
{
    public RuleMatchContext Create(
        FileTransferCandidate candidate)
    {
        ArgumentNullException.ThrowIfNull(
            candidate);

        var processPath =
            !string.IsNullOrWhiteSpace(
                candidate.Connection.Process?.ExecutablePath)
                ? candidate.Connection.Process.ExecutablePath
                : candidate.Connection.ApplicationPath;

        return new RuleMatchContext(
            FileHash:
                candidate.Sha256,

            FilePath:
                candidate.FilePath,

            FileName:
                Path.GetFileName(
                    candidate.FilePath),

            FileExtension:
                Path.GetExtension(
                    candidate.FilePath),

            Process:
                candidate.Connection.Process?.ProcessName,

            ProcessPath:
                processPath,

            RemoteAddress:
                candidate.Connection.RemoteAddress,

            RemotePort:
                candidate.Connection.RemotePort,

            Protocol:
                candidate.Connection.Protocol.ToString(),

            FileCategory:
                candidate.Classification.Category.ToString(),

            TransferActivityKind:
                Enums.TransferActivityKind
                    .FileTransfer
                    .ToString());
    }
}