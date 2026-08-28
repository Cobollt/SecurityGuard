using SecurityGuard.TransferGuard.Enums;

namespace SecurityGuard.TransferGuard.Models;

public sealed record TransferFileClassification(
    TransferFileCategory Category,
    TransferFilePriority Priority,
    string Reason)
{
    public static TransferFileClassification Default =>
        new(
            TransferFileCategory.Unknown,
            TransferFilePriority.Low,
            "Unknown file type");
}