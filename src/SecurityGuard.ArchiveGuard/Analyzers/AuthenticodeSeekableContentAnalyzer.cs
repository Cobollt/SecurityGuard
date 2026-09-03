using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Analyzers;

public sealed class AuthenticodeSeekableContentAnalyzer
    : IArchiveSeekableContentAnalyzer
{
    private readonly IAuthenticodeVerifier _verifier;

    public AuthenticodeSeekableContentAnalyzer(
        IAuthenticodeVerifier verifier)
    {
        _verifier =
            verifier;
    }

    public bool Supports(
        DetectedFileType fileType)
    {
        return fileType ==
               DetectedFileType.Pe;
    }

    public async Task<IReadOnlyList<ArchiveScanFinding>> AnalyzeAsync(
        ArchiveFileMetadata metadata,
        Stream stream,
        string? physicalFilePath,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(
                physicalFilePath))
        {
            return
            [
                new ArchiveScanFinding(
                    ArchiveFindingKind.AuthenticodeVerificationUnavailable,
                    ScanVerdict.Unknown,
                    SecuritySeverity.Low,
                    "Authenticode verification unavailable",
                    "Physical PE file path is unavailable.")
            ];
        }

        var result =
            await _verifier.VerifyAsync(
                physicalFilePath,
                cancellationToken);

        var publisher =
            result.Publisher?.Name ??
            result.Publisher?.Subject ??
            "Unknown";

        return result.SignatureStatus switch
        {
            AuthenticodeSignatureStatus.Valid =>
            [
                new ArchiveScanFinding(
                    ArchiveFindingKind.AuthenticodeValid,
                    ScanVerdict.Clean,
                    SecuritySeverity.Info,
                    "Valid Authenticode signature",
                    $"Publisher={publisher}; Thumbprint={result.Publisher?.Thumbprint ?? "Unknown"}")
            ],

            AuthenticodeSignatureStatus.Unsigned =>
            [
                new ArchiveScanFinding(
                    ArchiveFindingKind.AuthenticodeUnsigned,
                    ScanVerdict.Clean,
                    SecuritySeverity.Info,
                    "PE file is unsigned",
                    $"File={metadata.FileName}")
            ],

            AuthenticodeSignatureStatus.Untrusted =>
            [
                new ArchiveScanFinding(
                    ArchiveFindingKind.AuthenticodeUntrusted,
                    ScanVerdict.Suspicious,
                    SecuritySeverity.Medium,
                    "Authenticode publisher is not trusted",
                    $"Publisher={publisher}; NativeStatus=0x{result.NativeStatus:X8}")
            ],

            AuthenticodeSignatureStatus.Revoked =>
            [
                new ArchiveScanFinding(
                    ArchiveFindingKind.AuthenticodeRevoked,
                    ScanVerdict.Suspicious,
                    SecuritySeverity.Critical,
                    "Authenticode certificate is revoked",
                    $"Publisher={publisher}; NativeStatus=0x{result.NativeStatus:X8}")
            ],

            AuthenticodeSignatureStatus.Invalid =>
            [
                new ArchiveScanFinding(
                    ArchiveFindingKind.AuthenticodeInvalid,
                    ScanVerdict.Suspicious,
                    SecuritySeverity.High,
                    "Invalid Authenticode signature",
                    $"Publisher={publisher}; NativeStatus=0x{result.NativeStatus:X8}")
            ],

            AuthenticodeSignatureStatus.Unavailable =>
            [
                new ArchiveScanFinding(
                    ArchiveFindingKind.AuthenticodeVerificationUnavailable,
                    ScanVerdict.Unknown,
                    SecuritySeverity.Low,
                    "Authenticode verification unavailable",
                    result.Message)
            ],

            _ =>
            [
                new ArchiveScanFinding(
                    ArchiveFindingKind.AuthenticodeVerificationUnavailable,
                    ScanVerdict.Error,
                    SecuritySeverity.High,
                    "Authenticode verification failed",
                    result.Message)
            ]
        };
    }
}