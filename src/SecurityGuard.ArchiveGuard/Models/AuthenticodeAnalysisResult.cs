using SecurityGuard.ArchiveGuard.Enums;

namespace SecurityGuard.ArchiveGuard.Models;

public sealed record AuthenticodeAnalysisResult(
    AuthenticodeSignatureStatus SignatureStatus,
    PublisherTrustStatus PublisherTrust,
    AuthenticodePublisherInfo? Publisher,
    int NativeStatus,
    string Message);