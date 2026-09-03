using SecurityGuard.ArchiveGuard.Enums;

namespace SecurityGuard.ArchiveGuard.Services;

public static class WinTrustStatusClassifier
{
    private const int TrustENoSignature =
        unchecked((int)0x800B0100);

    private const int TrustEBadDigest =
        unchecked((int)0x80096010);

    private const int TrustECertSignature =
        unchecked((int)0x80096004);

    private const int TrustECounterSigner =
        unchecked((int)0x80096003);

    private const int TrustENoSignerCert =
        unchecked((int)0x80096002);

    private const int TrustETimeStamp =
        unchecked((int)0x80096005);

    private const int TrustEExplicitDistrust =
        unchecked((int)0x800B0111);

    private const int CertEUntrustedRoot =
        unchecked((int)0x800B0109);

    private const int CertEUntrustedTestRoot =
        unchecked((int)0x800B010D);

    private const int CertEChaining =
        unchecked((int)0x800B010A);

    private const int CertEUntrustedCa =
        unchecked((int)0x800B0112);

    private const int CertEExpired =
        unchecked((int)0x800B0101);

    private const int CertEWrongUsage =
        unchecked((int)0x800B0110);

    private const int CertERevoked =
        unchecked((int)0x800B010C);

    private const int CryptERevoked =
        unchecked((int)0x80092010);

    private const int CryptERevocationOffline =
        unchecked((int)0x80092013);

    private const int CertERevocationFailure =
        unchecked((int)0x800B010E);

    public static AuthenticodeSignatureStatus Classify(
        int status)
    {
        if (status == 0)
        {
            return AuthenticodeSignatureStatus.Valid;
        }

        if (status ==
            TrustENoSignature)
        {
            return AuthenticodeSignatureStatus.Unsigned;
        }

        if (status ==
                CertERevoked ||
            status ==
                CryptERevoked)
        {
            return AuthenticodeSignatureStatus.Revoked;
        }

        if (status ==
                CertEUntrustedRoot ||
            status ==
                CertEUntrustedTestRoot ||
            status ==
                CertEChaining ||
            status ==
                CertEUntrustedCa ||
            status ==
                CertEExpired ||
            status ==
                CertEWrongUsage ||
            status ==
                CryptERevocationOffline ||
            status ==
                CertERevocationFailure ||
            status ==
                TrustEExplicitDistrust)
        {
            return AuthenticodeSignatureStatus.Untrusted;
        }

        if (status ==
                TrustEBadDigest ||
            status ==
                TrustECertSignature ||
            status ==
                TrustECounterSigner ||
            status ==
                TrustENoSignerCert ||
            status ==
                TrustETimeStamp)
        {
            return AuthenticodeSignatureStatus.Invalid;
        }

        return AuthenticodeSignatureStatus.Invalid;
    }

    public static PublisherTrustStatus GetPublisherTrust(
        int status)
    {
        if (status == 0)
        {
            return PublisherTrustStatus.TrustedByWindows;
        }

        if (status ==
            TrustEExplicitDistrust)
        {
            return PublisherTrustStatus.ExplicitlyDistrusted;
        }

        if (status ==
            TrustENoSignature)
        {
            return PublisherTrustStatus.None;
        }

        return PublisherTrustStatus.Unknown;
    }
}