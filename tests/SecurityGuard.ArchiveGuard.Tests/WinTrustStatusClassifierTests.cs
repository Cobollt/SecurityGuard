using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Services;

namespace SecurityGuard.ArchiveGuard.Tests;

public sealed class WinTrustStatusClassifierTests
{
    [Fact]
    public void Zero_is_valid()
    {
        Assert.Equal(
            AuthenticodeSignatureStatus.Valid,
            WinTrustStatusClassifier.Classify(
                0));
    }

    [Fact]
    public void No_signature_is_unsigned()
    {
        Assert.Equal(
            AuthenticodeSignatureStatus.Unsigned,
            WinTrustStatusClassifier.Classify(
                unchecked(
                    (int)0x800B0100)));
    }

    [Fact]
    public void Bad_digest_is_invalid()
    {
        Assert.Equal(
            AuthenticodeSignatureStatus.Invalid,
            WinTrustStatusClassifier.Classify(
                unchecked(
                    (int)0x80096010)));
    }

    [Fact]
    public void Untrusted_root_is_untrusted()
    {
        Assert.Equal(
            AuthenticodeSignatureStatus.Untrusted,
            WinTrustStatusClassifier.Classify(
                unchecked(
                    (int)0x800B0109)));
    }

    [Fact]
    public void Revoked_certificate_is_revoked()
    {
        Assert.Equal(
            AuthenticodeSignatureStatus.Revoked,
            WinTrustStatusClassifier.Classify(
                unchecked(
                    (int)0x800B010C)));
    }

    [Fact]
    public void Explicit_distrust_is_preserved()
    {
        Assert.Equal(
            PublisherTrustStatus.ExplicitlyDistrusted,
            WinTrustStatusClassifier.GetPublisherTrust(
                unchecked(
                    (int)0x800B0111)));
    }
}