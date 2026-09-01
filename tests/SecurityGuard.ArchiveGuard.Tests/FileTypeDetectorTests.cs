using System.Buffers.Binary;
using System.Text;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Services;

namespace SecurityGuard.ArchiveGuard.Tests;

public sealed class FileTypeDetectorTests
{
    private readonly FileTypeDetector _detector =
        new();

    [Fact]
    public void Zip_is_detected()
    {
        var result =
            _detector.Detect(
                [
                    0x50,
                    0x4B,
                    0x03,
                    0x04,
                    0x14,
                    0x00
                ]);

        Assert.Equal(
            DetectedFileType.Zip,
            result);
    }

    [Fact]
    public void Empty_zip_is_detected()
    {
        var result =
            _detector.Detect(
                [
                    0x50,
                    0x4B,
                    0x05,
                    0x06
                ]);

        Assert.Equal(
            DetectedFileType.Zip,
            result);
    }

    [Fact]
    public void Seven_zip_is_detected()
    {
        var result =
            _detector.Detect(
                [
                    0x37,
                    0x7A,
                    0xBC,
                    0xAF,
                    0x27,
                    0x1C,
                    0x00,
                    0x04
                ]);

        Assert.Equal(
            DetectedFileType.SevenZip,
            result);
    }

    [Fact]
    public void Rar4_is_detected()
    {
        var result =
            _detector.Detect(
                [
                    0x52,
                    0x61,
                    0x72,
                    0x21,
                    0x1A,
                    0x07,
                    0x00
                ]);

        Assert.Equal(
            DetectedFileType.Rar,
            result);
    }

    [Fact]
    public void Rar5_is_detected()
    {
        var result =
            _detector.Detect(
                [
                    0x52,
                    0x61,
                    0x72,
                    0x21,
                    0x1A,
                    0x07,
                    0x01,
                    0x00
                ]);

        Assert.Equal(
            DetectedFileType.Rar,
            result);
    }

    [Fact]
    public void Gzip_is_detected()
    {
        var result =
            _detector.Detect(
                [
                    0x1F,
                    0x8B,
                    0x08,
                    0x00
                ]);

        Assert.Equal(
            DetectedFileType.Gzip,
            result);
    }

    [Fact]
    public void Pdf_is_detected()
    {
        var result =
            _detector.Detect(
                Encoding.ASCII.GetBytes(
                    "%PDF-1.7"));

        Assert.Equal(
            DetectedFileType.Pdf,
            result);
    }

    [Fact]
    public void Tar_is_detected()
    {
        var header =
            new byte[512];

        Encoding.ASCII
            .GetBytes(
                "ustar")
            .CopyTo(
                header,
                257);

        var result =
            _detector.Detect(
                header);

        Assert.Equal(
            DetectedFileType.Tar,
            result);
    }

    [Fact]
    public void Pe_is_detected()
    {
        var header =
            CreatePeHeader();

        var result =
            _detector.Detect(
                header);

        Assert.Equal(
            DetectedFileType.Pe,
            result);
    }

    [Fact]
    public void Mz_without_pe_signature_is_not_pe()
    {
        var header =
            new byte[128];

        header[0] =
            0x4D;

        header[1] =
            0x5A;

        var result =
            _detector.Detect(
                header);

        Assert.Equal(
            DetectedFileType.Unknown,
            result);
    }

    private static byte[] CreatePeHeader()
    {
        var header =
            new byte[256];

        header[0] =
            0x4D;

        header[1] =
            0x5A;

        BinaryPrimitives.WriteInt32LittleEndian(
            header.AsSpan(
                0x3C,
                4),
            0x80);

        header[0x80] =
            0x50;

        header[0x81] =
            0x45;

        header[0x82] =
            0x00;

        header[0x83] =
            0x00;

        return header;
    }
}