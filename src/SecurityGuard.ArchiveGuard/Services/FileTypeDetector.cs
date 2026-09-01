using System.Buffers.Binary;
using System.Text;
using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class FileTypeDetector
    : IFileTypeDetector
{
    private static readonly byte[] ZipLocalHeader =
    [
        0x50,
        0x4B,
        0x03,
        0x04
    ];

    private static readonly byte[] ZipEmptyArchive =
    [
        0x50,
        0x4B,
        0x05,
        0x06
    ];

    private static readonly byte[] ZipSpannedArchive =
    [
        0x50,
        0x4B,
        0x07,
        0x08
    ];

    private static readonly byte[] SevenZipSignature =
    [
        0x37,
        0x7A,
        0xBC,
        0xAF,
        0x27,
        0x1C
    ];

    private static readonly byte[] Rar4Signature =
    [
        0x52,
        0x61,
        0x72,
        0x21,
        0x1A,
        0x07,
        0x00
    ];

    private static readonly byte[] Rar5Signature =
    [
        0x52,
        0x61,
        0x72,
        0x21,
        0x1A,
        0x07,
        0x01,
        0x00
    ];

    private static readonly byte[] GzipSignature =
    [
        0x1F,
        0x8B
    ];

    private static readonly byte[] PdfSignature =
        Encoding.ASCII.GetBytes(
            "%PDF-");

    private static readonly byte[] TarSignature =
        Encoding.ASCII.GetBytes(
            "ustar");

    public DetectedFileType Detect(
        ReadOnlySpan<byte> header)
    {
        if (IsPe(
                header))
        {
            return DetectedFileType.Pe;
        }

        if (StartsWith(
                header,
                PdfSignature))
        {
            return DetectedFileType.Pdf;
        }

        if (IsZip(
                header))
        {
            return DetectedFileType.Zip;
        }

        if (StartsWith(
                header,
                SevenZipSignature))
        {
            return DetectedFileType.SevenZip;
        }

        if (StartsWith(
                header,
                Rar5Signature) ||
            StartsWith(
                header,
                Rar4Signature))
        {
            return DetectedFileType.Rar;
        }

        if (StartsWith(
                header,
                GzipSignature))
        {
            return DetectedFileType.Gzip;
        }

        if (IsTar(
                header))
        {
            return DetectedFileType.Tar;
        }

        return DetectedFileType.Unknown;
    }

    private static bool IsZip(
        ReadOnlySpan<byte> header)
    {
        return StartsWith(
                   header,
                   ZipLocalHeader) ||
               StartsWith(
                   header,
                   ZipEmptyArchive) ||
               StartsWith(
                   header,
                   ZipSpannedArchive);
    }

    private static bool IsPe(
        ReadOnlySpan<byte> header)
    {
        if (header.Length <
            0x40)
        {
            return false;
        }

        if (header[0] !=
                0x4D ||
            header[1] !=
                0x5A)
        {
            return false;
        }

        var peOffset =
            BinaryPrimitives.ReadInt32LittleEndian(
                header.Slice(
                    0x3C,
                    4));

        if (peOffset <
                0x40 ||
            peOffset >
                header.Length - 4)
        {
            return false;
        }

        return header[peOffset] ==
                   0x50 &&
               header[peOffset + 1] ==
                   0x45 &&
               header[peOffset + 2] ==
                   0x00 &&
               header[peOffset + 3] ==
                   0x00;
    }

    private static bool IsTar(
        ReadOnlySpan<byte> header)
    {
        const int offset =
            257;

        if (header.Length <
            offset +
            TarSignature.Length)
        {
            return false;
        }

        return header
            .Slice(
                offset,
                TarSignature.Length)
            .SequenceEqual(
                TarSignature);
    }

    private static bool StartsWith(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
        return data.Length >=
                   signature.Length &&
               data[..signature.Length]
                   .SequenceEqual(
                       signature);
    }
}