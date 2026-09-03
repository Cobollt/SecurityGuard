using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using SecurityGuard.ArchiveGuard.Configuration;
using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class WindowsAuthenticodeVerifier
    : IAuthenticodeVerifier
{
    private static readonly Guid GenericVerifyV2 =
        new(
            "00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    private const uint WtdUiNone =
        2;

    private const uint WtdRevokeNone =
        0;

    private const uint WtdRevokeWholeChain =
        1;

    private const uint WtdChoiceFile =
        1;

    private const uint WtdStateActionVerify =
        1;

    private const uint WtdStateActionClose =
        2;

    private const uint WtdRevocationCheckNone =
        0x10;

    private const uint WtdRevocationCheckChainExcludeRoot =
        0x80;

    private const uint WtdCacheOnlyUrlRetrieval =
        0x1000;

    private const uint WtdDisableMd2Md4 =
        0x2000;

    private const ushort WinCertTypePkcsSignedData =
        0x0002;

    private readonly ArchiveGuardOptions _options;

    public WindowsAuthenticodeVerifier(
        ArchiveGuardOptions options)
    {
        _options =
            options;
    }

    public async Task<AuthenticodeAnalysisResult> VerifyAsync(
        string filePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            filePath);

        if (!OperatingSystem.IsWindows())
        {
            return new AuthenticodeAnalysisResult(
                AuthenticodeSignatureStatus.Unavailable,
                PublisherTrustStatus.Unknown,
                null,
                0,
                "Authenticode trust verification is available only on Windows.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        AuthenticodePublisherInfo? publisher =
            null;

        try
        {
            publisher =
                await ReadPublisherAsync(
                    filePath,
                    cancellationToken);
        }
        catch
        {
        }

        int nativeStatus;

        try
        {
            nativeStatus =
                VerifyNative(
                    filePath);
        }
        catch (Exception exception)
        {
            return new AuthenticodeAnalysisResult(
                AuthenticodeSignatureStatus.Error,
                PublisherTrustStatus.Unknown,
                publisher,
                0,
                exception.Message);
        }

        var signatureStatus =
            WinTrustStatusClassifier.Classify(
                nativeStatus);

        var publisherTrust =
            WinTrustStatusClassifier.GetPublisherTrust(
                nativeStatus);

        return new AuthenticodeAnalysisResult(
            signatureStatus,
            publisherTrust,
            publisher,
            nativeStatus,
            GetStatusMessage(
                signatureStatus,
                nativeStatus));
    }

    private int VerifyNative(
        string filePath)
    {
        var fileInfo =
            new WinTrustFileInfo
            {
                cbStruct =
                    (uint)Marshal.SizeOf<WinTrustFileInfo>(),

                pcwszFilePath =
                    filePath,

                hFile =
                    IntPtr.Zero,

                pgKnownSubject =
                    IntPtr.Zero
            };

        var fileInfoPointer =
            Marshal.AllocHGlobal(
                Marshal.SizeOf<WinTrustFileInfo>());

        try
        {
            Marshal.StructureToPtr(
                fileInfo,
                fileInfoPointer,
                false);

            var data =
                new WinTrustData
                {
                    cbStruct =
                        (uint)Marshal.SizeOf<WinTrustData>(),

                    pPolicyCallbackData =
                        IntPtr.Zero,

                    pSIPClientData =
                        IntPtr.Zero,

                    dwUIChoice =
                        WtdUiNone,

                    fdwRevocationChecks =
                        _options.AuthenticodeOnlineRevocationCheck
                            ? WtdRevokeWholeChain
                            : WtdRevokeNone,

                    dwUnionChoice =
                        WtdChoiceFile,

                    pInfoStruct =
                        fileInfoPointer,

                    dwStateAction =
                        WtdStateActionVerify,

                    hWVTStateData =
                        IntPtr.Zero,

                    pwszURLReference =
                        IntPtr.Zero,

                    dwProvFlags =
                        BuildProviderFlags(),

                    dwUIContext =
                        0,

                    pSignatureSettings =
                        IntPtr.Zero
                };

            var action =
                GenericVerifyV2;

            int result;

            try
            {
                result =
                    WinVerifyTrust(
                        IntPtr.Zero,
                        ref action,
                        ref data);
            }
            finally
            {
                data.dwStateAction =
                    WtdStateActionClose;

                WinVerifyTrust(
                    IntPtr.Zero,
                    ref action,
                    ref data);
            }

            return result;
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustFileInfo>(
                fileInfoPointer);

            Marshal.FreeHGlobal(
                fileInfoPointer);
        }
    }

    private uint BuildProviderFlags()
    {
        if (_options.AuthenticodeOnlineRevocationCheck)
        {
            return
                WtdRevocationCheckChainExcludeRoot |
                WtdDisableMd2Md4;
        }

        return
            WtdRevocationCheckNone |
            WtdCacheOnlyUrlRetrieval |
            WtdDisableMd2Md4;
    }

    private static async Task<AuthenticodePublisherInfo?> ReadPublisherAsync(
        string filePath,
        CancellationToken cancellationToken)
    {
        await using var stream =
            new FileStream(
                filePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite |
                FileShare.Delete,
                bufferSize:
                    8192,
                FileOptions.Asynchronous |
                FileOptions.RandomAccess);

        var certificateTable =
            await FindCertificateTableAsync(
                stream,
                cancellationToken);

        if (certificateTable is null)
        {
            return null;
        }

        var position =
            (long)certificateTable.Value.Offset;

        var end =
            position +
            certificateTable.Value.Size;

        while (position <=
               end -
               8)
        {
            var header =
                await ReadAtAsync(
                    stream,
                    position,
                    8,
                    cancellationToken);

            var length =
                BinaryPrimitives.ReadUInt32LittleEndian(
                    header);

            var type =
                BinaryPrimitives.ReadUInt16LittleEndian(
                    header.AsSpan(
                        6,
                        2));

            if (length <
                    8 ||
                length >
                    end -
                    position)
            {
                return null;
            }

            if (type ==
                WinCertTypePkcsSignedData)
            {
                var certificateLength =
                    checked(
                        (int)length -
                        8);

                var certificate =
                    await ReadAtAsync(
                        stream,
                        position +
                        8,
                        certificateLength,
                        cancellationToken);

                var derLength =
                    GetDerObjectLength(
                        certificate);

                if (derLength <= 0)
                {
                    return null;
                }

                var cms =
                    new SignedCms();

                cms.Decode(
                    certificate.AsSpan(
                        0,
                        derLength));

                if (cms.SignerInfos.Count == 0)
                {
                    return null;
                }

                var signer =
                    cms.SignerInfos[0];

                var signerCertificate =
                    signer.Certificate ??
                    cms.Certificates
                        .Cast<X509Certificate2>()
                        .FirstOrDefault();

                if (signerCertificate is null)
                {
                    return null;
                }

                var name =
                    signerCertificate.GetNameInfo(
                        X509NameType.SimpleName,
                        false);

                return new AuthenticodePublisherInfo(
                    string.IsNullOrWhiteSpace(
                        name)
                        ? null
                        : name,
                    signerCertificate.Subject,
                    signerCertificate.Issuer,
                    signerCertificate.Thumbprint,
                    new DateTimeOffset(
                        signerCertificate.NotBefore.ToUniversalTime()),
                    new DateTimeOffset(
                        signerCertificate.NotAfter.ToUniversalTime()));
            }

            position =
                checked(
                    position +
                    AlignEight(
                        length));
        }

        return null;
    }

    private static async Task<CertificateTable?> FindCertificateTableAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        if (stream.Length <
            64)
        {
            return null;
        }

        var dos =
            await ReadAtAsync(
                stream,
                0,
                64,
                cancellationToken);

        if (dos[0] !=
                0x4D ||
            dos[1] !=
                0x5A)
        {
            return null;
        }

        var peOffset =
            BinaryPrimitives.ReadUInt32LittleEndian(
                dos.AsSpan(
                    0x3C,
                    4));

        if (peOffset >
            stream.Length -
            24)
        {
            return null;
        }

        var pe =
            await ReadAtAsync(
                stream,
                peOffset,
                24,
                cancellationToken);

        if (pe[0] !=
                0x50 ||
            pe[1] !=
                0x45 ||
            pe[2] !=
                0 ||
            pe[3] !=
                0)
        {
            return null;
        }

        var optionalSize =
            BinaryPrimitives.ReadUInt16LittleEndian(
                pe.AsSpan(
                    20,
                    2));

        if (optionalSize <
            112)
        {
            return null;
        }

        var optional =
            await ReadAtAsync(
                stream,
                peOffset +
                24,
                optionalSize,
                cancellationToken);

        var magic =
            BinaryPrimitives.ReadUInt16LittleEndian(
                optional);

        int countOffset;
        int directoryOffset;

        if (magic ==
            0x10B)
        {
            countOffset =
                92;

            directoryOffset =
                96;
        }
        else if (magic ==
                 0x20B)
        {
            countOffset =
                108;

            directoryOffset =
                112;
        }
        else
        {
            return null;
        }

        if (optional.Length <
            countOffset +
            4)
        {
            return null;
        }

        var count =
            BinaryPrimitives.ReadUInt32LittleEndian(
                optional.AsSpan(
                    countOffset,
                    4));

        if (count <= 4)
        {
            return null;
        }

        var certificateOffset =
            directoryOffset +
            4 * 8;

        if (optional.Length <
            certificateOffset +
            8)
        {
            return null;
        }

        var fileOffset =
            BinaryPrimitives.ReadUInt32LittleEndian(
                optional.AsSpan(
                    certificateOffset,
                    4));

        var size =
            BinaryPrimitives.ReadUInt32LittleEndian(
                optional.AsSpan(
                    certificateOffset + 4,
                    4));

        if (fileOffset == 0 ||
            size == 0 ||
            fileOffset >
                stream.Length ||
            size >
                stream.Length -
                fileOffset)
        {
            return null;
        }

        return new CertificateTable(
            fileOffset,
            size);
    }

    private static int GetDerObjectLength(
        ReadOnlySpan<byte> data)
    {
        if (data.Length <
                2 ||
            data[0] !=
                0x30)
        {
            return -1;
        }

        var lengthByte =
            data[1];

        if ((lengthByte &
             0x80) ==
            0)
        {
            var total =
                2 +
                lengthByte;

            return total <=
                   data.Length
                ? total
                : -1;
        }

        var lengthBytes =
            lengthByte &
            0x7F;

        if (lengthBytes is
                0 or > 4 ||
            data.Length <
                2 +
                lengthBytes)
        {
            return -1;
        }

        var contentLength =
            0;

        for (var index = 0;
             index < lengthBytes;
             index++)
        {
            contentLength =
                checked(
                    contentLength *
                    256 +
                    data[2 + index]);
        }

        var totalLength =
            checked(
                2 +
                lengthBytes +
                contentLength);

        return totalLength <=
               data.Length
            ? totalLength
            : -1;
    }

    private static long AlignEight(
        uint value)
    {
        return
            (value +
             7u) &
            ~7u;
    }

    private static async Task<byte[]> ReadAtAsync(
        Stream stream,
        long offset,
        int length,
        CancellationToken cancellationToken)
    {
        if (offset < 0 ||
            length < 0 ||
            offset >
                stream.Length ||
            length >
                stream.Length -
                offset)
        {
            throw new InvalidDataException(
                "Authenticode range exceeds file bounds.");
        }

        stream.Position =
            offset;

        var buffer =
            new byte[length];

        var total =
            0;

        while (total <
               buffer.Length)
        {
            var read =
                await stream.ReadAsync(
                    buffer.AsMemory(
                        total),
                    cancellationToken);

            if (read == 0)
            {
                throw new EndOfStreamException();
            }

            total +=
                read;
        }

        return buffer;
    }

    private static string GetStatusMessage(
        AuthenticodeSignatureStatus status,
        int nativeStatus)
    {
        return status switch
        {
            AuthenticodeSignatureStatus.Valid =>
                "Authenticode signature is trusted by Windows.",

            AuthenticodeSignatureStatus.Unsigned =>
                "File does not contain a trusted Authenticode signature.",

            AuthenticodeSignatureStatus.Untrusted =>
                $"Authenticode signature is not trusted. NativeStatus=0x{nativeStatus:X8}",

            AuthenticodeSignatureStatus.Revoked =>
                $"Authenticode certificate is revoked. NativeStatus=0x{nativeStatus:X8}",

            AuthenticodeSignatureStatus.Invalid =>
                $"Authenticode signature is invalid. NativeStatus=0x{nativeStatus:X8}",

            _ =>
                $"Authenticode verification failed. NativeStatus=0x{nativeStatus:X8}"
        };
    }

    [DllImport(
        "wintrust.dll",
        ExactSpelling = true,
        SetLastError = true)]
    private static extern int WinVerifyTrust(
        IntPtr hwnd,
        ref Guid pgActionId,
        ref WinTrustData pWinTrustData);

    [StructLayout(
        LayoutKind.Sequential,
        CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;

        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszFilePath;

        public IntPtr hFile;

        public IntPtr pgKnownSubject;
    }

    [StructLayout(
        LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint cbStruct;

        public IntPtr pPolicyCallbackData;

        public IntPtr pSIPClientData;

        public uint dwUIChoice;

        public uint fdwRevocationChecks;

        public uint dwUnionChoice;

        public IntPtr pInfoStruct;

        public uint dwStateAction;

        public IntPtr hWVTStateData;

        public IntPtr pwszURLReference;

        public uint dwProvFlags;

        public uint dwUIContext;

        public IntPtr pSignatureSettings;
    }

    private readonly record struct CertificateTable(
        uint Offset,
        uint Size);
}