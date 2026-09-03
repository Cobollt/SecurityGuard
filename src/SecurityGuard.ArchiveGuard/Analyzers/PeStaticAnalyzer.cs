using System.Buffers.Binary;
using System.Text;
using SecurityGuard.ArchiveGuard.Configuration;
using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.ArchiveGuard.Analyzers;

public sealed class PeStaticAnalyzer
    : IPeStaticAnalyzer
{
    private const uint SectionMemExecute =
        0x20000000;

    private const uint SectionMemWrite =
        0x80000000;

    private readonly ArchiveGuardOptions _options;

    public PeStaticAnalyzer(
        ArchiveGuardOptions options)
    {
        _options =
            options;
    }

    public async Task<PeStaticAnalysisResult> AnalyzeAsync(
        Stream stream,
        string logicalPath,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            stream);

        if (!stream.CanRead ||
            !stream.CanSeek)
        {
            return Invalid(
                logicalPath,
                "PE analysis requires a readable seekable stream.");
        }

        try
        {
            if (stream.Length <
                64)
            {
                return Invalid(
                    logicalPath,
                    "PE file is too small.");
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
                return Invalid(
                    logicalPath,
                    "DOS MZ signature is missing.");
            }

            var peOffset =
                BinaryPrimitives.ReadUInt32LittleEndian(
                    dos.AsSpan(
                        0x3C,
                        4));

            if (peOffset >
                    stream.Length -
                    24 ||
                peOffset >
                    16 * 1024 * 1024)
            {
                return Invalid(
                    logicalPath,
                    "Invalid PE header offset.");
            }

            var signatureAndCoff =
                await ReadAtAsync(
                    stream,
                    peOffset,
                    24,
                    cancellationToken);

            if (signatureAndCoff[0] !=
                    0x50 ||
                signatureAndCoff[1] !=
                    0x45 ||
                signatureAndCoff[2] !=
                    0x00 ||
                signatureAndCoff[3] !=
                    0x00)
            {
                return Invalid(
                    logicalPath,
                    "PE signature is missing.");
            }

            var coff =
                signatureAndCoff.AsSpan(
                    4);

            var machine =
                BinaryPrimitives.ReadUInt16LittleEndian(
                    coff);

            var sectionCount =
                BinaryPrimitives.ReadUInt16LittleEndian(
                    coff.Slice(
                        2,
                        2));

            var optionalHeaderSize =
                BinaryPrimitives.ReadUInt16LittleEndian(
                    coff.Slice(
                        16,
                        2));

            var characteristics =
                BinaryPrimitives.ReadUInt16LittleEndian(
                    coff.Slice(
                        18,
                        2));

            if (sectionCount == 0 ||
                sectionCount >
                _options.MaxPeSections)
            {
                return Invalid(
                    logicalPath,
                    $"Invalid PE section count: {sectionCount}.");
            }

            if (optionalHeaderSize <
                72)
            {
                return Invalid(
                    logicalPath,
                    "PE optional header is too small.");
            }

            var optionalOffset =
                checked(
                    (long)peOffset +
                    24);

            if (optionalOffset >
                    stream.Length ||
                optionalHeaderSize >
                    stream.Length -
                    optionalOffset)
            {
                return Invalid(
                    logicalPath,
                    "PE optional header exceeds file bounds.");
            }

            var optional =
                await ReadAtAsync(
                    stream,
                    optionalOffset,
                    optionalHeaderSize,
                    cancellationToken);

            var magic =
                BinaryPrimitives.ReadUInt16LittleEndian(
                    optional);

            var pe32 =
                magic ==
                0x10B;

            var pe32Plus =
                magic ==
                0x20B;

            if (!pe32 &&
                !pe32Plus)
            {
                return Invalid(
                    logicalPath,
                    $"Unsupported PE optional header magic: 0x{magic:X4}.");
            }

            var minimumOptional =
                pe32
                    ? 96
                    : 112;

            if (optional.Length <
                minimumOptional)
            {
                return Invalid(
                    logicalPath,
                    "PE optional header is truncated.");
            }

            var entryPoint =
                BinaryPrimitives.ReadUInt32LittleEndian(
                    optional.AsSpan(
                        16,
                        4));

            ulong imageBase;

            if (pe32)
            {
                imageBase =
                    BinaryPrimitives.ReadUInt32LittleEndian(
                        optional.AsSpan(
                            28,
                            4));
            }
            else
            {
                imageBase =
                    BinaryPrimitives.ReadUInt64LittleEndian(
                        optional.AsSpan(
                            24,
                            8));
            }

            var sizeOfImage =
                BinaryPrimitives.ReadUInt32LittleEndian(
                    optional.AsSpan(
                        56,
                        4));

            var sizeOfHeaders =
                BinaryPrimitives.ReadUInt32LittleEndian(
                    optional.AsSpan(
                        60,
                        4));

            var subsystem =
                BinaryPrimitives.ReadUInt16LittleEndian(
                    optional.AsSpan(
                        68,
                        2));

            var dllCharacteristics =
                BinaryPrimitives.ReadUInt16LittleEndian(
                    optional.AsSpan(
                        70,
                        2));

            var numberOfRvaAndSizesOffset =
                pe32
                    ? 92
                    : 108;

            var dataDirectoryOffset =
                pe32
                    ? 96
                    : 112;

            var directoryCount =
                optional.Length >=
                numberOfRvaAndSizesOffset + 4
                    ? BinaryPrimitives.ReadUInt32LittleEndian(
                        optional.AsSpan(
                            numberOfRvaAndSizesOffset,
                            4))
                    : 0;

            var importDirectory =
                ReadDirectory(
                    optional,
                    directoryCount,
                    dataDirectoryOffset,
                    1);

            var certificateDirectory =
                ReadDirectory(
                    optional,
                    directoryCount,
                    dataDirectoryOffset,
                    4);

            var sectionTableOffset =
                checked(
                    optionalOffset +
                    optionalHeaderSize);

            var sectionTableLength =
                checked(
                    sectionCount *
                    40);

            if (sectionTableOffset >
                    stream.Length ||
                sectionTableLength >
                    stream.Length -
                    sectionTableOffset)
            {
                return Invalid(
                    logicalPath,
                    "PE section table exceeds file bounds.");
            }

            var sectionBytes =
                await ReadAtAsync(
                    stream,
                    sectionTableOffset,
                    sectionTableLength,
                    cancellationToken);

            var sections =
                new List<PeSectionInfo>(
                    sectionCount);

            var findings =
                new List<ArchiveScanFinding>();

            for (var index = 0;
                 index < sectionCount;
                 index++)
            {
                var header =
                    sectionBytes.AsSpan(
                        index * 40,
                        40);

                var name =
                    ReadSectionName(
                        header[..8]);

                var virtualSize =
                    BinaryPrimitives.ReadUInt32LittleEndian(
                        header.Slice(
                            8,
                            4));

                var virtualAddress =
                    BinaryPrimitives.ReadUInt32LittleEndian(
                        header.Slice(
                            12,
                            4));

                var rawSize =
                    BinaryPrimitives.ReadUInt32LittleEndian(
                        header.Slice(
                            16,
                            4));

                var rawOffset =
                    BinaryPrimitives.ReadUInt32LittleEndian(
                        header.Slice(
                            20,
                            4));

                var sectionCharacteristics =
                    BinaryPrimitives.ReadUInt32LittleEndian(
                        header.Slice(
                            36,
                            4));

                if (rawSize > 0 &&
                    !IsValidRange(
                        stream.Length,
                        rawOffset,
                        rawSize))
                {
                    return Invalid(
                        logicalPath,
                        $"PE section {name} exceeds file bounds.");
                }

                var executable =
                    (sectionCharacteristics &
                     SectionMemExecute) !=
                    0;

                var writable =
                    (sectionCharacteristics &
                     SectionMemWrite) !=
                    0;

                double? entropy =
                    null;

                if (rawSize > 0)
                {
                    var sampleLength =
                        (int)Math.Min(
                            rawSize,
                            (uint)_options.MaxPeSectionEntropySampleBytes);

                    var sample =
                        await ReadAtAsync(
                            stream,
                            rawOffset,
                            sampleLength,
                            cancellationToken);

                    entropy =
                        CalculateEntropy(
                            sample);
                }

                sections.Add(
                    new PeSectionInfo(
                        name,
                        virtualAddress,
                        virtualSize,
                        rawOffset,
                        rawSize,
                        sectionCharacteristics,
                        executable,
                        writable,
                        entropy));

                if (executable &&
                    writable)
                {
                    findings.Add(
                        new ArchiveScanFinding(
                            ArchiveFindingKind.PeWritableExecutableSection,
                            ScanVerdict.Suspicious,
                            SecuritySeverity.High,
                            "PE section is writable and executable",
                            $"Section={name}; Characteristics=0x{sectionCharacteristics:X8}"));
                }

                if (executable &&
                    entropy is not null &&
                    entropy >=
                    _options.PeHighEntropyThreshold)
                {
                    findings.Add(
                        new ArchiveScanFinding(
                            ArchiveFindingKind.PeHighEntropySection,
                            ScanVerdict.Suspicious,
                            SecuritySeverity.Medium,
                            "Executable PE section has high entropy",
                            $"Section={name}; Entropy={entropy:F3}; Threshold={_options.PeHighEntropyThreshold:F2}"));
                }
            }

            if (entryPoint != 0 &&
                !IsEntryPointExecutable(
                    entryPoint,
                    sections))
            {
                findings.Add(
                    new ArchiveScanFinding(
                        ArchiveFindingKind.PeEntryPointOutsideExecutableSection,
                        ScanVerdict.Suspicious,
                        SecuritySeverity.High,
                        "PE entry point is outside executable sections",
                        $"EntryPointRva=0x{entryPoint:X8}"));
            }

            var imports =
                await ReadImportsAsync(
                    stream,
                    importDirectory,
                    sizeOfHeaders,
                    sections,
                    pe32Plus,
                    cancellationToken);

            if (HasSuspiciousImportCombination(
                    imports))
            {
                findings.Add(
                    new ArchiveScanFinding(
                        ArchiveFindingKind.PeSuspiciousImportCombination,
                        ScanVerdict.Suspicious,
                        SecuritySeverity.High,
                        "PE contains a suspicious import combination",
                        BuildImportDetails(
                            imports)));
            }

            var hasCertificate =
                certificateDirectory.Size > 0 &&
                certificateDirectory.Address > 0 &&
                IsValidRange(
                    stream.Length,
                    certificateDirectory.Address,
                    certificateDirectory.Size);

            return new PeStaticAnalysisResult(
                true,
                machine,
                GetMachineName(
                    machine),
                characteristics,
                subsystem,
                GetSubsystemName(
                    subsystem),
                dllCharacteristics,
                entryPoint,
                imageBase,
                sizeOfImage,
                hasCertificate,
                sections,
                imports,
                findings);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            return Invalid(
                logicalPath,
                $"{exception.GetType().Name}: {exception.Message}");
        }
    }

    private async Task<IReadOnlyList<PeImportModule>> ReadImportsAsync(
        Stream stream,
        DirectoryInfo importDirectory,
        uint sizeOfHeaders,
        IReadOnlyList<PeSectionInfo> sections,
        bool pe32Plus,
        CancellationToken cancellationToken)
    {
        if (importDirectory.Address == 0 ||
            importDirectory.Size == 0)
        {
            return [];
        }

        var directoryOffset =
            RvaToFileOffset(
                importDirectory.Address,
                sizeOfHeaders,
                sections);

        if (directoryOffset is null)
        {
            return [];
        }

        var modules =
            new List<PeImportModule>();

        var totalImports =
            0;

        for (var index = 0;
             index < _options.MaxPeImportDescriptors;
             index++)
        {
            var descriptorOffset =
                checked(
                    directoryOffset.Value +
                    index * 20L);

            if (!IsValidRange(
                    stream.Length,
                    descriptorOffset,
                    20))
            {
                break;
            }

            var descriptor =
                await ReadAtAsync(
                    stream,
                    descriptorOffset,
                    20,
                    cancellationToken);

            if (descriptor.All(
                    value =>
                        value == 0))
            {
                break;
            }

            var originalFirstThunk =
                BinaryPrimitives.ReadUInt32LittleEndian(
                    descriptor.AsSpan(
                        0,
                        4));

            var nameRva =
                BinaryPrimitives.ReadUInt32LittleEndian(
                    descriptor.AsSpan(
                        12,
                        4));

            var firstThunk =
                BinaryPrimitives.ReadUInt32LittleEndian(
                    descriptor.AsSpan(
                        16,
                        4));

            var nameOffset =
                RvaToFileOffset(
                    nameRva,
                    sizeOfHeaders,
                    sections);

            if (nameOffset is null)
            {
                continue;
            }

            var moduleName =
                await ReadAsciiStringAsync(
                    stream,
                    nameOffset.Value,
                    _options.MaxPeImportNameBytes,
                    cancellationToken);

            if (string.IsNullOrWhiteSpace(
                    moduleName))
            {
                continue;
            }

            var functions =
                new List<string>();

            var thunkRva =
                originalFirstThunk != 0
                    ? originalFirstThunk
                    : firstThunk;

            var thunkOffset =
                RvaToFileOffset(
                    thunkRva,
                    sizeOfHeaders,
                    sections);

            if (thunkOffset is not null)
            {
                var width =
                    pe32Plus
                        ? 8
                        : 4;

                while (totalImports <
                       _options.MaxPeImports)
                {
                    var currentOffset =
                        checked(
                            thunkOffset.Value +
                            functions.Count *
                            width);

                    if (!IsValidRange(
                            stream.Length,
                            currentOffset,
                            width))
                    {
                        break;
                    }

                    var thunk =
                        await ReadAtAsync(
                            stream,
                            currentOffset,
                            width,
                            cancellationToken);

                    ulong value =
                        pe32Plus
                            ? BinaryPrimitives.ReadUInt64LittleEndian(
                                thunk)
                            : BinaryPrimitives.ReadUInt32LittleEndian(
                                thunk);

                    if (value == 0)
                    {
                        break;
                    }

                    var ordinal =
                        pe32Plus
                            ? (value &
                               0x8000000000000000UL) !=
                              0
                            : (value &
                               0x80000000UL) !=
                              0;

                    totalImports++;

                    if (ordinal)
                    {
                        continue;
                    }

                    var importNameRva =
                        value &
                        (pe32Plus
                            ? 0x7FFFFFFFFFFFFFFFUL
                            : 0x7FFFFFFFUL);

                    if (importNameRva >
                        uint.MaxValue)
                    {
                        continue;
                    }

                    var importNameOffset =
                        RvaToFileOffset(
                            (uint)importNameRva,
                            sizeOfHeaders,
                            sections);

                    if (importNameOffset is null ||
                        !IsValidRange(
                            stream.Length,
                            importNameOffset.Value,
                            2))
                    {
                        continue;
                    }

                    var functionName =
                        await ReadAsciiStringAsync(
                            stream,
                            importNameOffset.Value +
                            2,
                            _options.MaxPeImportNameBytes,
                            cancellationToken);

                    if (!string.IsNullOrWhiteSpace(
                            functionName))
                    {
                        functions.Add(
                            functionName);
                    }
                }
            }

            modules.Add(
                new PeImportModule(
                    moduleName,
                    functions));
        }

        return modules;
    }

    private static bool HasSuspiciousImportCombination(
        IReadOnlyList<PeImportModule> imports)
    {
        var functions =
            imports
                .SelectMany(
                    module =>
                        module.Functions)
                .ToHashSet(
                    StringComparer.OrdinalIgnoreCase);

        var network =
            functions.Contains(
                "URLDownloadToFileW") ||
            functions.Contains(
                "URLDownloadToFileA") ||
            functions.Contains(
                "InternetOpenUrlW") ||
            functions.Contains(
                "InternetOpenUrlA") ||
            functions.Contains(
                "InternetReadFile") ||
            functions.Contains(
                "WinHttpReadData");

        var remoteMemory =
            functions.Contains(
                "VirtualAllocEx") ||
            functions.Contains(
                "WriteProcessMemory") ||
            functions.Contains(
                "NtWriteVirtualMemory");

        var remoteThread =
            functions.Contains(
                "CreateRemoteThread") ||
            functions.Contains(
                "NtCreateThreadEx");

        return network &&
               remoteMemory &&
               remoteThread;
    }

    private static string BuildImportDetails(
        IReadOnlyList<PeImportModule> imports)
    {
        var functions =
            imports
                .SelectMany(
                    module =>
                        module.Functions)
                .Where(
                    name =>
                        name.Equals(
                            "URLDownloadToFileW",
                            StringComparison.OrdinalIgnoreCase) ||
                        name.Equals(
                            "URLDownloadToFileA",
                            StringComparison.OrdinalIgnoreCase) ||
                        name.Equals(
                            "InternetOpenUrlW",
                            StringComparison.OrdinalIgnoreCase) ||
                        name.Equals(
                            "InternetOpenUrlA",
                            StringComparison.OrdinalIgnoreCase) ||
                        name.Equals(
                            "InternetReadFile",
                            StringComparison.OrdinalIgnoreCase) ||
                        name.Equals(
                            "WinHttpReadData",
                            StringComparison.OrdinalIgnoreCase) ||
                        name.Equals(
                            "VirtualAllocEx",
                            StringComparison.OrdinalIgnoreCase) ||
                        name.Equals(
                            "WriteProcessMemory",
                            StringComparison.OrdinalIgnoreCase) ||
                        name.Equals(
                            "CreateRemoteThread",
                            StringComparison.OrdinalIgnoreCase) ||
                        name.Equals(
                            "NtWriteVirtualMemory",
                            StringComparison.OrdinalIgnoreCase) ||
                        name.Equals(
                            "NtCreateThreadEx",
                            StringComparison.OrdinalIgnoreCase))
                .Distinct(
                    StringComparer.OrdinalIgnoreCase);

        return string.Join(
            ", ",
            functions);
    }

    private static DirectoryInfo ReadDirectory(
        byte[] optional,
        uint directoryCount,
        int directoryOffset,
        int index)
    {
        if (directoryCount <=
            index)
        {
            return default;
        }

        var offset =
            directoryOffset +
            index * 8;

        if (offset < 0 ||
            offset >
            optional.Length -
            8)
        {
            return default;
        }

        return new DirectoryInfo(
            BinaryPrimitives.ReadUInt32LittleEndian(
                optional.AsSpan(
                    offset,
                    4)),
            BinaryPrimitives.ReadUInt32LittleEndian(
                optional.AsSpan(
                    offset + 4,
                    4)));
    }

    private static long? RvaToFileOffset(
        uint rva,
        uint sizeOfHeaders,
        IReadOnlyList<PeSectionInfo> sections)
    {
        if (rva <
            sizeOfHeaders)
        {
            return rva;
        }

        foreach (var section in
                 sections)
        {
            var mappedSize =
                Math.Max(
                    section.VirtualSize,
                    section.RawSize);

            var end =
                (ulong)section.VirtualAddress +
                mappedSize;

            if (rva <
                    section.VirtualAddress ||
                rva >=
                    end)
            {
                continue;
            }

            var delta =
                rva -
                section.VirtualAddress;

            if (delta >=
                section.RawSize)
            {
                return null;
            }

            return checked(
                (long)section.RawOffset +
                delta);
        }

        return null;
    }

    private static bool IsEntryPointExecutable(
        uint entryPoint,
        IReadOnlyList<PeSectionInfo> sections)
    {
        foreach (var section in
                 sections)
        {
            if (!section.Executable)
            {
                continue;
            }

            var size =
                Math.Max(
                    section.VirtualSize,
                    section.RawSize);

            var end =
                (ulong)section.VirtualAddress +
                size;

            if (entryPoint >=
                    section.VirtualAddress &&
                entryPoint <
                    end)
            {
                return true;
            }
        }

        return false;
    }

    private static double CalculateEntropy(
        byte[] bytes)
    {
        if (bytes.Length == 0)
        {
            return 0;
        }

        Span<int> frequencies =
            stackalloc int[256];

        foreach (var value in
                 bytes)
        {
            frequencies[value]++;
        }

        var entropy =
            0.0;

        foreach (var count in
                 frequencies)
        {
            if (count == 0)
            {
                continue;
            }

            var probability =
                (double)count /
                bytes.Length;

            entropy -=
                probability *
                Math.Log2(
                    probability);
        }

        return entropy;
    }

    private static string ReadSectionName(
        ReadOnlySpan<byte> bytes)
    {
        var length =
            bytes.IndexOf(
                (byte)0);

        if (length < 0)
        {
            length =
                bytes.Length;
        }

        return Encoding.ASCII.GetString(
            bytes[..length]);
    }

    private static async Task<string> ReadAsciiStringAsync(
        Stream stream,
        long offset,
        int maxLength,
        CancellationToken cancellationToken)
    {
        if (offset < 0 ||
            offset >=
            stream.Length)
        {
            return string.Empty;
        }

        var length =
            (int)Math.Min(
                maxLength,
                stream.Length -
                offset);

        var bytes =
            await ReadAtAsync(
                stream,
                offset,
                length,
                cancellationToken);

        var terminator =
            Array.IndexOf(
                bytes,
                (byte)0);

        if (terminator >= 0)
        {
            length =
                terminator;
        }

        if (length <= 0)
        {
            return string.Empty;
        }

        for (var index = 0;
             index < length;
             index++)
        {
            var value =
                bytes[index];

            if (value < 0x20 ||
                value > 0x7E)
            {
                return string.Empty;
            }
        }

        return Encoding.ASCII.GetString(
            bytes,
            0,
            length);
    }

    private static async Task<byte[]> ReadAtAsync(
        Stream stream,
        long offset,
        int length,
        CancellationToken cancellationToken)
    {
        if (!IsValidRange(
                stream.Length,
                offset,
                length))
        {
            throw new InvalidDataException(
                "Requested PE range exceeds file bounds.");
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

    private static bool IsValidRange(
        long fileLength,
        long offset,
        long size)
    {
        return offset >= 0 &&
               size >= 0 &&
               offset <=
               fileLength &&
               size <=
               fileLength -
               offset;
    }

    private static string GetMachineName(
        ushort machine)
    {
        return machine switch
        {
            0x014C =>
                "x86",

            0x8664 =>
                "x64",

            0x01C4 =>
                "ARM",

            0xAA64 =>
                "ARM64",

            _ =>
                $"0x{machine:X4}"
        };
    }

    private static string GetSubsystemName(
        ushort subsystem)
    {
        return subsystem switch
        {
            1 =>
                "Native",

            2 =>
                "Windows GUI",

            3 =>
                "Windows CUI",

            10 =>
                "EFI Application",

            11 =>
                "EFI Boot Service Driver",

            12 =>
                "EFI Runtime Driver",

            14 =>
                "Xbox",

            16 =>
                "Windows Boot Application",

            _ =>
                subsystem.ToString()
        };
    }

    private static PeStaticAnalysisResult Invalid(
        string logicalPath,
        string message)
    {
        return new PeStaticAnalysisResult(
            false,
            0,
            "Unknown",
            0,
            0,
            "Unknown",
            0,
            0,
            0,
            0,
            false,
            [],
            [],
            [
                new ArchiveScanFinding(
                    ArchiveFindingKind.PeInvalidStructure,
                    ScanVerdict.Error,
                    SecuritySeverity.High,
                    "Invalid PE structure",
                    message)
            ]);
    }

    private readonly record struct DirectoryInfo(
        uint Address,
        uint Size);
}