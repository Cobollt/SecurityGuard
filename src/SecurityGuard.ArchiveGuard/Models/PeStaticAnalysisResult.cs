namespace SecurityGuard.ArchiveGuard.Models;

public sealed record PeStaticAnalysisResult(
    bool IsValid,
    ushort Machine,
    string MachineName,
    ushort Characteristics,
    ushort Subsystem,
    string SubsystemName,
    ushort DllCharacteristics,
    uint AddressOfEntryPoint,
    ulong ImageBase,
    uint SizeOfImage,
    bool HasEmbeddedCertificateTable,
    IReadOnlyList<PeSectionInfo> Sections,
    IReadOnlyList<PeImportModule> Imports,
    IReadOnlyList<ArchiveScanFinding> Findings);