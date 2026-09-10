using System.Security.Cryptography;
using SecurityGuard.ArchiveGuard.Configuration;
using SecurityGuard.ArchiveGuard.Exceptions;
using SecurityGuard.ArchiveGuard.Services;
using SecurityGuard.Core.Contracts;

namespace SecurityGuard.ArchiveGuard.Tests;

public sealed class ArchiveFileMetadataServiceTests
{
    [Fact]
    public async Task Stable_file_is_loaded()
    {
        var root =
            ArchiveGuardTestFactory.CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "test.bin");

            await File.WriteAllTextAsync(
                file,
                "SecurityGuard");

            var service =
                new ArchiveFileMetadataService(
                    new NormalHashService(),
                    new FileTypeDetector(),
                    new ArchiveGuardOptions());

            var metadata =
                await service.LoadAsync(
                    file);

            Assert.Equal(
                Path.GetFullPath(
                    file),
                metadata.FilePath);

            Assert.False(
                string.IsNullOrWhiteSpace(
                    metadata.Sha256));
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    [Fact]
    public async Task File_mutation_is_detected()
    {
        var root =
            ArchiveGuardTestFactory.CreateTemporaryDirectory();

        try
        {
            var file =
                Path.Combine(
                    root,
                    "test.bin");

            await File.WriteAllTextAsync(
                file,
                "A");

            var service =
                new ArchiveFileMetadataService(
                    new MutatingHashService(),
                    new FileTypeDetector(),
                    new ArchiveGuardOptions
                    {
                        MaxFileMutationRetries =
                            0
                    });

            await Assert.ThrowsAsync<
                ArchiveFileChangedException>(
                    () =>
                        service.LoadAsync(
                            file));
        }
        finally
        {
            Directory.Delete(
                root,
                true);
        }
    }

    private sealed class NormalHashService
        : IFileHashService
    {
        public async Task<string> ComputeSha256Async(
            string filePath,
            CancellationToken cancellationToken = default)
        {
            await using var stream =
                File.OpenRead(
                    filePath);

            var hash =
                await SHA256.HashDataAsync(
                    stream,
                    cancellationToken);

            return Convert.ToHexString(
                hash);
        }
    }

    private sealed class MutatingHashService
        : IFileHashService
    {
        public async Task<string> ComputeSha256Async(
            string filePath,
            CancellationToken cancellationToken = default)
        {
            var original =
                await File.ReadAllBytesAsync(
                    filePath,
                    cancellationToken);

            await File.AppendAllTextAsync(
                filePath,
                "B",
                cancellationToken);

            return Convert.ToHexString(
                SHA256.HashData(
                    original));
        }
    }
}