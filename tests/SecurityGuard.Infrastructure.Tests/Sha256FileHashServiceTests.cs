using SecurityGuard.Infrastructure.Hashing;

namespace SecurityGuard.Infrastructure.Tests;

public sealed class Sha256FileHashServiceTests
{
    [Fact]
    public async Task Same_content_has_same_hash()
    {
        var directory =
            Path.Combine(
                Path.GetTempPath(),
                Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(directory);

        try
        {
            var first =
                Path.Combine(
                    directory,
                    "first.txt");

            var second =
                Path.Combine(
                    directory,
                    "second.txt");

            await File.WriteAllTextAsync(
                first,
                "SecurityGuard");

            await File.WriteAllTextAsync(
                second,
                "SecurityGuard");

            var service =
                new Sha256FileHashService();

            var firstHash =
                await service.ComputeSha256Async(first);

            var secondHash =
                await service.ComputeSha256Async(second);

            Assert.Equal(
                firstHash,
                secondHash);

            Assert.Equal(
                64,
                firstHash.Length);
        }
        finally
        {
            Directory.Delete(
                directory,
                true);
        }
    }

    [Fact]
    public async Task Different_content_has_different_hash()
    {
        var directory =
            Path.Combine(
                Path.GetTempPath(),
                Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(directory);

        try
        {
            var first =
                Path.Combine(
                    directory,
                    "first.txt");

            var second =
                Path.Combine(
                    directory,
                    "second.txt");

            await File.WriteAllTextAsync(
                first,
                "First");

            await File.WriteAllTextAsync(
                second,
                "Second");

            var service =
                new Sha256FileHashService();

            var firstHash =
                await service.ComputeSha256Async(first);

            var secondHash =
                await service.ComputeSha256Async(second);

            Assert.NotEqual(
                firstHash,
                secondHash);
        }
        finally
        {
            Directory.Delete(
                directory,
                true);
        }
    }
}