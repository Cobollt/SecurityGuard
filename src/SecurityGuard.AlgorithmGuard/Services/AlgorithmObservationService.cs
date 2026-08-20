using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Models;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Models;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class AlgorithmObservationService
{
    private readonly IFileHashService _hashService;
    private readonly IProtectedObjectRepository _protectedObjectRepository;
    private readonly IAuthenticodeSignatureService _signatureService;

    public AlgorithmObservationService(
        IFileHashService hashService,
        IProtectedObjectRepository protectedObjectRepository,
        IAuthenticodeSignatureService signatureService)
    {
        _hashService =
            hashService;

        _protectedObjectRepository =
            protectedObjectRepository;

        _signatureService =
            signatureService;
    }

    public async Task<AlgorithmExecutionAttempt> EnrichAsync(
        AlgorithmExecutionAttempt attempt,
        CancellationToken cancellationToken = default)
    {
        var processSignature =
            await GetSignatureAsync(
                attempt.ExecutablePath,
                cancellationToken);

        var enriched =
            attempt with
            {
                ProcessPublisher =
                    processSignature?.Publisher,

                ProcessSignatureStatus =
                    processSignature?.Status
            };

        if (string.IsNullOrWhiteSpace(
                attempt.ScriptPath))
        {
            return enriched;
        }

        if (!Path.IsPathRooted(
                attempt.ScriptPath))
        {
            return enriched;
        }

        if (!File.Exists(
                attempt.ScriptPath))
        {
            return enriched;
        }

        var file =
            new FileInfo(
                attempt.ScriptPath);

        var hash =
            await _hashService.ComputeSha256Async(
                file.FullName,
                cancellationToken);

        var scriptSignature =
            await GetSignatureAsync(
                file.FullName,
                cancellationToken);

        var now =
            DateTimeOffset.UtcNow;

        var existing =
            await _protectedObjectRepository.FindByHashAsync(
                hash,
                cancellationToken);

        var protectedObject =
            new ProtectedObject(
                existing?.Id ??
                Guid.NewGuid(),
                file.FullName,
                file.Name,
                file.Extension,
                hash,
                file.Length,
                existing?.TrustStatus ??
                ObjectTrustStatus.Unknown,
                existing?.FirstSeenAtUtc ??
                now,
                now);

        await _protectedObjectRepository.UpsertAsync(
            protectedObject,
            cancellationToken);

        return enriched with
        {
            ScriptPath =
                file.FullName,

            ScriptSha256 =
                hash,

            ScriptPublisher =
                scriptSignature?.Publisher,

            ScriptSignatureStatus =
                scriptSignature?.Status
        };
    }

    private async Task<AuthenticodeSignatureInfo?> GetSignatureAsync(
        string? filePath,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(
                filePath))
        {
            return null;
        }

        if (!File.Exists(
                filePath))
        {
            return null;
        }

        try
        {
            return await _signatureService.GetAsync(
                filePath,
                cancellationToken);
        }
        catch
        {
            return new AuthenticodeSignatureInfo(
                filePath,
                false,
                false,
                "Error",
                null,
                null);
        }
    }
}