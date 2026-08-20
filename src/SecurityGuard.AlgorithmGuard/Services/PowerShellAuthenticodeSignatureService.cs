using System.Collections.Concurrent;
using System.Text.Json;
using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class PowerShellAuthenticodeSignatureService
    : IAuthenticodeSignatureService
{
    private readonly PowerShellProcessRunner _runner;

    private readonly ConcurrentDictionary<string, CacheEntry> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    public PowerShellAuthenticodeSignatureService(
        PowerShellProcessRunner runner)
    {
        _runner =
            runner;
    }

    public async Task<AuthenticodeSignatureInfo> GetAsync(
        string filePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            filePath);

        var fullPath =
            Path.GetFullPath(
                filePath);

        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException(
                "File was not found.",
                fullPath);
        }

        var file =
            new FileInfo(
                fullPath);

        if (_cache.TryGetValue(
                fullPath,
                out var cached) &&
            cached.Length == file.Length &&
            cached.LastWriteTimeUtc ==
            file.LastWriteTimeUtc)
        {
            return cached.Value;
        }

        var environment =
            new Dictionary<string, string>
            {
                ["SG_SIGNATURE_FILE"] =
                    fullPath
            };

        var output =
            await _runner.RunEncodedAsync(
                BuildScript(),
                environment,
                cancellationToken);

        var dto =
            JsonSerializer.Deserialize<SignatureDto>(
                output,
                new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

        if (dto is null)
        {
            throw new InvalidOperationException(
                "Unable to parse Authenticode signature information.");
        }

        var status =
            dto.Status ??
            "Unknown";

        var result =
            new AuthenticodeSignatureInfo(
                fullPath,
                dto.HasSignerCertificate,
                string.Equals(
                    status,
                    "Valid",
                    StringComparison.OrdinalIgnoreCase),
                status,
                dto.Publisher,
                dto.Thumbprint);

        _cache[fullPath] =
            new CacheEntry(
                file.Length,
                file.LastWriteTimeUtc,
                result);

        return result;
    }

    private static string BuildScript()
    {
        return
            """
            $ErrorActionPreference = 'Stop'

            $path = $env:SG_SIGNATURE_FILE

            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                throw "Target file was not found."
            }

            $signature =
                Get-AuthenticodeSignature `
                    -LiteralPath $path

            $certificate =
                $signature.SignerCertificate

            $result =
                [PSCustomObject]@{
                    Status =
                        [string]$signature.Status

                    HasSignerCertificate =
                        $null -ne $certificate

                    Publisher =
                        if ($null -ne $certificate) {
                            $certificate.Subject
                        }
                        else {
                            $null
                        }

                    Thumbprint =
                        if ($null -ne $certificate) {
                            $certificate.Thumbprint
                        }
                        else {
                            $null
                        }
                }

            $result |
                ConvertTo-Json `
                    -Compress
            """;
    }

    private sealed record SignatureDto(
        string? Status,
        bool HasSignerCertificate,
        string? Publisher,
        string? Thumbprint);

    private sealed record CacheEntry(
        long Length,
        DateTime LastWriteTimeUtc,
        AuthenticodeSignatureInfo Value);
}