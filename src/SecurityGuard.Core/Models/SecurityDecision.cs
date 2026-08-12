using SecurityGuard.Core.Enums;

namespace SecurityGuard.Core.Models;

public sealed record SecurityDecision(
    Guid RequestId,
    SecurityAction Action,
    bool RememberDecision,
    DateTimeOffset DecidedAtUtc);