using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferRuleContextFactory
{
    public RuleMatchContext Create(
        NetworkConnectionObservation observation)
    {
        ArgumentNullException.ThrowIfNull(
            observation);

        var processPath =
            !string.IsNullOrWhiteSpace(
                observation.Process?.ExecutablePath)
                    ? observation.Process.ExecutablePath
                    : observation.ApplicationPath;

        return new RuleMatchContext(
            Process:
                observation.Process?.ProcessName,

            ProcessPath:
                processPath,

            RemoteAddress:
                observation.RemoteAddress,

            RemotePort:
                observation.RemotePort,

            Protocol:
                observation.Protocol.ToString());
    }
}