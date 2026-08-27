using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Xml.Linq;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Monitoring;

public sealed class FilteringPlatformEventParser
{
    private const string OutboundCode =
        "%%14593";

    public FilteringPlatformConnectionEvent? Parse(
        string xml,
        DateTimeOffset detectedAtUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            xml);

        var document =
            XDocument.Parse(
                xml);

        XNamespace ns =
            "http://schemas.microsoft.com/win/2004/08/events/event";

        var data =
            document
                .Descendants(
                    ns + "Data")
                .Where(
                    element =>
                        element.Attribute(
                            "Name") is not null)
                .ToDictionary(
                    element =>
                        element.Attribute(
                            "Name")!.Value,
                    element =>
                        element.Value,
                    StringComparer.OrdinalIgnoreCase);

        if (!data.TryGetValue(
                "Direction",
                out var direction))
        {
            return null;
        }

        if (!IsOutbound(
                direction))
        {
            return null;
        }

        if (!TryReadProcessId(
                data,
                out var processId))
        {
            return null;
        }

        if (!data.TryGetValue(
                "Protocol",
                out var protocolText) ||
            !int.TryParse(
                protocolText,
                CultureInfo.InvariantCulture,
                out var protocolNumber))
        {
            return null;
        }

        var protocol =
            protocolNumber switch
            {
                6 =>
                    TransferProtocol.Tcp,

                17 =>
                    TransferProtocol.Udp,

                _ =>
                    (TransferProtocol?)null
            };

        if (protocol is null)
        {
            return null;
        }

        if (!TryGetEndpoint(
                data,
                "SourceAddress",
                "SourcePort",
                out var localAddress,
                out var localPort))
        {
            return null;
        }

        if (!TryGetEndpoint(
                data,
                "DestAddress",
                "DestPort",
                out var remoteAddress,
                out var remotePort))
        {
            return null;
        }

        var family =
            GetAddressFamily(
                remoteAddress);

        data.TryGetValue(
            "Application",
            out var applicationPath);

        return new FilteringPlatformConnectionEvent(
            detectedAtUtc,
            processId,
            applicationPath,
            protocol.Value,
            family,
            localAddress,
            localPort,
            remoteAddress,
            remotePort);
    }

    private static bool IsOutbound(
        string direction)
    {
        return string.Equals(
                   direction,
                   OutboundCode,
                   StringComparison.OrdinalIgnoreCase) ||
               string.Equals(
                   direction,
                   "Outbound",
                   StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryReadProcessId(
        IReadOnlyDictionary<string, string> data,
        out int processId)
    {
        processId =
            0;

        if (!data.TryGetValue(
                "ProcessID",
                out var value) &&
            !data.TryGetValue(
                "ProcessId",
                out value))
        {
            return false;
        }

        if (value.StartsWith(
                "0x",
                StringComparison.OrdinalIgnoreCase))
        {
            return int.TryParse(
                value[2..],
                NumberStyles.HexNumber,
                CultureInfo.InvariantCulture,
                out processId);
        }

        return int.TryParse(
            value,
            NumberStyles.Integer,
            CultureInfo.InvariantCulture,
            out processId);
    }

    private static bool TryGetEndpoint(
        IReadOnlyDictionary<string, string> data,
        string addressKey,
        string portKey,
        out string address,
        out int port)
    {
        address =
            string.Empty;

        port =
            0;

        if (!data.TryGetValue(
                addressKey,
                out var addressValue) ||
            string.IsNullOrWhiteSpace(
                addressValue))
        {
            return false;
        }

        address =
            addressValue;

        if (!data.TryGetValue(
                portKey,
                out var portText))
        {
            return false;
        }

        return int.TryParse(
            portText,
            NumberStyles.Integer,
            CultureInfo.InvariantCulture,
            out port);
    }

    private static NetworkAddressFamily GetAddressFamily(
        string address)
    {
        if (!IPAddress.TryParse(
                address,
                out var ip))
        {
            return NetworkAddressFamily.IPv4;
        }

        return ip.AddressFamily ==
               AddressFamily.InterNetworkV6
            ? NetworkAddressFamily.IPv6
            : NetworkAddressFamily.IPv4;
    }
}