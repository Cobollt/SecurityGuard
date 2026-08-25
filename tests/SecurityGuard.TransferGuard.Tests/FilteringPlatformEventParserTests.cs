using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Monitoring;

namespace SecurityGuard.TransferGuard.Tests;

public sealed class FilteringPlatformEventParserTests
{
    [Fact]
    public void Outbound_tcp_event_is_parsed()
    {
        var parser =
            new FilteringPlatformEventParser();

        var result =
            parser.Parse(
                CreateEvent(
                    "%%14593",
                    "6",
                    "192.168.1.20",
                    "51234",
                    "1.1.1.1",
                    "443"),
                DateTimeOffset.UtcNow);

        Assert.NotNull(
            result);

        Assert.Equal(
            1234,
            result.ProcessId);

        Assert.Equal(
            TransferProtocol.Tcp,
            result.Protocol);

        Assert.Equal(
            "1.1.1.1",
            result.RemoteAddress);

        Assert.Equal(
            443,
            result.RemotePort);
    }

    [Fact]
    public void Outbound_udp_event_is_parsed()
    {
        var parser =
            new FilteringPlatformEventParser();

        var result =
            parser.Parse(
                CreateEvent(
                    "%%14593",
                    "17",
                    "192.168.1.20",
                    "53000",
                    "8.8.8.8",
                    "53"),
                DateTimeOffset.UtcNow);

        Assert.NotNull(
            result);

        Assert.Equal(
            TransferProtocol.Udp,
            result.Protocol);

        Assert.Equal(
            53,
            result.RemotePort);
    }

    [Fact]
    public void Inbound_event_is_ignored()
    {
        var parser =
            new FilteringPlatformEventParser();

        var result =
            parser.Parse(
                CreateEvent(
                    "%%14592",
                    "6",
                    "192.168.1.20",
                    "443",
                    "192.168.1.50",
                    "52000"),
                DateTimeOffset.UtcNow);

        Assert.Null(
            result);
    }

    private static string CreateEvent(
        string direction,
        string protocol,
        string sourceAddress,
        string sourcePort,
        string destinationAddress,
        string destinationPort)
    {
        return
            $"""
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <System>
                <EventID>5156</EventID>
              </System>
              <EventData>
                <Data Name="ProcessID">1234</Data>
                <Data Name="Application">\device\harddiskvolume3\test.exe</Data>
                <Data Name="Direction">{direction}</Data>
                <Data Name="SourceAddress">{sourceAddress}</Data>
                <Data Name="SourcePort">{sourcePort}</Data>
                <Data Name="DestAddress">{destinationAddress}</Data>
                <Data Name="DestPort">{destinationPort}</Data>
                <Data Name="Protocol">{protocol}</Data>
              </EventData>
            </Event>
            """;
    }
}