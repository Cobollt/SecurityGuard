using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferCorrelationConfidenceCalculator
{
    public TransferCorrelationAssessment Calculate(
        RecentFileRead file,
        RecentNetworkSend send,
        long? fileSize)
    {
        ArgumentNullException.ThrowIfNull(
            file);

        ArgumentNullException.ThrowIfNull(
            send);

        var difference =
            (file.LastReadAtUtc -
             send.LastSendAtUtc)
            .Duration();

        var similarity =
            CalculateVolumeSimilarity(
                file.ObservedReadBytes,
                send.ObservedSentBytes);

        var score =
            0;

        if (difference <=
            TimeSpan.FromSeconds(1))
        {
            score +=
                3;
        }
        else if (difference <=
                 TimeSpan.FromSeconds(3))
        {
            score +=
                2;
        }
        else if (difference <=
                 TimeSpan.FromSeconds(8))
        {
            score +=
                1;
        }

        if (file.ObservedReadBytes >=
                64L * 1024L &&
            send.ObservedSentBytes >=
                64L * 1024L)
        {
            score +=
                2;
        }
        else if (file.ObservedReadBytes >=
                     4L * 1024L &&
                 send.ObservedSentBytes >=
                     4L * 1024L)
        {
            score +=
                1;
        }

        if (similarity >=
            0.80)
        {
            score +=
                3;
        }
        else if (similarity >=
                 0.50)
        {
            score +=
                2;
        }
        else if (similarity >=
                 0.25)
        {
            score +=
                1;
        }

        if (fileSize is > 0)
        {
            var readRatio =
                Math.Min(
                    1.0,
                    (double)file.ObservedReadBytes /
                    fileSize.Value);

            if (readRatio >=
                0.80)
            {
                score +=
                    1;
            }
        }

        var confidence =
            score switch
            {
                >= 8 =>
                    TransferCorrelationConfidence.High,

                >= 5 =>
                    TransferCorrelationConfidence.Medium,

                _ =>
                    TransferCorrelationConfidence.Low
            };

        return new TransferCorrelationAssessment(
            confidence,
            similarity);
    }

    private static double CalculateVolumeSimilarity(
        long readBytes,
        long sentBytes)
    {
        if (readBytes <= 0 ||
            sentBytes <= 0)
        {
            return 0;
        }

        var smaller =
            Math.Min(
                readBytes,
                sentBytes);

        var larger =
            Math.Max(
                readBytes,
                sentBytes);

        return (double)smaller /
               larger;
    }
}