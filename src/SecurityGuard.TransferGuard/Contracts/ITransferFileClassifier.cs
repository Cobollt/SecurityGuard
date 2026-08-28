using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Contracts;

public interface ITransferFileClassifier
{
    TransferFileClassification Classify(
        string filePath);
}