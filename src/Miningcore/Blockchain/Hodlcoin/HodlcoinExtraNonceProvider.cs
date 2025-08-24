namespace Miningcore.Blockchain.Hodlcoin;

public class BitcoinExtraNonceProvider : ExtraNonceProviderBase
{
    public BitcoinExtraNonceProvider(string poolId, byte? clusterInstanceId) : base(poolId, 4, clusterInstanceId)
    {
    }
}
