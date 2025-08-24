namespace Miningcore.Blockchain.Hodlcoin;

public class HodlcoinExtraNonceProvider : ExtraNonceProviderBase
{
    public HodlcoinExtraNonceProvider(string poolId, byte? clusterInstanceId) : base(poolId, 4, clusterInstanceId)
    {
    }
}
