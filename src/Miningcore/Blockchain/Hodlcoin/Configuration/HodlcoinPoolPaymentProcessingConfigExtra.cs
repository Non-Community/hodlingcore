namespace Miningcore.Blockchain.Hodlcoin.Configuration;

public class HodlcoinPoolPaymentProcessingConfigExtra
{
    /// <summary>
    /// Wallet Password if the daemon is running with an encrypted wallet (used for unlocking wallet during payment processing)
    /// </summary>
    public string WalletPassword { get; set; }

    /// <summary>
    /// if True, miners pay payment tx fees
    /// </summary>
    public bool MinersPayTxFees { get; set; }
}
