using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using Miningcore.Blockchain.Hodlcoin.Configuration;
using Miningcore.Blockchain.Hodlcoin.DaemonResponses;
using Miningcore.Configuration;
using Miningcore.Contracts;
using Miningcore.Crypto;
using Miningcore.Extensions;
using Miningcore.Stratum;
using Miningcore.Time;
using Miningcore.Util;
using NBitcoin;
using NBitcoin.DataEncoders;
using Newtonsoft.Json.Linq;
using Transaction = NBitcoin.Transaction;

namespace Miningcore.Blockchain.Hodlcoin;

public class HodlcoinJob
{
    protected IHashAlgorithm blockHasher;
    protected IMasterClock clock;
    protected IHashAlgorithm coinbaseHasher;
    protected double shareMultiplier;
    protected int extraNoncePlaceHolderLength;
    protected IHashAlgorithm headerHasher;
    protected bool isPoS;
    protected string txComment;

    protected PayeeBlockTemplateExtra payeeParameters;
    protected MasterNodeBlockTemplateExtra masterNodeParameters;
    protected FounderBlockTemplateExtra founderParameters;
    protected MinerFundTemplateExtra minerFundParameters;

    protected Network network;
    protected IDestination poolAddressDestination;
    protected HodlcoinTemplate coin;
    private HodlcoinTemplate.HodlcoinNetworkParams networkParams;

    protected readonly ConcurrentDictionary<string, bool> submissions = new(StringComparer.OrdinalIgnoreCase);
    protected uint256 blockTargetValue;
    protected byte[] coinbaseFinal;
    protected string coinbaseFinalHex;
    protected byte[] coinbaseInitial;
    protected string coinbaseInitialHex;
    protected string[] merkleBranchesHex;
    protected MerkleTree mt;

    // --- HODL: two 4-byte extensions appended to the 80-byte header ---
    private uint birthdayA;
    private uint birthdayB;

    ///////////////////////////////////////////
    // GetJobParams related properties

    protected object[] jobParams;
    protected string previousBlockHashReversedHex;
    protected Money rewardToPool;
    protected Transaction txOut;

    // serialization constants
    protected byte[] scriptSigFinalBytes;

    protected static readonly byte[] sha256Empty = new byte[32];
    protected uint txVersion = 1u; // coinbase tx version

    protected static uint txInputCount = 1u;
    protected static readonly uint txInPrevOutIndex = uint.MaxValue;
    protected static uint txInSequence;
    protected static uint txLockTime;

    #region Template helpers (HODL birthdays)

    public void SetBirthdaysFromTemplate(BlockTemplate tpl)
    {
        birthdayA = TryGetUintTemplateExtra(tpl, "birthdayA")
                 ?? TryGetUintTemplateExtra(tpl, "nBirthdayA")
                 ?? TryGetUintTemplateExtra(tpl, "birthday_a")
                 ?? 0u;

        birthdayB = TryGetUintTemplateExtra(tpl, "birthdayB")
                 ?? TryGetUintTemplateExtra(tpl, "nBirthdayB")
                 ?? TryGetUintTemplateExtra(tpl, "birthday_b")
                 ?? 0u;
    }

    private static uint? TryGetUintTemplateExtra(BlockTemplate tpl, string key)
    {
        if (tpl?.Extra is JObject jo && jo.TryGetValue(key, StringComparison.OrdinalIgnoreCase, out var tok))
        {
            if (tok.Type == JTokenType.Integer)
                return (uint) tok.Value<long>();

            if (tok.Type == JTokenType.String &&
                uint.TryParse(tok.Value<string>(), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v))
                return v;
        }
        return null;
    }

    #endregion

    #region Coinbase, Merkle, Block serialization

    protected virtual void BuildMerkleBranches()
    {
        var transactionHashes = BlockTemplate.Transactions
            .Select(tx => (tx.TxId ?? tx.Hash).HexToByteArray().ReverseInPlace())
            .ToArray();

        mt = new MerkleTree(transactionHashes);

        merkleBranchesHex = mt.Steps
            .Select(x => x.ToHexString())
            .ToArray();
    }

    protected virtual void BuildCoinbase()
    {
        // scriptSig initial part
        var sigScriptInitial = GenerateScriptSigInitial();
        var sigScriptInitialBytes = sigScriptInitial.ToBytes();

        var sigScriptLength = (uint)(
            sigScriptInitial.Length +
            extraNoncePlaceHolderLength +
            scriptSigFinalBytes.Length);

        // output transaction
        txOut = CreateOutputTransaction();

        // coinbase initial
        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            // version
            bs.ReadWrite(ref txVersion);

            // POS coins embed timestamp in tx
            if(isPoS)
            {
                var timestamp = BlockTemplate.CurTime;
                bs.ReadWrite(ref timestamp);
            }

            // input
            bs.ReadWriteAsVarInt(ref txInputCount);
            bs.ReadWrite(ref sha256Empty);
            bs.ReadWrite(ref txInPrevOutIndex);

            // signature script initial
            bs.ReadWriteAsVarInt(ref sigScriptLength);
            bs.ReadWrite(ref sigScriptInitialBytes);

            coinbaseInitial = stream.ToArray();
            coinbaseInitialHex = coinbaseInitial.ToHexString();
        }

        // coinbase final
        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            // signature script final
            bs.ReadWrite(ref scriptSigFinalBytes);

            // sequence
            bs.ReadWrite(ref txInSequence);

            // outputs
            var txOutBytes = SerializeOutputTransaction(txOut);
            bs.ReadWrite(ref txOutBytes);

            // locktime
            bs.ReadWrite(ref txLockTime);

            // extension point
            AppendCoinbaseFinal(bs);

            coinbaseFinal = stream.ToArray();
            coinbaseFinalHex = coinbaseFinal.ToHexString();
        }
    }

    protected virtual void AppendCoinbaseFinal(BitcoinStream bs)
    {
        if(!string.IsNullOrEmpty(txComment))
        {
            var data = Encoding.ASCII.GetBytes(txComment);
            bs.ReadWriteAsVarString(ref data);
        }

        if(coin.HasMasterNodes && !string.IsNullOrEmpty(masterNodeParameters.CoinbasePayload))
        {
            var data = masterNodeParameters.CoinbasePayload.HexToByteArray();
            bs.ReadWriteAsVarString(ref data);
        }
    }

    protected virtual byte[] SerializeOutputTransaction(Transaction tx)
    {
        var withDefaultWitnessCommitment = !string.IsNullOrEmpty(BlockTemplate.DefaultWitnessCommitment);

        var outputCount = (uint) tx.Outputs.Count;
        if(withDefaultWitnessCommitment)
            outputCount++;

        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            // count
            bs.ReadWriteAsVarInt(ref outputCount);

            long amount;
            byte[] raw;
            uint rawLength;

            // witness (segwit)
            if(withDefaultWitnessCommitment)
            {
                amount = 0;
                raw = BlockTemplate.DefaultWitnessCommitment.HexToByteArray();
                rawLength = (uint) raw.Length;

                bs.ReadWrite(ref amount);
                bs.ReadWriteAsVarInt(ref rawLength);
                bs.ReadWrite(ref raw);
            }

            // outputs
            foreach(var output in tx.Outputs)
            {
                amount = output.Value.Satoshi;
                var outScript = output.ScriptPubKey;
                raw = outScript.ToBytes(true);
                rawLength = (uint) raw.Length;

                bs.ReadWrite(ref amount);
                bs.ReadWriteAsVarInt(ref rawLength);
                bs.ReadWrite(ref raw);
            }

            return stream.ToArray();
        }
    }

    protected virtual Script GenerateScriptSigInitial()
    {
        var now = ((DateTimeOffset) clock.Now).ToUnixTimeSeconds();

        var ops = new List<Op>();

        // block height
        ops.Add(Op.GetPushOp(BlockTemplate.Height));

        // aux-flags
        if(!coin.CoinbaseIgnoreAuxFlags && !string.IsNullOrEmpty(BlockTemplate.CoinbaseAux?.Flags))
            ops.Add(Op.GetPushOp(BlockTemplate.CoinbaseAux.Flags.HexToByteArray()));

        // timestamp
        ops.Add(Op.GetPushOp(now));

        // extranonce placeholder
        ops.Add(Op.GetPushOp(0));

        return new Script(ops);
    }

    protected virtual Transaction CreateOutputTransaction()
    {
        rewardToPool = new Money(BlockTemplate.CoinbaseValue, MoneyUnit.Satoshi);
        var tx = Transaction.Create(network);

        if(coin.HasPayee)
            rewardToPool = CreatePayeeOutput(tx, rewardToPool);

        if(coin.HasMasterNodes)
            rewardToPool = CreateMasternodeOutputs(tx, rewardToPool);

        if(coin.HasFounderFee)
            rewardToPool = CreateFounderOutputs(tx, rewardToPool);

        if(coin.HasMinerFund)
            rewardToPool = CreateMinerFundOutputs(tx, rewardToPool);

        // remainder to pool
        tx.Outputs.Add(rewardToPool, poolAddressDestination);

        return tx;
    }

    protected virtual Money CreatePayeeOutput(Transaction tx, Money reward)
    {
        if(payeeParameters?.PayeeAmount != null && payeeParameters.PayeeAmount.Value > 0)
        {
            var payeeReward = new Money(payeeParameters.PayeeAmount.Value, MoneyUnit.Satoshi);
            reward -= payeeReward;

            tx.Outputs.Add(payeeReward, BitcoinUtils.AddressToDestination(payeeParameters.Payee, network));
        }

        return reward;
    }

    protected bool RegisterSubmit(string extraNonce1, string extraNonce2, string nTime, string nonce)
    {
        var key = new StringBuilder()
            .Append(extraNonce1)
            .Append(extraNonce2)
            .Append(nTime)
            .Append(nonce)
            .ToString();

        return submissions.TryAdd(key, true);
    }

    /// <summary>
    /// HODL: serialize 88-byte header [ver|prev|merkle|time|bits|nonce|birthdayA|birthdayB]
    /// </summary>
    protected virtual byte[] SerializeHeader(Span<byte> coinbaseHash, uint nTime, uint nonce, uint? versionMask, uint? versionBits)
    {
        // merkle (internal)
        var merkleRoot = mt.WithFirst(coinbaseHash.ToArray());

        // version (with optional version-rolling)
        var version = BlockTemplate.Version;
        if(versionMask.HasValue && versionBits.HasValue)
            version = (version & ~versionMask.Value) | (versionBits.Value & versionMask.Value);

        // prevhash (internal bytes)
        var prevHash = uint256.Parse(BlockTemplate.PreviousBlockhash).ToBytes();

        // bits (compact) as uint32
        var bitsCompact = new Target(Encoders.Hex.DecodeData(BlockTemplate.Bits)).ToCompact();

        var header = new byte[88];
        var span = header.AsSpan();

        BinaryPrimitives.WriteInt32LittleEndian(span.Slice(0, 4), version);
        prevHash.CopyTo(span.Slice(4, 32));
        merkleRoot.CopyTo(span.Slice(36, 32));
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(68, 4), nTime);
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(72, 4), bitsCompact);
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(76, 4), nonce);
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(80, 4), birthdayA);
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(84, 4), birthdayB);

        return header;
    }

    protected virtual (Share Share, string BlockHex) ProcessShareInternal(
        StratumConnection worker, string extraNonce2, uint nTime, uint nonce, uint? versionBits)
    {
        var context = worker.ContextAs<HodlcoinWorkerContext>();
        var extraNonce1 = context.ExtraNonce1;

        // coinbase
        var coinbase = SerializeCoinbase(extraNonce1, extraNonce2);
        Span<byte> coinbaseHash = stackalloc byte[32];
        coinbaseHasher.Digest(coinbase, coinbaseHash);

        // header (88 bytes) & hash
        var headerBytes = SerializeHeader(coinbaseHash, nTime, nonce, context.VersionRollingMask, versionBits);
        Span<byte> headerHash = stackalloc byte[32];
        headerHasher.Digest(headerBytes, headerHash, nTime, BlockTemplate, coin, networkParams);
        var headerValue = new uint256(headerHash);

        // share difficulty
        var shareDiff = (double) new BigRational(HodlcoinConstants.Diff1, headerHash.ToBigInteger()) * shareMultiplier;
        var stratumDifficulty = context.Difficulty;
        var ratio = shareDiff / stratumDifficulty;

        // block candidate?
        var isBlockCandidate = headerValue <= blockTargetValue;

        // meets miner diff?
        if(!isBlockCandidate && ratio < 0.99)
        {
            if(context.VarDiff?.LastUpdate != null && context.PreviousDifficulty.HasValue)
            {
                ratio = shareDiff / context.PreviousDifficulty.Value;
                if(ratio < 0.99)
                    throw new StratumException(StratumError.LowDifficultyShare, $"low difficulty share ({shareDiff})");

                stratumDifficulty = context.PreviousDifficulty.Value;
            }
            else
                throw new StratumException(StratumError.LowDifficultyShare, $"low difficulty share ({shareDiff})");
        }

        var result = new Share
        {
            BlockHeight = BlockTemplate.Height,
            NetworkDifficulty = Difficulty,
            Difficulty = stratumDifficulty / shareMultiplier,
        };

        if(isBlockCandidate)
        {
            result.IsBlockCandidate = true;

            Span<byte> blockHash = stackalloc byte[32];
            blockHasher.Digest(headerBytes, blockHash, nTime);
            result.BlockHash = blockHash.ToHexString();

            var blockBytes = SerializeBlock(headerBytes, coinbase);
            var blockHex = blockBytes.ToHexString();

            return (result, blockHex);
        }

        return (result, null);
    }

    protected virtual byte[] SerializeCoinbase(string extraNonce1, string extraNonce2)
    {
        var extraNonce1Bytes = extraNonce1.HexToByteArray();
        var extraNonce2Bytes = extraNonce2.HexToByteArray();

        using(var stream = new MemoryStream())
        {
            stream.Write(coinbaseInitial);
            stream.Write(extraNonce1Bytes);
            stream.Write(extraNonce2Bytes);
            stream.Write(coinbaseFinal);
            return stream.ToArray();
        }
    }

    protected virtual byte[] SerializeBlock(byte[] header, byte[] coinbase)
    {
        var rawTransactionBuffer = BuildRawTransactionBuffer();
        var transactionCount = (uint) BlockTemplate.Transactions.Length + 1; // + coinbase

        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            bs.ReadWrite(ref header);
            bs.ReadWriteAsVarInt(ref transactionCount);
            bs.ReadWrite(ref coinbase);
            bs.ReadWrite(ref rawTransactionBuffer);

            // POS coins: append zero byte (daemon replaces with signature)
            if(isPoS)
                bs.ReadWrite((byte) 0);

            return stream.ToArray();
        }
    }

    protected virtual byte[] BuildRawTransactionBuffer()
    {
        using var stream = new MemoryStream();
        foreach(var tx in BlockTemplate.Transactions)
            stream.Write(tx.Data.HexToByteArray());
        return stream.ToArray();
    }

    #endregion

    #region Masternodes/Founder/MinerFund

    protected virtual Money CreateMasternodeOutputs(Transaction tx, Money reward)
    {
        if(masterNodeParameters.Masternode != null)
        {
            Masternode[] masternodes;

            if(masterNodeParameters.Masternode.Type == JTokenType.Array)
                masternodes = masterNodeParameters.Masternode.ToObject<Masternode[]>();
            else
                masternodes = new[] { masterNodeParameters.Masternode.ToObject<Masternode>() };

            if(masternodes != null)
            {
                foreach(var mn in masternodes)
                {
                    if(!string.IsNullOrEmpty(mn.Payee))
                    {
                        var payeeDestination = BitcoinUtils.AddressToDestination(mn.Payee, network);
                        var payeeReward = mn.Amount;

                        tx.Outputs.Add(payeeReward, payeeDestination);
                        reward -= payeeReward;
                    }
                }
            }
        }

        if(masterNodeParameters.SuperBlocks is { Length: > 0 })
        {
            foreach(var superBlock in masterNodeParameters.SuperBlocks)
            {
                var payeeAddress = BitcoinUtils.AddressToDestination(superBlock.Payee, network);
                var payeeReward = superBlock.Amount;

                tx.Outputs.Add(payeeReward, payeeAddress);
                reward -= payeeReward;
            }
        }

        if(!coin.HasPayee && !string.IsNullOrEmpty(masterNodeParameters.Payee))
        {
            var payeeAddress = BitcoinUtils.AddressToDestination(masterNodeParameters.Payee, network);
            var payeeReward = masterNodeParameters.PayeeAmount;

            tx.Outputs.Add(payeeReward, payeeAddress);
            reward -= payeeReward;
        }

        return reward;
    }

    protected virtual Money CreateFounderOutputs(Transaction tx, Money reward)
    {
        if (founderParameters.Founder != null)
        {
            Founder[] founders;

            if (founderParameters.Founder.Type == JTokenType.Array)
                founders = founderParameters.Founder.ToObject<Founder[]>();
            else
                founders = new[] { founderParameters.Founder.ToObject<Founder>() };

            if(founders != null)
            {
                foreach(var f in founders)
                {
                    if(!string.IsNullOrEmpty(f.Payee))
                    {
                        var payeeAddress = BitcoinUtils.AddressToDestination(f.Payee, network);
                        var payeeReward = f.Amount;

                        tx.Outputs.Add(payeeReward, payeeAddress);
                        reward -= payeeReward;
                    }
                }
            }
        }

        return reward;
    }

    protected virtual Money CreateMinerFundOutputs(Transaction tx, Money reward)
    {
        var payeeReward = minerFundParameters.MinimumValue;

        var addr = minerFundParameters.Addresses?.FirstOrDefault();
        if (!string.IsNullOrEmpty(addr))
        {
            var payeeAddress = BitcoinUtils.AddressToDestination(addr, network);
            tx.Outputs.Add(payeeReward, payeeAddress);
        }

        reward -= payeeReward;
        return reward;
    }

    #endregion

    #region API Surface

    public BlockTemplate BlockTemplate { get; protected set; }
    public double Difficulty { get; protected set; }
    public string JobId { get; protected set; }

    public void Init(BlockTemplate blockTemplate, string jobId,
        PoolConfig pc, HodlcoinPoolConfigExtra extraPoolConfig,
        ClusterConfig cc, IMasterClock clock,
        IDestination poolAddressDestination, Network network,
        bool isPoS, double shareMultiplier, IHashAlgorithm coinbaseHasher,
        IHashAlgorithm headerHasher, IHashAlgorithm blockHasher)
    {
        Contract.RequiresNonNull(blockTemplate);
        Contract.RequiresNonNull(pc);
        Contract.RequiresNonNull(cc);
        Contract.RequiresNonNull(clock);
        Contract.RequiresNonNull(poolAddressDestination);
        Contract.RequiresNonNull(coinbaseHasher);
        Contract.RequiresNonNull(headerHasher);
        Contract.RequiresNonNull(blockHasher);
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(jobId));

        coin = pc.Template.As<HodlcoinTemplate>();
        networkParams = coin.GetNetwork(network.ChainName);
        txVersion = coin.CoinbaseTxVersion;

        this.network = network;
        this.clock = clock;
        this.poolAddressDestination = poolAddressDestination;
        BlockTemplate = blockTemplate;
        JobId = jobId;

        var coinbaseString = !string.IsNullOrEmpty(cc.PaymentProcessing?.CoinbaseString)
            ? cc.PaymentProcessing.CoinbaseString.Trim()
            : "Miningcore";

        scriptSigFinalBytes = new Script(Op.GetPushOp(Encoding.UTF8.GetBytes(coinbaseString))).ToBytes();

        Difficulty = new Target(System.Numerics.BigInteger.Parse(BlockTemplate.Target, NumberStyles.HexNumber)).Difficulty;

        extraNoncePlaceHolderLength = HodlcoinConstants.ExtranoncePlaceHolderLength;
        this.isPoS = isPoS;
        this.shareMultiplier = shareMultiplier;

        txComment = !string.IsNullOrEmpty(extraPoolConfig?.CoinbaseTxComment)
            ? extraPoolConfig.CoinbaseTxComment
            : coin.CoinbaseTxComment;

        if(coin.HasMasterNodes)
        {
            masterNodeParameters = BlockTemplate.Extra.SafeExtensionDataAs<MasterNodeBlockTemplateExtra>();

            if(!string.IsNullOrEmpty(masterNodeParameters.CoinbasePayload))
            {
                txVersion = 3;
                const uint txType = 5;
                txVersion += txType << 16;
            }
        }

        if(coin.HasPayee)
            payeeParameters = BlockTemplate.Extra.SafeExtensionDataAs<PayeeBlockTemplateExtra>();

        if(coin.HasFounderFee)
            founderParameters = BlockTemplate.Extra.SafeExtensionDataAs<FounderBlockTemplateExtra>();

        if(coin.HasMinerFund)
            minerFundParameters = BlockTemplate.Extra.SafeExtensionDataAs<MinerFundTemplateExtra>("coinbasetxn", "minerfund");

        this.coinbaseHasher = coinbaseHasher;
        this.headerHasher = headerHasher;
        this.blockHasher = blockHasher;

        if(!string.IsNullOrEmpty(BlockTemplate.Target))
            blockTargetValue = new uint256(BlockTemplate.Target);
        else
        {
            var tmp = new Target(BlockTemplate.Bits.HexToByteArray());
            blockTargetValue = tmp.ToUInt256();
        }

        previousBlockHashReversedHex = BlockTemplate.PreviousBlockhash
            .HexToByteArray()
            .ReverseByteOrder()
            .ToHexString();

        // Build merkle, coinbase, and pick up per-job birthdays
        BuildMerkleBranches();
        BuildCoinbase();
        SetBirthdaysFromTemplate(BlockTemplate);

        jobParams = new object[]
        {
            JobId,
            previousBlockHashReversedHex,
            coinbaseInitialHex,
            coinbaseFinalHex,
            merkleBranchesHex,
            BlockTemplate.Version.ToStringHex8(),
            BlockTemplate.Bits,
            BlockTemplate.CurTime.ToStringHex8(),
            false
        };
    }

    public object GetJobParams(bool isNew)
    {
        jobParams[^1] = isNew;
        return jobParams;
    }

    /// <summary>
    /// Accepts optional versionBits and (HODL) optional birthdayA/birthdayB (hex, LE).
    /// </summary>
    public virtual (Share Share, string BlockHex) ProcessShare(StratumConnection worker,
        string extraNonce2, string nTime, string nonce, string versionBits = null,
        string birthdayAHex = null, string birthdayBHex = null)
    {
        Contract.RequiresNonNull(worker);
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(extraNonce2));
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(nTime));
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(nonce));

        var context = worker.ContextAs<HodlcoinWorkerContext>();

        // validate nTime
        if(nTime.Length != 8)
            throw new StratumException(StratumError.Other, "incorrect size of ntime");

        var nTimeInt = uint.Parse(nTime, NumberStyles.HexNumber);
        if(nTimeInt < BlockTemplate.CurTime || nTimeInt > ((DateTimeOffset) clock.Now).ToUnixTimeSeconds() + 7200)
            throw new StratumException(StratumError.Other, "ntime out of range");

        // validate nonce
        if(nonce.Length != 8)
            throw new StratumException(StratumError.Other, "incorrect size of nonce");

        var nonceInt = uint.Parse(nonce, NumberStyles.HexNumber);

        // version-rolling
        uint versionBitsInt = 0;
        if(context.VersionRollingMask.HasValue && versionBits != null)
        {
            versionBitsInt = uint.Parse(versionBits, NumberStyles.HexNumber);
            if((versionBitsInt & ~context.VersionRollingMask.Value) != 0)
                throw new StratumException(StratumError.Other, "rolling-version mask violation");
        }

        // dupe check (before touching birthdays)
        if(!RegisterSubmit(context.ExtraNonce1, extraNonce2, nTime, nonce))
            throw new StratumException(StratumError.DuplicateShare, "duplicate share");

        // optional birthdays from miner (hex LE, up to 8 chars)
        if (!string.IsNullOrEmpty(birthdayAHex) && birthdayAHex.Length <= 8)
            birthdayA = Convert.ToUInt32(birthdayAHex, 16);
        if (!string.IsNullOrEmpty(birthdayBHex) && birthdayBHex.Length <= 8)
            birthdayB = Convert.ToUInt32(birthdayBHex, 16);

        return ProcessShareInternal(worker, extraNonce2, nTimeInt, nonceInt, versionBitsInt);
    }

    #endregion
}
