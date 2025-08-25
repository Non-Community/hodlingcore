using Autofac;
using Miningcore.Blockchain.Hodlcoin.Configuration;
using Miningcore.Blockchain.Hodlcoin.DaemonResponses;
using Miningcore.Configuration;
using Miningcore.Contracts;
using Miningcore.Crypto;
using Miningcore.Extensions;
using Miningcore.JsonRpc;
using Miningcore.Messaging;
using Miningcore.Rpc;
using Miningcore.Stratum;
using Miningcore.Time;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using NLog;

namespace Miningcore.Blockchain.Hodlcoin;

public class HodlcoinJobManager : HodlcoinJobManagerBase<HodlcoinJob>
{
    public HodlcoinJobManager(
        IComponentContext ctx,
        IMasterClock clock,
        IMessageBus messageBus,
        IExtraNonceProvider extraNonceProvider) :
        base(ctx, clock, messageBus, extraNonceProvider)
    {
    }

    private HodlcoinTemplate coin;

    protected override object[] GetBlockTemplateParams()
    {
        var result = base.GetBlockTemplateParams();

        if(coin.BlockTemplateRpcExtraParams != null)
        {
            if(coin.BlockTemplateRpcExtraParams.Type == JTokenType.Array)
                result = result.Concat(coin.BlockTemplateRpcExtraParams.ToObject<object[]>() ?? Array.Empty<object>()).ToArray();
            else
                result = result.Concat(new []{ coin.BlockTemplateRpcExtraParams.ToObject<object>()}).ToArray();
        }

        return result;
    }

    protected async Task<RpcResponse<BlockTemplate>> GetBlockTemplateAsync(CancellationToken ct)
    {
        const string rpcMethod = "getblocktemplate";
        var args = extraPoolConfig?.GBTArgs ?? (object) GetBlockTemplateParams();

        var result = await rpc.ExecuteAsync<BlockTemplate>(logger, rpcMethod, ct, args);
        return result;
    }

    protected RpcResponse<BlockTemplate> GetBlockTemplateFromJson(string json)
    {
        var result = JsonConvert.DeserializeObject<JsonRpcResponse>(json);
        return new RpcResponse<BlockTemplate>(result!.ResultAs<BlockTemplate>());
    }

    private HodlcoinJob CreateJob() => new();

    protected override void PostChainIdentifyConfigure()
    {
        base.PostChainIdentifyConfigure();

        if(poolConfig.EnableInternalStratum == true && coin.HeaderHasherValue is IHashAlgorithmInit hashInit)
        {
            if(!hashInit.DigestInit(poolConfig))
                logger.Error(()=> $"{hashInit.GetType().Name} initialization failed");
        }
    }

    protected override async Task<(bool IsNew, bool Force)> UpdateJob(CancellationToken ct, bool forceUpdate, string via = null, string json = null)
    {
        try
        {
            if(forceUpdate)
                lastJobRebroadcast = clock.Now;

            var response = string.IsNullOrEmpty(json)
                ? await GetBlockTemplateAsync(ct)
                : GetBlockTemplateFromJson(json);

            if(response.Error != null)
            {
                logger.Warn(() => $"Unable to update job. Daemon responded with: {response.Error.Message} Code {response.Error.Code}");
                return (false, forceUpdate);
            }

            var blockTemplate = response.Response;
            var job = currentJob;

            var isNew = job == null ||
                        (blockTemplate != null &&
                         (job.BlockTemplate?.PreviousBlockhash != blockTemplate.PreviousBlockhash ||
                          blockTemplate.Height > job.BlockTemplate?.Height));

            if(isNew)
                messageBus.NotifyChainHeight(poolConfig.Id, blockTemplate.Height, poolConfig.Template);

            if(isNew || forceUpdate)
            {
                job = CreateJob();

                job.Init(blockTemplate, NextJobId(),
                    poolConfig, extraPoolConfig, clusterConfig, clock, poolAddressDestination, network, isPoS,
                    ShareMultiplier, coin.CoinbaseHasherValue, coin.HeaderHasherValue,
                    !isPoS ? coin.BlockHasherValue : coin.PoSBlockHasherValue ?? coin.BlockHasherValue);

                // pick up per-job birthdays from template (if present)
                job.SetBirthdaysFromTemplate(blockTemplate);

                lock(jobLock)
                {
                    validJobs.Insert(0, job);
                    while(validJobs.Count > maxActiveJobs)
                        validJobs.RemoveAt(validJobs.Count - 1);
                }

                if(isNew)
                {
                    if(via != null)
                        logger.Info(() => $"Detected new block {blockTemplate.Height} [{via}]");
                    else
                        logger.Info(() => $"Detected new block {blockTemplate.Height}");

                    BlockchainStats.LastNetworkBlockTime = clock.Now;
                    BlockchainStats.BlockHeight = blockTemplate.Height;
                    BlockchainStats.NetworkDifficulty = job.Difficulty;
                    BlockchainStats.NextNetworkTarget = blockTemplate.Target;
                    BlockchainStats.NextNetworkBits = blockTemplate.Bits;
                }
                else
                {
                    if(via != null)
                        logger.Debug(() => $"Template update {blockTemplate?.Height} [{via}]");
                    else
                        logger.Debug(() => $"Template update {blockTemplate?.Height}");
                }

                currentJob = job;
            }

            return (isNew, forceUpdate);
        }
        catch(OperationCanceledException) { }
        catch(Exception ex)
        {
            logger.Error(ex, () => $"Error during {nameof(UpdateJob)}");
        }

        return (false, forceUpdate);
    }

    protected override object GetJobParamsForStratum(bool isNew)
    {
        var job = currentJob;
        return job?.GetJobParams(isNew);
    }

    #region API-Surface

    public override void Configure(PoolConfig pc, ClusterConfig cc)
    {
        coin = pc.Template.As<HodlcoinTemplate>();
        extraPoolConfig = pc.Extra.SafeExtensionDataAs<HodlcoinPoolConfigExtra>();
        extraPoolPaymentProcessingConfig = pc.PaymentProcessing?.Extra?.SafeExtensionDataAs<HodlcoinPoolPaymentProcessingConfigExtra>();

        if(extraPoolConfig?.MaxActiveJobs.HasValue == true)
            maxActiveJobs = extraPoolConfig.MaxActiveJobs.Value;

        hasLegacyDaemon = extraPoolConfig?.HasLegacyDaemon == true;

        base.Configure(pc, cc);
    }

    public virtual object[] GetSubscriberData(StratumConnection worker)
    {
        Contract.RequiresNonNull(worker);

        var context = worker.ContextAs<HodlcoinWorkerContext>();

        // assign unique ExtraNonce1
        context.ExtraNonce1 = extraNonceProvider.Next();

        return new object[]
        {
            context.ExtraNonce1,
            HodlcoinConstants.ExtranoncePlaceHolderLength - ExtranonceBytes,
        };
    }

    public override async ValueTask<Share> SubmitShareAsync(StratumConnection worker, object submission, CancellationToken ct)
    {
        Contract.RequiresNonNull(worker);
        Contract.RequiresNonNull(submission);

        if(submission is not object[] p || p.Length < 5)
            throw new StratumException(StratumError.Other, "invalid params");

        var context = worker.ContextAs<HodlcoinWorkerContext>();

        var workerValue = (p[0] as string)?.Trim();
        var jobId       = p[1] as string;
        var extraNonce2 = p[2] as string;
        var nTime       = p[3] as string;
        var nonce       = p[4] as string;

        // optional version-bits, then optional birthdays
        string versionBits = null;
        string birthdayA   = null;
        string birthdayB   = null;

        var idx = 5;

        if(context.VersionRollingMask.HasValue && p.Length > idx)
            versionBits = p[idx++] as string;

        if(p.Length > idx) birthdayA = p[idx++] as string;
        if(p.Length > idx) birthdayB = p[idx++] as string;

        if(string.IsNullOrEmpty(workerValue))
            throw new StratumException(StratumError.Other, "missing or invalid workername");

        HodlcoinJob job;
        lock(jobLock)
            job = validJobs.FirstOrDefault(x => x.JobId == jobId);

        if(job == null)
            throw new StratumException(StratumError.JobNotFound, "job not found");

        // process (validates sizes, calculates diff, detects block-candidate)
        var (share, blockHex) = job.ProcessShare(worker, extraNonce2, nTime, nonce, versionBits, birthdayA, birthdayB);

        // enrich
        share.PoolId    = poolConfig.Id;
        share.IpAddress = worker.RemoteEndpoint.Address.ToString();
        share.Miner     = context.Miner;
        share.Worker    = context.Worker;
        share.UserAgent = context.UserAgent;
        share.Source    = clusterConfig.ClusterName;
        share.Created   = clock.Now;

        // submit candidate
        if(share.IsBlockCandidate)
        {
            logger.Info(() => $"Submitting block {share.BlockHeight} [{share.BlockHash}]");

            var acceptResponse = await SubmitBlockAsync(share, blockHex, ct);

            share.IsBlockCandidate = acceptResponse.Accepted;

            if(share.IsBlockCandidate)
            {
                logger.Info(() => $"Daemon accepted block {share.BlockHeight} [{share.BlockHash}] submitted by {context.Miner}");
                OnBlockFound();

                share.TransactionConfirmationData = acceptResponse.CoinbaseTx;
            }
            else
            {
                share.TransactionConfirmationData = null;
            }
        }

        return share;
    }

    public double ShareMultiplier => coin.ShareMultiplier;

    #endregion
}
