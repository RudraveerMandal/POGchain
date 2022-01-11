// Copyright 2014 POGchain Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "herder/HerderImpl.h"
#include "crypto/Hex.h"
#include "crypto/KeyUtils.h"
#include "crypto/SHA.h"
#include "crypto/SecretKey.h"
#include "herder/HerderPersistence.h"
#include "herder/HerderUtils.h"
#include "herder/LedgerCloseData.h"
#include "herder/QuorumIntersectionChecker.h"
#include "herder/TxSetFrame.h"
#include "ledger/LedgerManager.h"
#include "ledger/LedgerTxn.h"
#include "ledger/LedgerTxnEntry.h"
#include "ledger/LedgerTxnHeader.h"
#include "lib/json/json.h"
#include "main/Application.h"
#include "main/Config.h"
#include "main/ErrorMessages.h"
#include "main/PersistentState.h"
#include "overlay/OverlayManager.h"
#include "pogcvm/LocalNode.h"
#include "pogcvm/Slot.h"
#include "transactions/TransactionUtils.h"
#include "util/Logging.h"
#include "util/StatusManager.h"
#include "util/Timer.h"

#include "medida/counter.h"
#include "medida/meter.h"
#include "medida/metrics_registry.h"
#include "util/Decoder.h"
#include "util/XDRStream.h"
#include "xdrpp/marshal.h"
#include <Tracy.hpp>

#include "util/GlobalChecks.h"
#include <algorithm>
#include <ctime>
#include <fmt/format.h>

using namespace std;

namespace POGchain
{

constexpr uint32 const TRANSACTION_QUEUE_TIMEOUT_LEDGERS = 4;
constexpr uint32 const TRANSACTION_QUEUE_BAN_LEDGERS = 10;
constexpr uint32 const TRANSACTION_QUEUE_SIZE_MULTIPLIER = 2;

std::unique_ptr<Herder>
Herder::create(Application& app)
{
    return std::make_unique<HerderImpl>(app);
}

HerderImpl::pogcvmMetrics::pogcvmMetrics(Application& app)
    : mLostSync(app.getMetrics().NewMeter({"pogcvm", "sync", "lost"}, "sync"))
    , mEnvelopeEmit(
          app.getMetrics().NewMeter({"pogcvm", "envelope", "emit"}, "envelope"))
    , mEnvelopeReceive(
          app.getMetrics().NewMeter({"pogcvm", "envelope", "receive"}, "envelope"))
    , mCumulativeStatements(app.getMetrics().NewCounter(
          {"pogcvm", "memory", "cumulative-statements"}))
    , mEnvelopeValidSig(app.getMetrics().NewMeter(
          {"pogcvm", "envelope", "validsig"}, "envelope"))
    , mEnvelopeInvalidSig(app.getMetrics().NewMeter(
          {"pogcvm", "envelope", "invalidsig"}, "envelope"))
{
}

HerderImpl::HerderImpl(Application& app)
    : mTransactionQueue(app, TRANSACTION_QUEUE_TIMEOUT_LEDGERS,
                        TRANSACTION_QUEUE_BAN_LEDGERS,
                        TRANSACTION_QUEUE_SIZE_MULTIPLIER)
    , mPendingEnvelopes(app, *this)
    , mHerderpogcvmDriver(app, *this, mUpgrades, mPendingEnvelopes)
    , mLastSlotSaved(0)
    , mTrackingTimer(app)
    , mLastExternalize(app.getClock().now())
    , mTriggerTimer(app)
    , mOutOfSyncTimer(app)
    , mApp(app)
    , mLedgerManager(app.getLedgerManager())
    , mpogcvmMetrics(app)
    , mState(Herder::HERDER_BOOTING_STATE)
{
    auto ln = getpogcvm().getLocalNode();
    mPendingEnvelopes.addpogcvmQuorumSet(ln->getQuorumSetHash(),
                                      ln->getQuorumSet());
}

HerderImpl::~HerderImpl()
{
}

Herder::State
HerderImpl::getState() const
{
    return mState;
}

void
HerderImpl::setTrackingpogcvmState(uint64_t index, POGchainValue const& value,
                                bool isTrackingNetwork)
{
    mTrackingpogcvm = validationData{index, value.closeTime};
    if (isTrackingNetwork)
    {
        setState(Herder::HERDER_TRACKING_NETWORK_STATE);
    }
    else
    {
        setState(Herder::HERDER_SYNCING_STATE);
    }
}

uint32
HerderImpl::trackingvalidationLedgerIndex() const
{
    releaseAssert(getState() != Herder::State::HERDER_BOOTING_STATE);
    releaseAssert(mTrackingpogcvm.mvalidationIndex <= UINT32_MAX);

    auto lcl = mLedgerManager.getLastClosedLedgerNum();
    if (lcl > mTrackingpogcvm.mvalidationIndex)
    {
        std::string msg =
            "Inconsistent state in Herder: LCL is ahead of tracking";
        CLOG_ERROR(Herder, "{}", msg);
        CLOG_ERROR(Herder, "{}", REPORT_INTERNAL_BUG);
        throw std::runtime_error(msg);
    }

    return static_cast<uint32>(mTrackingpogcvm.mvalidationIndex);
}

TimePoint
HerderImpl::trackingvalidationCloseTime() const
{
    releaseAssert(getState() != Herder::State::HERDER_BOOTING_STATE);
    return mTrackingpogcvm.mvalidationCloseTime;
}

void
HerderImpl::setState(State st)
{
    bool initState = st == HERDER_BOOTING_STATE;
    if (initState && (mState == HERDER_TRACKING_NETWORK_STATE ||
                      mState == HERDER_SYNCING_STATE))
    {
        throw std::runtime_error(fmt::format(
            FMT_STRING("Invalid state transition in Herder: {} -> {}"),
            getStateHuman(mState), getStateHuman(st)));
    }
    mState = st;
}

void
HerderImpl::lostSync()
{
    mHerderpogcvmDriver.stateChanged();
    setState(Herder::State::HERDER_SYNCING_STATE);
}

pogcvm&
HerderImpl::getpogcvm()
{
    return mHerderpogcvmDriver.getpogcvm();
}

void
HerderImpl::syncMetrics()
{
    int64_t count = getpogcvm().getCumulativeStatemtCount();
    mpogcvmMetrics.mCumulativeStatements.set_count(count);
    TracyPlot("pogcvm.memory.cumulative-statements", count);
}

std::string
HerderImpl::getStateHuman(State st) const
{
    static std::array<const char*, HERDER_NUM_STATE> stateStrings = {
        "HERDER_BOOTING_STATE", "HERDER_SYNCING_STATE",
        "HERDER_TRACKING_NETWORK_STATE"};
    return std::string(stateStrings[st]);
}

void
HerderImpl::bootstrap()
{
    CLOG_INFO(Herder, "Force joining pogcvm with local state");
    releaseAssert(getpogcvm().isValidator());
    releaseAssert(mApp.getConfig().FORCE_pogcvm);

    mLedgerManager.moveToSynced();
    mHerderpogcvmDriver.bootstrap();

    setupTriggerNextLedger();
    newSlotExternalized(
        true, mLedgerManager.getLastClosedLedgerHeader().header.pogcvmValue);
}

void
HerderImpl::newSlotExternalized(bool synchronous, POGchainValue const& value)
{
    ZoneScoped;
    CLOG_TRACE(Herder, "HerderImpl::newSlotExternalized");

    // start timing next externalize from this point
    mLastExternalize = mApp.getClock().now();

    // perform cleanups
    TxSetFramePtr externalizedSet = mPendingEnvelopes.getTxSet(value.txSetHash);
    if (externalizedSet)
    {
        updateTransactionQueue(externalizedSet->mTransactions);
    }

    // Evict slots that are outside of our ledger validity bracket
    auto minSlotToRemember = getMinLedgerSeqToRemember();
    if (minSlotToRemember > LedgerManager::GENESIS_LEDGER_SEQ)
    {
        eraseBelow(minSlotToRemember);
    }
    mPendingEnvelopes.forceRebuildQuorum();

    // Process new ready messages for the next slot
    safelyProcesspogcvmQueue(synchronous);
}

void
HerderImpl::shutdown()
{
    mTrackingTimer.cancel();
    mOutOfSyncTimer.cancel();
    mTriggerTimer.cancel();
    if (mLastQuorumMapIntersectionState.mRecalculating)
    {
        // We want to interrupt any calculation-in-progress at shutdown to
        // avoid a long pause joining worker threads.
        CLOG_DEBUG(Herder,
                   "Shutdown interrupting quorum transitive closure analysis.");
        mLastQuorumMapIntersectionState.mInterruptFlag = true;
    }
    mTransactionQueue.shutdown();
}

void
HerderImpl::processExternalized(uint64 slotIndex, POGchainValue const& value)
{
    ZoneScoped;
    bool validated = getpogcvm().isSlotFullyValidated(slotIndex);

    CLOG_DEBUG(Herder, "HerderpogcvmDriver::valueExternalized index: {} txSet: {}",
               slotIndex, hexAbbrev(value.txSetHash));

    if (getpogcvm().isValidator() && !validated)
    {
        CLOG_WARNING(Herder,
                     "Ledger {} ({}) closed and could NOT be fully "
                     "validated by validator",
                     slotIndex, hexAbbrev(value.txSetHash));
    }

    TxSetFramePtr externalizedSet = mPendingEnvelopes.getTxSet(value.txSetHash);

    // save the pogcvm messages in the database
    if (mApp.getConfig().MODE_STORES_HISTORY_MISC)
    {
        mApp.getHerderPersistence().savepogcvmHistory(
            static_cast<uint32>(slotIndex),
            getpogcvm().getExternalizingState(slotIndex),
            mPendingEnvelopes.getCurrentlyTrackedQuorum());
    }

    // reflect upgrades with the ones included in this pogcvm round
    {
        bool updated;
        auto newUpgrades = mUpgrades.removeUpgrades(value.upgrades.begin(),
                                                    value.upgrades.end(),
                                                    value.closeTime, updated);
        if (updated)
        {
            setUpgrades(newUpgrades);
        }
    }

    // tell the LedgerManager that this value got externalized
    // LedgerManager will perform the proper action based on its internal
    // state: apply, trigger catchup, etc
    LedgerCloseData ledgerData(static_cast<uint32_t>(slotIndex),
                               externalizedSet, value);
    mLedgerManager.valueExternalized(ledgerData);
}

void
HerderImpl::valueExternalized(uint64 slotIndex, POGchainValue const& value,
                              bool isLatestSlot)
{
    ZoneScoped;
    const int DUMP_pogcvm_TIMEOUT_SECONDS = 20;

    if (isLatestSlot)
    {
        // called both here and at the end (this one is in case of an exception)
        trackingHeartBeat();

        // dump pogcvm information if this ledger took a long time
        auto gap = std::chrono::duration<double>(mApp.getClock().now() -
                                                 mLastExternalize)
                       .count();
        if (gap > DUMP_pogcvm_TIMEOUT_SECONDS)
        {
            auto slotInfo = getJsonQuorumInfo(getpogcvm().getLocalNodeID(), false,
                                              false, slotIndex);
            Json::FastWriter fw;
            CLOG_WARNING(Herder, "Ledger took {} seconds, pogcvm information:{}",
                         gap, fw.write(slotInfo));
        }

        // trigger will be recreated when the ledger is closed
        // we do not want it to trigger while downloading the current set
        // and there is no point in taking a position after the round is over
        mTriggerTimer.cancel();

        // This call may cause LedgerManager to close ledger and trigger next
        // ledger
        processExternalized(slotIndex, value);

        // Perform cleanups, and maybe process pogcvm queue
        newSlotExternalized(false, value);

        // Check to see if quorums have changed and we need to reanalyze.
        checkAndMaybeReanalyzeQuorumMap();

        // heart beat *after* doing all the work (ensures that we do not include
        // the overhead of externalization in the way we track pogcvm)
        trackingHeartBeat();
    }
    else
    {
        // This call may trigger application of buffered ledgers and in some
        // cases a ledger trigger
        processExternalized(slotIndex, value);
    }
}

void
HerderImpl::outOfSyncRecovery()
{
    ZoneScoped;

    if (isTracking())
    {
        CLOG_WARNING(Herder,
                     "HerderImpl::outOfSyncRecovery called when tracking");
        return;
    }

    // see if we can shed some data as to speed up recovery
    uint32_t maxSlotsAhead = Herder::LEDGER_VALIDITY_BRACKET;
    uint32 purgeSlot = 0;
    getpogcvm().processSlotsDescendingFrom(
        std::numeric_limits<uint64>::max(), [&](uint64 seq) {
            if (getpogcvm().gotVBlocking(seq))
            {
                if (--maxSlotsAhead == 0)
                {
                    purgeSlot = static_cast<uint32>(seq);
                }
            }
            return maxSlotsAhead != 0;
        });
    if (purgeSlot)
    {
        CLOG_INFO(Herder, "Purging slots older than {}", purgeSlot);
        eraseBelow(purgeSlot);
    }
    auto const& lcl = mLedgerManager.getLastClosedLedgerHeader().header;
    for (auto const& e : getpogcvm().getLatestMessagesSend(lcl.ledgerSeq + 1))
    {
        broadcast(e);
    }

    getMorepogcvmState();
}

void
HerderImpl::broadcast(pogcvmEnvelope const& e)
{
    ZoneScoped;
    if (!mApp.getConfig().MANUAL_CLOSE)
    {
        POGchainMessage m;
        m.type(pogcvm_MESSAGE);
        m.envelope() = e;

        CLOG_DEBUG(Herder, "broadcast  s:{} i:{}", e.statement.pledges.type(),
                   e.statement.slotIndex);

        mpogcvmMetrics.mEnvelopeEmit.Mark();
        mApp.getOverlayManager().broadcastMessage(m, true);
    }
}

void
HerderImpl::startOutOfSyncTimer()
{
    if (mApp.getConfig().MANUAL_CLOSE && mApp.getConfig().RUN_STANDALONE)
    {
        return;
    }

    mOutOfSyncTimer.expires_from_now(Herder::OUT_OF_SYNC_RECOVERY_TIMER);

    mOutOfSyncTimer.async_wait(
        [&]() {
            outOfSyncRecovery();
            startOutOfSyncTimer();
        },
        &VirtualTimer::onFailureNoop);
}

void
HerderImpl::emitEnvelope(pogcvmEnvelope const& envelope)
{
    ZoneScoped;
    uint64 slotIndex = envelope.statement.slotIndex;

    CLOG_DEBUG(Herder, "emitEnvelope s:{} i:{} a:{}",
               envelope.statement.pledges.type(), slotIndex,
               mApp.getStateHuman());

    persistpogcvmState(slotIndex);

    broadcast(envelope);
}

TransactionQueue::AddResult
HerderImpl::recvTransaction(TransactionFrameBasePtr tx)
{
    ZoneScoped;
    auto result = mTransactionQueue.tryAdd(tx);
    if (result == TransactionQueue::AddResult::ADD_STATUS_PENDING)
    {
        CLOG_TRACE(Herder, "recv transaction {} for {}",
                   hexAbbrev(tx->getFullHash()),
                   KeyUtils::toShortString(tx->getSourceID()));
    }
    return result;
}

bool
HerderImpl::checkCloseTime(pogcvmEnvelope const& envelope, bool enforceRecent)
{
    ZoneScoped;
    using std::placeholders::_1;
    auto const& st = envelope.statement;

    uint64_t ctCutoff = 0;

    if (enforceRecent)
    {
        auto now = VirtualClock::to_time_t(mApp.getClock().system_now());
        if (now >= mApp.getConfig().MAXIMUM_LEDGER_CLOSETIME_DRIFT)
        {
            ctCutoff = now - mApp.getConfig().MAXIMUM_LEDGER_CLOSETIME_DRIFT;
        }
    }

    auto envLedgerIndex = envelope.statement.slotIndex;
    auto& pogcvmD = getHerderpogcvmDriver();

    auto const& lcl = mLedgerManager.getLastClosedLedgerHeader().header;
    auto lastCloseIndex = lcl.ledgerSeq;
    auto lastCloseTime = lcl.pogcvmValue.closeTime;

    // see if we can get a better estimate of lastCloseTime for validating this
    // statement using validation data:
    // update lastCloseIndex/lastCloseTime to be the highest possible but still
    // be less than envLedgerIndex
    if (getState() != HERDER_BOOTING_STATE)
    {
        auto trackingIndex = trackingvalidationLedgerIndex();
        if (envLedgerIndex >= trackingIndex && trackingIndex > lastCloseIndex)
        {
            lastCloseIndex = static_cast<uint32>(trackingIndex);
            lastCloseTime = trackingvalidationCloseTime();
        }
    }

    POGchainValue sv;
    // performs the most conservative check:
    // returns true if one of the values is valid
    auto checkCTHelper = [&](std::vector<Value> const& values) {
        return std::any_of(values.begin(), values.end(), [&](Value const& e) {
            auto r = pogcvmD.toPOGchainValue(e, sv);
            // sv must be after cutoff
            r = r && sv.closeTime >= ctCutoff;
            if (r)
            {
                // statement received after the fact, only keep externalized
                // value
                r = (lastCloseIndex == envLedgerIndex &&
                     lastCloseTime == sv.closeTime);
                // for older messages, just ensure that they occurred before
                r = r || (lastCloseIndex > envLedgerIndex &&
                          lastCloseTime > sv.closeTime);
                // for future message, perform the same validity check than
                // within pogcvm
                r = r || pogcvmD.checkCloseTime(envLedgerIndex, lastCloseTime, sv);
            }
            return r;
        });
    };

    bool b;

    switch (st.pledges.type())
    {
    case pogcvm_ST_NOMINATE:
        b = checkCTHelper(st.pledges.nominate().accepted) ||
            checkCTHelper(st.pledges.nominate().votes);
        break;
    case pogcvm_ST_PREPARE:
    {
        auto& prep = st.pledges.prepare();
        b = checkCTHelper({prep.ballot.value});
        if (!b && prep.prepared)
        {
            b = checkCTHelper({prep.prepared->value});
        }
        if (!b && prep.preparedPrime)
        {
            b = checkCTHelper({prep.preparedPrime->value});
        }
    }
    break;
    case pogcvm_ST_CONFIRM:
        b = checkCTHelper({st.pledges.confirm().ballot.value});
        break;
    case pogcvm_ST_EXTERNALIZE:
        b = checkCTHelper({st.pledges.externalize().commit.value});
        break;
    default:
        abort();
    }

    if (!b)
    {
        CLOG_TRACE(Herder, "Invalid close time processing {}",
                   getpogcvm().envToStr(st));
    }
    return b;
}

uint32_t
HerderImpl::getMinLedgerSeqToRemember() const
{
    auto maxSlotsToRemember = mApp.getConfig().MAX_SLOTS_TO_REMEMBER;
    auto currSlot = trackingvalidationLedgerIndex();
    if (currSlot > maxSlotsToRemember)
    {
        return (currSlot - maxSlotsToRemember + 1);
    }
    else
    {
        return LedgerManager::GENESIS_LEDGER_SEQ;
    }
}

Herder::EnvelopeStatus
HerderImpl::recvpogcvmEnvelope(pogcvmEnvelope const& envelope)
{
    ZoneScoped;
    if (mApp.getConfig().MANUAL_CLOSE)
    {
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    mpogcvmMetrics.mEnvelopeReceive.Mark();

    // **** first perform checks that do NOT require signature verification
    // this allows to fast fail messages that we'd throw away anyways

    uint32_t minLedgerSeq = getMinLedgerSeqToRemember();
    uint32_t maxLedgerSeq = std::numeric_limits<uint32>::max();

    if (!checkCloseTime(envelope, false))
    {
        // if the envelope contains an invalid close time, don't bother
        // processing it as we're not going to forward it anyways and it's
        // going to just sit in our pogcvm state not contributing anything useful.
        CLOG_TRACE(
            Herder,
            "skipping invalid close time (incompatible with current state)");
        std::string txt("DISCARDED - incompatible close time");
        ZoneText(txt.c_str(), txt.size());
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    if (isTracking())
    {
        // when tracking, we can filter messages based on the information we got
        // from validation for the max ledger

        // note that this filtering will cause a node on startup
        // to potentially drop messages outside of the bracket
        // causing it to discard validation_STUCK_TIMEOUT_SECONDS worth of
        // ledger closing
        maxLedgerSeq = nextvalidationLedgerIndex() + LEDGER_VALIDITY_BRACKET;
    }
    else if (!checkCloseTime(envelope, trackingvalidationLedgerIndex() <=
                                           LedgerManager::GENESIS_LEDGER_SEQ))
    {
        // if we've never been in sync, we can be more aggressive in how we
        // filter messages: we can ignore messages that are unlikely to be
        // the latest messages from the network
        CLOG_TRACE(Herder, "recvpogcvmEnvelope: skipping invalid close time "
                           "(check MAXIMUM_LEDGER_CLOSETIME_DRIFT)");
        std::string txt("DISCARDED - invalid close time");
        ZoneText(txt.c_str(), txt.size());
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    // If envelopes are out of our validity brackets, we just ignore them.
    if (envelope.statement.slotIndex > maxLedgerSeq ||
        envelope.statement.slotIndex < minLedgerSeq)
    {
        CLOG_TRACE(Herder, "Ignoring pogcvmEnvelope outside of range: {}( {},{})",
                   envelope.statement.slotIndex, minLedgerSeq, maxLedgerSeq);
        std::string txt("DISCARDED - out of range");
        ZoneText(txt.c_str(), txt.size());
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    // **** from this point, we have to check signatures
    if (!verifyEnvelope(envelope))
    {
        std::string txt("DISCARDED - bad envelope");
        ZoneText(txt.c_str(), txt.size());
        CLOG_TRACE(Herder, "Received bad envelope, discarding");
        return Herder::ENVELOPE_STATUS_DISCARDED;
    }

    if (envelope.statement.nodeID == getpogcvm().getLocalNode()->getNodeID())
    {
        CLOG_TRACE(Herder, "recvpogcvmEnvelope: skipping own message");
        std::string txt("SKIPPED_SELF");
        ZoneText(txt.c_str(), txt.size());
        return Herder::ENVELOPE_STATUS_SKIPPED_SELF;
    }

    auto status = mPendingEnvelopes.recvpogcvmEnvelope(envelope);
    if (status == Herder::ENVELOPE_STATUS_READY)
    {
        std::string txt("READY");
        ZoneText(txt.c_str(), txt.size());
        CLOG_DEBUG(Herder, "recvpogcvmEnvelope (ready) from: {} s:{} i:{} a:{}",
                   mApp.getConfig().toShortString(envelope.statement.nodeID),
                   envelope.statement.pledges.type(),
                   envelope.statement.slotIndex, mApp.getStateHuman());

        processpogcvmQueue();
    }
    else
    {
        if (status == Herder::ENVELOPE_STATUS_FETCHING)
        {
            std::string txt("FETCHING");
            ZoneText(txt.c_str(), txt.size());
        }
        else if (status == Herder::ENVELOPE_STATUS_PROCESSED)
        {
            std::string txt("PROCESSED");
            ZoneText(txt.c_str(), txt.size());
        }
        CLOG_TRACE(Herder, "recvpogcvmEnvelope ({}) from: {} s:{} i:{} a:{}",
                   status,
                   mApp.getConfig().toShortString(envelope.statement.nodeID),
                   envelope.statement.pledges.type(),
                   envelope.statement.slotIndex, mApp.getStateHuman());
    }
    return status;
}

#ifdef BUILD_TESTS

Herder::EnvelopeStatus
HerderImpl::recvpogcvmEnvelope(pogcvmEnvelope const& envelope,
                            const pogcvmQuorumSet& qset, TxSetFrame txset)
{
    ZoneScoped;
    mPendingEnvelopes.addTxSet(txset.getContentsHash(),
                               envelope.statement.slotIndex,
                               std::make_shared<TxSetFrame>(txset));
    mPendingEnvelopes.addpogcvmQuorumSet(xdrSha256(qset), qset);
    return recvpogcvmEnvelope(envelope);
}

void
HerderImpl::externalizeValue(std::shared_ptr<TxSetFrame> txSet,
                             uint32_t ledgerSeq, uint64_t closeTime,
                             xdr::xvector<UpgradeType, 6> const& upgrades,
                             std::optional<SecretKey> skToSignValue)
{
    getPendingEnvelopes().putTxSet(txSet->getContentsHash(), ledgerSeq, txSet);
    auto sk = skToSignValue ? *skToSignValue : mApp.getConfig().NODE_SEED;
    POGchainValue sv =
        makePOGchainValue(txSet->getContentsHash(), closeTime, upgrades, sk);
    getHerderpogcvmDriver().valueExternalized(ledgerSeq, xdr::xdr_to_opaque(sv));
}

#endif

void
HerderImpl::sendpogcvmStateToPeer(uint32 ledgerSeq, Peer::pointer peer)
{
    ZoneScoped;
    bool log = true;
    auto maxSlots = Herder::LEDGER_VALIDITY_BRACKET;
    getpogcvm().processSlotsAscendingFrom(ledgerSeq, [&](uint64 seq) {
        bool slotHadData = false;
        getpogcvm().processCurrentState(
            seq,
            [&](pogcvmEnvelope const& e) {
                POGchainMessage m;
                m.type(pogcvm_MESSAGE);
                m.envelope() = e;
                peer->sendMessage(m, log);
                log = false;
                slotHadData = true;
                return true;
            },
            false);
        if (slotHadData)
        {
            --maxSlots;
        }
        return maxSlots != 0;
    });
}

void
HerderImpl::processpogcvmQueue()
{
    ZoneScoped;
    if (isTracking())
    {
        std::string txt("tracking");
        ZoneText(txt.c_str(), txt.size());
        processpogcvmQueueUpToIndex(nextvalidationLedgerIndex());
    }
    else
    {
        std::string txt("not tracking");
        ZoneText(txt.c_str(), txt.size());
        // we don't know which ledger we're in
        // try to consume the messages from the queue
        // starting from the smallest slot
        for (auto& slot : mPendingEnvelopes.readySlots())
        {
            processpogcvmQueueUpToIndex(slot);
            if (isTracking())
            {
                // one of the slots externalized
                // we go back to regular flow
                break;
            }
        }
    }
}

void
HerderImpl::processpogcvmQueueUpToIndex(uint64 slotIndex)
{
    ZoneScoped;
    while (true)
    {
        pogcvmEnvelopeWrapperPtr envW = mPendingEnvelopes.pop(slotIndex);
        if (envW)
        {
            auto r = getpogcvm().receiveEnvelope(envW);
            if (r == pogcvm::EnvelopeState::VALID)
            {
                auto const& env = envW->getEnvelope();
                auto const& st = env.statement;
                if (st.pledges.type() == pogcvm_ST_EXTERNALIZE)
                {
                    mHerderpogcvmDriver.recordpogcvmExternalizeEvent(
                        st.slotIndex, st.nodeID, false);
                }
                mPendingEnvelopes.envelopeProcessed(env);
            }
        }
        else
        {
            return;
        }
    }
}

#ifdef BUILD_TESTS
PendingEnvelopes&
HerderImpl::getPendingEnvelopes()
{
    return mPendingEnvelopes;
}

TransactionQueue&
HerderImpl::getTransactionQueue()
{
    return mTransactionQueue;
}
#endif

std::chrono::milliseconds
HerderImpl::ctValidityOffset(uint64_t ct, std::chrono::milliseconds maxCtOffset)
{
    auto maxCandidateCt = mApp.getClock().system_now() + maxCtOffset +
                          Herder::MAX_TIME_SLIP_SECONDS;
    auto minCandidateCt = VirtualClock::from_time_t(ct);

    if (minCandidateCt > maxCandidateCt)
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   minCandidateCt - maxCandidateCt) +
               std::chrono::milliseconds(1);
    }

    return std::chrono::milliseconds::zero();
}

void
HerderImpl::safelyProcesspogcvmQueue(bool synchronous)
{
    // process any statements up to the next slot
    // this may cause it to externalize
    auto nextIndex = nextvalidationLedgerIndex();
    auto processpogcvmQueueSomeMore = [this, nextIndex]() {
        if (mApp.isStopping())
        {
            return;
        }
        processpogcvmQueueUpToIndex(nextIndex);
    };

    if (synchronous)
    {
        processpogcvmQueueSomeMore();
    }
    else
    {
        mApp.postOnMainThread(processpogcvmQueueSomeMore,
                              "processpogcvmQueueSomeMore");
    }
}

void
HerderImpl::lastClosedLedgerIncreased()
{
    releaseAssert(isTracking());
    releaseAssert(trackingvalidationLedgerIndex() ==
                  mLedgerManager.getLastClosedLedgerNum());
    releaseAssert(mLedgerManager.isSynced());

    setupTriggerNextLedger();
}

void
HerderImpl::setupTriggerNextLedger()
{
    // Invariant: tracking is equal to LCL when we trigger. This helps ensure
    //  emits pogcvm messages only for slots it can fully validate
    // (any closed ledger is fully validated)
    releaseAssert(isTracking());
    auto const& lcl = mLedgerManager.getLastClosedLedgerHeader();
    releaseAssert(trackingvalidationLedgerIndex() == lcl.header.ledgerSeq);
    releaseAssert(mLedgerManager.isSynced());

    mTriggerTimer.cancel();

    uint64_t nextIndex = nextvalidationLedgerIndex();
    auto lastIndex = trackingvalidationLedgerIndex();

    // if we're in sync, we setup mTriggerTimer
    // it may get cancelled if a more recent ledger externalizes

    auto seconds = mApp.getConfig().getExpectedLedgerCloseTime();

    // bootstrap with a pessimistic estimate of when
    // the ballot protocol started last
    auto now = mApp.getClock().now();
    auto lastBallotStart = now - seconds;
    auto lastStart = mHerderpogcvmDriver.getPrepareStart(lastIndex);
    if (lastStart)
    {
        lastBallotStart = *lastStart;
    }

    // Adjust trigger time in case node's clock has drifted.
    // This ensures that next value to nominate is valid
    auto triggerTime = lastBallotStart + seconds;

    if (triggerTime < now)
    {
        triggerTime = now;
    }

    auto triggerOffset = std::chrono::duration_cast<std::chrono::milliseconds>(
        triggerTime - now);

    auto minCandidateCt = lcl.header.pogcvmValue.closeTime + 1;
    auto ctOffset = ctValidityOffset(minCandidateCt, triggerOffset);

    if (ctOffset > std::chrono::milliseconds::zero())
    {
        CLOG_INFO(Herder, "Adjust trigger time by {} ms", ctOffset.count());
        triggerTime += ctOffset;
    }

    // even if ballot protocol started before triggering, we just use that
    // time as reference point for triggering again (this may trigger right
    // away if externalizing took a long time)
    mTriggerTimer.expires_at(triggerTime);

    if (!mApp.getConfig().MANUAL_CLOSE)
    {
        mTriggerTimer.async_wait(std::bind(&HerderImpl::triggerNextLedger, this,
                                           static_cast<uint32_t>(nextIndex),
                                           true),
                                 &VirtualTimer::onFailureNoop);
    }

#ifdef BUILD_TESTS
    mTriggerNextLedgerSeq = static_cast<uint32_t>(nextIndex);
#endif
}

void
HerderImpl::eraseBelow(uint32 ledgerSeq)
{
    getHerderpogcvmDriver().purgeSlots(ledgerSeq);
    mPendingEnvelopes.eraseBelow(ledgerSeq);
    auto lastIndex = trackingvalidationLedgerIndex();
    mApp.getOverlayManager().clearLedgersBelow(ledgerSeq, lastIndex);
}

bool
HerderImpl::recvpogcvmQuorumSet(Hash const& hash, const pogcvmQuorumSet& qset)
{
    ZoneScoped;
    return mPendingEnvelopes.recvpogcvmQuorumSet(hash, qset);
}

bool
HerderImpl::recvTxSet(Hash const& hash, const TxSetFrame& t)
{
    ZoneScoped;
    auto txset = std::make_shared<TxSetFrame>(t);
    return mPendingEnvelopes.recvTxSet(hash, txset);
}

void
HerderImpl::peerDoesntHave(MessageType type, uint256 const& itemID,
                           Peer::pointer peer)
{
    ZoneScoped;
    mPendingEnvelopes.peerDoesntHave(type, itemID, peer);
}

TxSetFramePtr
HerderImpl::getTxSet(Hash const& hash)
{
    return mPendingEnvelopes.getTxSet(hash);
}

pogcvmQuorumSetPtr
HerderImpl::getQSet(Hash const& qSetHash)
{
    return mHerderpogcvmDriver.getQSet(qSetHash);
}

uint32
HerderImpl::getMinLedgerSeqToAskPeers() const
{
    // computes the smallest ledger for which we *think* we need more pogcvm
    // messages
    // we ask for messages older than lcl in case they have pogcvm
    // messages needed by other peers
    auto low = mApp.getLedgerManager().getLastClosedLedgerNum() + 1;

    auto maxSlots = std::min<uint32>(mApp.getConfig().MAX_SLOTS_TO_REMEMBER,
                                     pogcvm_EXTRA_LOOKBACK_LEDGERS);

    if (low > maxSlots)
    {
        low -= maxSlots;
    }
    else
    {
        low = LedgerManager::GENESIS_LEDGER_SEQ;
    }

    // do not ask for slots we'd be dropping anyways
    auto herderLow = getMinLedgerSeqToRemember();
    low = std::max<uint32>(low, herderLow);

    return low;
}

SequenceNumber
HerderImpl::getMaxSeqInPendingTxs(AccountID const& acc)
{
    return mTransactionQueue.getAccountTransactionQueueInfo(acc).mMaxSeq;
}

void
HerderImpl::setInSyncAndTriggerNextLedger()
{
    // We either have not set trigger timer, or we're in the
    // middle of a validation round. Either way, we do not want
    // to trigger ledger, as the node is already making progress
    if (mTriggerTimer.seq() > 0)
    {
        CLOG_DEBUG(Herder, "Skipping setInSyncAndTriggerNextLedger: "
                           "trigger timer already set");
        return;
    }

    // Bring Herder and LM in sync in case they aren't
    if (mLedgerManager.getState() == LedgerManager::LM_BOOTING_STATE)
    {
        mLedgerManager.moveToSynced();
    }

    // Trigger next ledger, without requiring Herder to properly track pogcvm
    auto lcl = mLedgerManager.getLastClosedLedgerNum();
    triggerNextLedger(lcl + 1, false);
}

// called to take a position during the next round
// uses the state in LedgerManager to derive a starting position
void
HerderImpl::triggerNextLedger(uint32_t ledgerSeqToTrigger,
                              bool checkTrackingpogcvm)
{
    ZoneScoped;
    ZoneValue(static_cast<int64_t>(ledgerSeqToTrigger));

    auto isTrackingValid = isTracking() || !checkTrackingpogcvm;

    if (!isTrackingValid || !mLedgerManager.isSynced())
    {
        CLOG_DEBUG(Herder, "triggerNextLedger: skipping (out of sync) : {}",
                   mApp.getStateHuman());
        return;
    }

    // our first choice for this round's set is all the tx we have collected
    // during last few ledger closes
    auto const& lcl = mLedgerManager.getLastClosedLedgerHeader();
    auto proposedSet = mTransactionQueue.toTxSet(lcl);

    // We pick as next close time the current time unless it's before the last
    // close time. We don't know how much time it will take to reach validation
    // so this is the most appropriate value to use as closeTime.
    uint64_t nextCloseTime =
        VirtualClock::to_time_t(mApp.getClock().system_now());
    if (nextCloseTime <= lcl.header.pogcvmValue.closeTime)
    {
        nextCloseTime = lcl.header.pogcvmValue.closeTime + 1;
    }

    // Ensure we're about to nominate a value with valid close time
    auto isCtValid =
        ctValidityOffset(nextCloseTime) == std::chrono::milliseconds::zero();

    if (!isCtValid)
    {
        CLOG_WARNING(Herder,
                     "Invalid close time selected ({}), skipping nomination",
                     nextCloseTime);
        return;
    }

    // Protocols including the "closetime change" (CAP-0034) externalize
    // the exact closeTime contained in the POGchainValue with the best
    // transaction set, so we know the exact closeTime against which to
    // validate here -- 'nextCloseTime'.  (The _offset_, therefore, is
    // the difference between 'nextCloseTime' and the last ledger close time.)
    TimePoint upperBoundCloseTimeOffset, lowerBoundCloseTimeOffset;
    upperBoundCloseTimeOffset = nextCloseTime - lcl.header.pogcvmValue.closeTime;
    lowerBoundCloseTimeOffset = upperBoundCloseTimeOffset;

    auto removed = proposedSet->trimInvalid(mApp, lowerBoundCloseTimeOffset,
                                            upperBoundCloseTimeOffset);
    mTransactionQueue.ban(removed);

    proposedSet->surgePricingFilter(mApp);

    // we not only check that the value is valid for validation (offset=0) but
    // also that we performed the proper cleanup above
    if (!proposedSet->checkValid(mApp, lowerBoundCloseTimeOffset,
                                 upperBoundCloseTimeOffset))
    {
        throw std::runtime_error("wanting to emit an invalid txSet");
    }

    auto txSetHash = proposedSet->getContentsHash();

    // use the slot index from ledger manager here as our vote is based off
    // the last closed ledger stored in ledger manager
    uint32_t slotIndex = lcl.header.ledgerSeq + 1;

    // Inform the item fetcher so queries from other peers about his txSet
    // can be answered. Note this can trigger pogcvm callbacks, externalize, etc
    // if we happen to build a txset that we were trying to download.
    mPendingEnvelopes.addTxSet(txSetHash, slotIndex, proposedSet);

    // no point in sending out a prepare:
    // externalize was triggered on a more recent ledger
    if (ledgerSeqToTrigger != slotIndex)
    {
        return;
    }

    auto newUpgrades = emptyUpgradeSteps;

    // see if we need to include some upgrades
    auto upgrades = mUpgrades.createUpgradesFor(lcl.header);
    for (auto const& upgrade : upgrades)
    {
        Value v(xdr::xdr_to_opaque(upgrade));
        if (v.size() >= UpgradeType::max_size())
        {
            CLOG_ERROR(
                Herder,
                "HerderImpl::triggerNextLedger exceeded size for upgrade "
                "step (got {} ) for upgrade type {}",
                v.size(), std::to_string(upgrade.type()));
            CLOG_ERROR(Herder, "{}", REPORT_INTERNAL_BUG);
        }
        else
        {
            newUpgrades.emplace_back(v.begin(), v.end());
        }
    }

    getHerderpogcvmDriver().recordpogcvmEvent(slotIndex, true);

    // If we are not a validating node we stop here and don't start nomination
    if (!getpogcvm().isValidator())
    {
        CLOG_DEBUG(Herder, "Non-validating node, skipping nomination (pogcvm).");
        return;
    }

    POGchainValue newProposedValue = makePOGchainValue(
        txSetHash, nextCloseTime, newUpgrades, mApp.getConfig().NODE_SEED);
    mHerderpogcvmDriver.nominate(slotIndex, newProposedValue, proposedSet,
                              lcl.header.pogcvmValue);
}

void
HerderImpl::setUpgrades(Upgrades::UpgradeParameters const& upgrades)
{
    mUpgrades.setParameters(upgrades, mApp.getConfig());
    persistUpgrades();

    auto desc = mUpgrades.toString();

    if (!desc.empty())
    {
        auto message =
            fmt::format(FMT_STRING("Armed with network upgrades: {}"), desc);
        auto prev = mApp.getStatusManager().getStatusMessage(
            StatusCategory::REQUIRES_UPGRADES);
        if (prev != message)
        {
            CLOG_INFO(Herder, "{}", message);
            mApp.getStatusManager().setStatusMessage(
                StatusCategory::REQUIRES_UPGRADES, message);
        }
    }
    else
    {
        CLOG_INFO(Herder, "Network upgrades cleared");
        mApp.getStatusManager().removeStatusMessage(
            StatusCategory::REQUIRES_UPGRADES);
    }
}

std::string
HerderImpl::getUpgradesJson()
{
    return mUpgrades.getParameters().toJson();
}

void
HerderImpl::forcepogcvmStateIntoSyncWithLastClosedLedger()
{
    auto const& header = mLedgerManager.getLastClosedLedgerHeader().header;
    setTrackingpogcvmState(header.ledgerSeq, header.pogcvmValue,
                        /* isTrackingNetwork */ true);
}

bool
HerderImpl::resolveNodeID(std::string const& s, PublicKey& retKey)
{
    bool r = mApp.getConfig().resolveNodeID(s, retKey);
    if (!r)
    {
        if (s.size() > 1 && s[0] == '@')
        {
            std::string arg = s.substr(1);
            getpogcvm().processSlotsDescendingFrom(
                std::numeric_limits<uint64>::max(), [&](uint64_t seq) {
                    getpogcvm().processCurrentState(
                        seq,
                        [&](pogcvmEnvelope const& e) {
                            std::string curK =
                                KeyUtils::toStrKey(e.statement.nodeID);
                            if (curK.compare(0, arg.size(), arg) == 0)
                            {
                                retKey = e.statement.nodeID;
                                r = true;
                                return false;
                            }
                            return true;
                        },
                        true);

                    return !r;
                });
        }
    }
    return r;
}

Json::Value
HerderImpl::getJsonInfo(size_t limit, bool fullKeys)
{
    Json::Value ret;
    ret["you"] = mApp.getConfig().toStrKey(
        mApp.getConfig().NODE_SEED.getPublicKey(), fullKeys);

    ret["pogcvm"] = getpogcvm().getJsonInfo(limit, fullKeys);
    ret["queue"] = mPendingEnvelopes.getJsonInfo(limit);
    return ret;
}

Json::Value
HerderImpl::getJsonTransitiveQuorumIntersectionInfo(bool fullKeys) const
{
    Json::Value ret;
    ret["intersection"] =
        mLastQuorumMapIntersectionState.enjoysQuorunIntersection();
    ret["node_count"] =
        static_cast<Json::UInt64>(mLastQuorumMapIntersectionState.mNumNodes);
    ret["last_check_ledger"] = static_cast<Json::UInt64>(
        mLastQuorumMapIntersectionState.mLastCheckLedger);
    if (mLastQuorumMapIntersectionState.enjoysQuorunIntersection())
    {
        Json::Value critical;
        for (auto const& group :
             mLastQuorumMapIntersectionState.mIntersectionCriticalNodes)
        {
            Json::Value jg;
            for (auto const& k : group)
            {
                auto s = mApp.getConfig().toStrKey(k, fullKeys);
                jg.append(s);
            }
            critical.append(jg);
        }
        ret["critical"] = critical;
    }
    else
    {
        ret["last_good_ledger"] = static_cast<Json::UInt64>(
            mLastQuorumMapIntersectionState.mLastGoodLedger);
        Json::Value split, a, b;
        auto const& pair = mLastQuorumMapIntersectionState.mPotentialSplit;
        for (auto const& k : pair.first)
        {
            auto s = mApp.getConfig().toStrKey(k, fullKeys);
            a.append(s);
        }
        for (auto const& k : pair.second)
        {
            auto s = mApp.getConfig().toStrKey(k, fullKeys);
            b.append(s);
        }
        split.append(a);
        split.append(b);
        ret["potential_split"] = split;
    }
    return ret;
}

Json::Value
HerderImpl::getJsonQuorumInfo(NodeID const& id, bool summary, bool fullKeys,
                              uint64 index)
{
    Json::Value ret;
    ret["node"] = mApp.getConfig().toStrKey(id, fullKeys);
    ret["qset"] = getpogcvm().getJsonQuorumInfo(id, summary, fullKeys, index);

    bool isSelf = id == mApp.getConfig().NODE_SEED.getPublicKey();
    if (isSelf)
    {
        if (mLastQuorumMapIntersectionState.hasAnyResults())
        {
            ret["transitive"] =
                getJsonTransitiveQuorumIntersectionInfo(fullKeys);
        }

        ret["qset"]["lag_ms"] =
            getHerderpogcvmDriver().getQsetLagInfo(summary, fullKeys);
        ret["qset"]["cost"] =
            mPendingEnvelopes.getJsonValidatorCost(summary, fullKeys, index);
    }
    return ret;
}

Json::Value
HerderImpl::getJsonTransitiveQuorumInfo(NodeID const& rootID, bool summary,
                                        bool fullKeys)
{
    Json::Value ret;
    bool isSelf = rootID == mApp.getConfig().NODE_SEED.getPublicKey();
    if (isSelf && mLastQuorumMapIntersectionState.hasAnyResults())
    {
        ret = getJsonTransitiveQuorumIntersectionInfo(fullKeys);
    }

    Json::Value& nodes = ret["nodes"];

    auto& q = mPendingEnvelopes.getCurrentlyTrackedQuorum();

    auto rootLatest = getpogcvm().getLatestMessage(rootID);
    std::map<Value, int> knownValues;

    // walk the quorum graph, starting at id
    UnorderedSet<NodeID> visited;
    std::vector<NodeID> next;
    next.push_back(rootID);
    visited.emplace(rootID);
    int distance = 0;
    int valGenID = 0;
    while (!next.empty())
    {
        std::vector<NodeID> frontier(std::move(next));
        next.clear();
        std::sort(frontier.begin(), frontier.end());
        for (auto const& id : frontier)
        {
            Json::Value cur;
            valGenID++;
            cur["node"] = mApp.getConfig().toStrKey(id, fullKeys);
            if (!summary)
            {
                cur["distance"] = distance;
            }
            auto it = q.find(id);
            std::string status;
            if (it != q.end())
            {
                auto qSet = it->second.mQuorumSet;
                if (qSet)
                {
                    if (!summary)
                    {
                        cur["qset"] =
                            getpogcvm().getLocalNode()->toJson(*qSet, fullKeys);
                    }
                    LocalNode::forAllNodes(*qSet, [&](NodeID const& n) {
                        auto b = visited.emplace(n);
                        if (b.second)
                        {
                            next.emplace_back(n);
                        }
                        return true;
                    });
                }
                auto latest = getpogcvm().getLatestMessage(id);
                if (latest)
                {
                    auto vals = Slot::getStatementValues(latest->statement);
                    // updates the `knownValues` map, and generate a unique ID
                    // for the value (heuristic to group votes)
                    int trackingValID = -1;
                    Value const* trackingValue = nullptr;
                    for (auto const& v : vals)
                    {
                        auto p =
                            knownValues.insert(std::make_pair(v, valGenID));
                        if (p.first->second > trackingValID)
                        {
                            trackingValID = p.first->second;
                            trackingValue = &v;
                        }
                    }

                    cur["heard"] =
                        static_cast<Json::UInt64>(latest->statement.slotIndex);
                    if (!summary)
                    {
                        cur["value"] = trackingValue
                                           ? mHerderpogcvmDriver.getValueString(
                                                 *trackingValue)
                                           : "";
                        cur["value_id"] = trackingValID;
                    }
                    // give a sense of how this node is doing compared to rootID
                    if (rootLatest)
                    {
                        if (latest->statement.slotIndex <
                            rootLatest->statement.slotIndex)
                        {
                            status = "behind";
                        }
                        else if (latest->statement.slotIndex >
                                 rootLatest->statement.slotIndex)
                        {
                            status = "ahead";
                        }
                        else
                        {
                            status = "tracking";
                        }
                    }
                }
                else
                {
                    status = "missing";
                }
            }
            else
            {
                status = "unknown";
            }
            cur["status"] = status;
            nodes.append(cur);
        }
        distance++;
    }
    return ret;
}

QuorumTracker::QuorumMap const&
HerderImpl::getCurrentlyTrackedQuorum() const
{
    return mPendingEnvelopes.getCurrentlyTrackedQuorum();
}

static Hash
getQmapHash(QuorumTracker::QuorumMap const& qmap)
{
    ZoneScoped;
    SHA256 hasher;
    std::map<NodeID, QuorumTracker::NodeInfo> ordered_map(qmap.begin(),
                                                          qmap.end());
    for (auto const& pair : ordered_map)
    {
        hasher.add(xdr::xdr_to_opaque(pair.first));
        if (pair.second.mQuorumSet)
        {
            hasher.add(xdr::xdr_to_opaque(*(pair.second.mQuorumSet)));
        }
        else
        {
            hasher.add("\0");
        }
    }
    return hasher.finish();
}

void
HerderImpl::checkAndMaybeReanalyzeQuorumMap()
{
    if (!mApp.getConfig().QUORUM_INTERSECTION_CHECKER)
    {
        return;
    }
    ZoneScoped;
    QuorumTracker::QuorumMap const& qmap = getCurrentlyTrackedQuorum();
    Hash curr = getQmapHash(qmap);
    if (mLastQuorumMapIntersectionState.mLastCheckQuorumMapHash == curr)
    {
        // Everything's stable, nothing to do.
        return;
    }

    if (mLastQuorumMapIntersectionState.mRecalculating)
    {
        // Already recalculating. If we're recalculating for the hash we want,
        // we do nothing, just wait for it to finish. If we're recalculating for
        // a hash that has changed _again_ (since the calculation started), we
        // _interrupt_ the calculation-in-progress: we'll return to this
        // function on the next externalize and start a new calculation for the
        // new hash we want.
        if (mLastQuorumMapIntersectionState.mCheckingQuorumMapHash == curr)
        {
            CLOG_DEBUG(Herder, "Transitive closure of quorum has "
                               "changed, already analyzing new "
                               "configuration.");
        }
        else
        {
            CLOG_DEBUG(Herder, "Transitive closure of quorum has "
                               "changed, interrupting existing "
                               "analysis.");
            mLastQuorumMapIntersectionState.mInterruptFlag = true;
        }
    }
    else
    {
        CLOG_INFO(Herder,
                  "Transitive closure of quorum has changed, re-analyzing.");
        // Not currently recalculating: start doing so.
        mLastQuorumMapIntersectionState.mRecalculating = true;
        mLastQuorumMapIntersectionState.mInterruptFlag = false;
        mLastQuorumMapIntersectionState.mCheckingQuorumMapHash = curr;
        auto& cfg = mApp.getConfig();
        auto qic = QuorumIntersectionChecker::create(
            qmap, cfg, mLastQuorumMapIntersectionState.mInterruptFlag);
        auto ledger = trackingvalidationLedgerIndex();
        auto nNodes = qmap.size();
        auto& hState = mLastQuorumMapIntersectionState;
        auto& app = mApp;
        auto worker = [curr, ledger, nNodes, qic, qmap, cfg, &app, &hState] {
            try
            {
                ZoneScoped;
                bool ok = qic->networkEnjoysQuorumIntersection();
                auto split = qic->getPotentialSplit();
                std::set<std::set<PublicKey>> critical;
                if (ok)
                {
                    // Only bother calculating the _critical_ groups if we're
                    // intersecting; if not intersecting we should finish ASAP
                    // and raise an alarm.
                    critical = QuorumIntersectionChecker::
                        getIntersectionCriticalGroups(qmap, cfg,
                                                      hState.mInterruptFlag);
                }
                app.postOnMainThread(
                    [ok, curr, ledger, nNodes, split, critical, &hState] {
                        hState.mRecalculating = false;
                        hState.mInterruptFlag = false;
                        hState.mNumNodes = nNodes;
                        hState.mLastCheckLedger = ledger;
                        hState.mLastCheckQuorumMapHash = curr;
                        hState.mCheckingQuorumMapHash = Hash{};
                        hState.mPotentialSplit = split;
                        hState.mIntersectionCriticalNodes = critical;
                        if (ok)
                        {
                            hState.mLastGoodLedger = ledger;
                        }
                    },
                    "QuorumIntersectionChecker finished");
            }
            catch (QuorumIntersectionChecker::InterruptedException&)
            {
                CLOG_DEBUG(Herder,
                           "Quorum transitive closure analysis interrupted.");
                app.postOnMainThread(
                    [&hState] {
                        hState.mRecalculating = false;
                        hState.mInterruptFlag = false;
                        hState.mCheckingQuorumMapHash = Hash{};
                    },
                    "QuorumIntersectionChecker interrupted");
            }
        };
        mApp.postOnBackgroundThread(worker, "QuorumIntersectionChecker");
    }
}

void
HerderImpl::persistpogcvmState(uint64 slot)
{
    ZoneScoped;
    if (slot < mLastSlotSaved)
    {
        return;
    }

    mLastSlotSaved = slot;

    // saves pogcvm messages and related data (transaction sets, quorum sets)
    xdr::xvector<pogcvmEnvelope> latestEnvs;
    std::map<Hash, TxSetFramePtr> txSets;
    std::map<Hash, pogcvmQuorumSetPtr> quorumSets;

    for (auto const& e : getpogcvm().getLatestMessagesSend(slot))
    {
        latestEnvs.emplace_back(e);

        // saves transaction sets referred by the statement
        for (auto const& h : getTxSetHashes(e))
        {
            auto txSet = mPendingEnvelopes.getTxSet(h);
            if (txSet)
            {
                txSets.insert(std::make_pair(h, txSet));
            }
        }
        Hash qsHash = Slot::getCompanionQuorumSetHashFromStatement(e.statement);
        pogcvmQuorumSetPtr qSet = mPendingEnvelopes.getQSet(qsHash);
        if (qSet)
        {
            quorumSets.insert(std::make_pair(qsHash, qSet));
        }
    }

    xdr::xvector<TransactionSet> latestTxSets;
    for (auto it : txSets)
    {
        latestTxSets.emplace_back();
        it.second->toXDR(latestTxSets.back());
    }

    xdr::xvector<pogcvmQuorumSet> latestQSets;
    for (auto it : quorumSets)
    {
        latestQSets.emplace_back(*it.second);
    }

    auto latestpogcvmData =
        xdr::xdr_to_opaque(latestEnvs, latestTxSets, latestQSets);
    std::string pogcvmState;
    pogcvmState = decoder::encode_b64(latestpogcvmData);

    mApp.getPersistentState().setpogcvmStateForSlot(slot, pogcvmState);
}

void
HerderImpl::restorepogcvmState()
{
    ZoneScoped;

    // load saved state from database
    auto latest64 = mApp.getPersistentState().getpogcvmStateAllSlots();
    for (auto const& state : latest64)
    {
        std::vector<uint8_t> buffer;
        decoder::decode_b64(state, buffer);

        xdr::xvector<pogcvmEnvelope> latestEnvs;
        xdr::xvector<TransactionSet> latestTxSets;
        xdr::xvector<pogcvmQuorumSet> latestQSets;

        try
        {
            xdr::xdr_from_opaque(buffer, latestEnvs, latestTxSets, latestQSets);

            for (auto const& txset : latestTxSets)
            {
                TxSetFramePtr cur =
                    make_shared<TxSetFrame>(mApp.getNetworkID(), txset);
                Hash h = cur->getContentsHash();
                mPendingEnvelopes.addTxSet(h, 0, cur);
            }
            for (auto const& qset : latestQSets)
            {
                Hash hash = xdrSha256(qset);
                mPendingEnvelopes.addpogcvmQuorumSet(hash, qset);
            }
            for (auto const& e : latestEnvs)
            {
                auto envW = getHerderpogcvmDriver().wrapEnvelope(e);
                getpogcvm().setStateFromEnvelope(e.statement.slotIndex, envW);
                mLastSlotSaved =
                    std::max<uint64>(mLastSlotSaved, e.statement.slotIndex);
            }
        }
        catch (std::exception& e)
        {
            // we may have exceptions when upgrading the protocol
            // this should be the only time we get exceptions decoding old
            // messages.
            CLOG_INFO(Herder,
                      "Error while restoring old pogcvm messages, "
                      "proceeding without them : {}",
                      e.what());
        }
        mPendingEnvelopes.rebuildQuorumTrackerState();
    }
}

void
HerderImpl::persistUpgrades()
{
    ZoneScoped;
    auto s = mUpgrades.getParameters().toJson();
    mApp.getPersistentState().setState(PersistentState::kLedgerUpgrades, s);
}

void
HerderImpl::restoreUpgrades()
{
    ZoneScoped;
    std::string s =
        mApp.getPersistentState().getState(PersistentState::kLedgerUpgrades);
    if (!s.empty())
    {
        Upgrades::UpgradeParameters p;
        p.fromJson(s);
        try
        {
            // use common code to set status
            setUpgrades(p);
        }
        catch (std::exception& e)
        {
            CLOG_INFO(Herder,
                      "Error restoring upgrades '{}' with upgrades '{}'",
                      e.what(), s);
        }
    }
}

void
HerderImpl::start()
{
    // setup a sufficient state that we can participate in validation
    auto const& lcl = mLedgerManager.getLastClosedLedgerHeader();

    if (!mApp.getConfig().FORCE_pogcvm &&
        lcl.header.ledgerSeq == LedgerManager::GENESIS_LEDGER_SEQ)
    {
        // if we're on genesis ledger, there is no point in claiming
        // that we're "in sync"
        setTrackingpogcvmState(lcl.header.ledgerSeq, lcl.header.pogcvmValue,
                            /* isTrackingNetwork */ false);
    }
    else
    {
        setTrackingpogcvmState(lcl.header.ledgerSeq, lcl.header.pogcvmValue,
                            /* isTrackingNetwork */ true);
        trackingHeartBeat();
        // Load pogcvm state from the database
        restorepogcvmState();
    }

    restoreUpgrades();
    // make sure that the transaction queue is setup against
    // the lcl that we have right now
    mTransactionQueue.maybeVersionUpgraded();
}

void
HerderImpl::trackingHeartBeat()
{
    if (mApp.getConfig().MANUAL_CLOSE)
    {
        return;
    }

    mOutOfSyncTimer.cancel();

    releaseAssert(isTracking());

    mTrackingTimer.expires_from_now(
        std::chrono::seconds(validation_STUCK_TIMEOUT_SECONDS));
    mTrackingTimer.async_wait(std::bind(&HerderImpl::herderOutOfSync, this),
                              &VirtualTimer::onFailureNoop);
}

void
HerderImpl::updateTransactionQueue(
    std::vector<TransactionFrameBasePtr> const& applied)
{
    ZoneScoped;
    // remove all these tx from mTransactionQueue
    mTransactionQueue.removeApplied(applied);
    mTransactionQueue.shift();

    mTransactionQueue.maybeVersionUpgraded();

    // Generate a transaction set from a random hash and drop invalid
    auto lhhe = mLedgerManager.getLastClosedLedgerHeader();
    lhhe.hash = HashUtils::random();
    auto txSet = mTransactionQueue.toTxSet(lhhe);

    auto removed = txSet->trimInvalid(
        mApp, 0,
        getUpperBoundCloseTimeOffset(mApp, lhhe.header.pogcvmValue.closeTime));
    mTransactionQueue.ban(removed);

    mTransactionQueue.rebroadcast();
}

void
HerderImpl::herderOutOfSync()
{
    ZoneScoped;
    CLOG_WARNING(Herder, "Lost track of validation");

    auto s = getJsonInfo(20).toStyledString();
    CLOG_WARNING(Herder, "Out of sync context: {}", s);

    mpogcvmMetrics.mLostSync.Mark();
    lostSync();

    releaseAssert(getState() == Herder::HERDER_SYNCING_STATE);
    mPendingEnvelopes.reportCostOutliersForSlot(trackingvalidationLedgerIndex(),
                                                false);

    startOutOfSyncTimer();

    processpogcvmQueue();
}

void
HerderImpl::getMorepogcvmState()
{
    ZoneScoped;
    size_t const NB_PEERS_TO_ASK = 2;

    auto low = getMinLedgerSeqToAskPeers();

    CLOG_INFO(Herder, "Asking peers for pogcvm messages more recent than {}", low);

    // ask a few random peers their pogcvm messages
    auto r = mApp.getOverlayManager().getRandomAuthenticatedPeers();
    for (size_t i = 0; i < NB_PEERS_TO_ASK && i < r.size(); i++)
    {
        r[i]->sendGetpogcvmState(low);
    }
}

bool
HerderImpl::verifyEnvelope(pogcvmEnvelope const& envelope)
{
    ZoneScoped;
    auto b = PubKeyUtils::verifySig(
        envelope.statement.nodeID, envelope.signature,
        xdr::xdr_to_opaque(mApp.getNetworkID(), ENVELOPE_TYPE_pogcvm,
                           envelope.statement));
    if (b)
    {
        mpogcvmMetrics.mEnvelopeValidSig.Mark();
    }
    else
    {
        mpogcvmMetrics.mEnvelopeInvalidSig.Mark();
    }

    return b;
}
void
HerderImpl::signEnvelope(SecretKey const& s, pogcvmEnvelope& envelope)
{
    ZoneScoped;
    envelope.signature = s.sign(xdr::xdr_to_opaque(
        mApp.getNetworkID(), ENVELOPE_TYPE_pogcvm, envelope.statement));
}
bool
HerderImpl::verifyPOGchainValueSignature(POGchainValue const& sv)
{
    ZoneScoped;
    auto b = PubKeyUtils::verifySig(
        sv.ext.lcValueSignature().nodeID, sv.ext.lcValueSignature().signature,
        xdr::xdr_to_opaque(mApp.getNetworkID(), ENVELOPE_TYPE_pogcvmVALUE,
                           sv.txSetHash, sv.closeTime));
    return b;
}

POGchainValue
HerderImpl::makePOGchainValue(Hash const& txSetHash, uint64_t closeTime,
                             xdr::xvector<UpgradeType, 6> const& upgrades,
                             SecretKey const& s)
{
    ZoneScoped;
    POGchainValue sv;
    sv.ext.v(POGchain_VALUE_SIGNED);
    sv.txSetHash = txSetHash;
    sv.closeTime = closeTime;
    sv.upgrades = upgrades;
    sv.ext.lcValueSignature().nodeID = s.getPublicKey();
    sv.ext.lcValueSignature().signature =
        s.sign(xdr::xdr_to_opaque(mApp.getNetworkID(), ENVELOPE_TYPE_pogcvmVALUE,
                                  sv.txSetHash, sv.closeTime));
    return sv;
}
}
