// Copyright 2017 POGchain Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "herder/HerderpogcvmDriver.h"
#include "HerderUtils.h"
#include "crypto/Hex.h"
#include "crypto/SHA.h"
#include "crypto/SecretKey.h"
#include "herder/HerderImpl.h"
#include "herder/LedgerCloseData.h"
#include "herder/PendingEnvelopes.h"
#include "ledger/LedgerManager.h"
#include "main/Application.h"
#include "main/ErrorMessages.h"
#include "pogcvm/pogcvm.h"
#include "pogcvm/Slot.h"
#include "util/Logging.h"
#include "util/Math.h"
#include "xdr/POGchain-pogcvm.h"
#include "xdr/POGchain-ledger-entries.h"
#include "xdr/POGchain-ledger.h"
#include <Tracy.hpp>
#include <algorithm>
#include <fmt/format.h>
#include <medida/metrics_registry.h>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <xdrpp/marshal.h>

namespace POGchain
{

Hash
HerderpogcvmDriver::getHashOf(std::vector<xdr::opaque_vec<>> const& vals) const
{
    SHA256 hasher;
    for (auto const& v : vals)
    {
        hasher.add(v);
    }
    return hasher.finish();
}

HerderpogcvmDriver::pogcvmMetrics::pogcvmMetrics(Application& app)
    : mEnvelopeSign(
          app.getMetrics().NewMeter({"pogcvm", "envelope", "sign"}, "envelope"))
    , mValueValid(app.getMetrics().NewMeter({"pogcvm", "value", "valid"}, "value"))
    , mValueInvalid(
          app.getMetrics().NewMeter({"pogcvm", "value", "invalid"}, "value"))
    , mCombinedCandidates(app.getMetrics().NewMeter(
          {"pogcvm", "nomination", "combinecandidates"}, "value"))
    , mNominateToPrepare(
          app.getMetrics().NewTimer({"pogcvm", "timing", "nominated"}))
    , mPrepareToExternalize(
          app.getMetrics().NewTimer({"pogcvm", "timing", "externalized"}))
    , mFirstToSelfExternalizeLag(app.getMetrics().NewTimer(
          {"pogcvm", "timing", "first-to-self-externalize-lag"}))
    , mSelfToOthersExternalizeLag(app.getMetrics().NewTimer(
          {"pogcvm", "timing", "self-to-others-externalize-lag"}))
{
}

HerderpogcvmDriver::HerderpogcvmDriver(Application& app, HerderImpl& herder,
                                 Upgrades const& upgrades,
                                 PendingEnvelopes& pendingEnvelopes)
    : mApp{app}
    , mHerder{herder}
    , mLedgerManager{mApp.getLedgerManager()}
    , mUpgrades{upgrades}
    , mPendingEnvelopes{pendingEnvelopes}
    , mpogcvm{*this, mApp.getConfig().NODE_SEED.getPublicKey(),
           mApp.getConfig().NODE_IS_VALIDATOR, mApp.getConfig().QUORUM_SET}
    , mpogcvmMetrics{mApp}
    , mNominateTimeout{mApp.getMetrics().NewHistogram(
          {"pogcvm", "timeout", "nominate"})}
    , mPrepareTimeout{mApp.getMetrics().NewHistogram(
          {"pogcvm", "timeout", "prepare"})}
    , mLedgerSeqNominating(0)
{
}

HerderpogcvmDriver::~HerderpogcvmDriver()
{
}

void
HerderpogcvmDriver::stateChanged()
{
    mApp.syncOwnMetrics();
}

void
HerderpogcvmDriver::bootstrap()
{
    stateChanged();
    clearpogcvmExecutionEvents();
}

// envelope handling

class pogcvmHerderEnvelopeWrapper : public pogcvmEnvelopeWrapper
{
    HerderImpl& mHerder;

    pogcvmQuorumSetPtr mQSet;
    std::vector<TxSetFramePtr> mTxSets;

  public:
    explicit pogcvmHerderEnvelopeWrapper(pogcvmEnvelope const& e, HerderImpl& herder)
        : pogcvmEnvelopeWrapper(e), mHerder(herder)
    {
        // attach everything we can to the wrapper
        auto qSetH = Slot::getCompanionQuorumSetHashFromStatement(e.statement);
        mQSet = mHerder.getQSet(qSetH);
        if (!mQSet)
        {
            throw std::runtime_error(fmt::format(
                FMT_STRING("pogcvmHerderEnvelopeWrapper: Wrapping an unknown "
                           "qset {} from envelope"),
                hexAbbrev(qSetH)));
        }
        auto txSets = getTxSetHashes(e);
        for (auto const& txSetH : txSets)
        {
            auto txSet = mHerder.getTxSet(txSetH);
            if (txSet)
            {
                mTxSets.emplace_back(txSet);
            }
            else
            {
                throw std::runtime_error(fmt::format(
                    FMT_STRING("pogcvmHerderEnvelopeWrapper: Wrapping an unknown "
                               "tx set {} from envelope"),
                    hexAbbrev(txSetH)));
            }
        }
    }
};

pogcvmEnvelopeWrapperPtr
HerderpogcvmDriver::wrapEnvelope(pogcvmEnvelope const& envelope)
{
    auto r = std::make_shared<pogcvmHerderEnvelopeWrapper>(envelope, mHerder);
    return r;
}

void
HerderpogcvmDriver::signEnvelope(pogcvmEnvelope& envelope)
{
    ZoneScoped;
    mpogcvmMetrics.mEnvelopeSign.Mark();
    mHerder.signEnvelope(mApp.getConfig().NODE_SEED, envelope);
}

void
HerderpogcvmDriver::emitEnvelope(pogcvmEnvelope const& envelope)
{
    ZoneScoped;
    mHerder.emitEnvelope(envelope);
}

// value validation

bool
HerderpogcvmDriver::checkCloseTime(uint64_t slotIndex, uint64_t lastCloseTime,
                                POGchainValue const& b) const
{
    // Check closeTime (not too old)
    if (b.closeTime <= lastCloseTime)
    {
        CLOG_TRACE(Herder, "Close time too old for slot {}, got {} vs {}",
                   slotIndex, b.closeTime, lastCloseTime);
        return false;
    }

    // Check closeTime (not too far in future)
    uint64_t timeNow = mApp.timeNow();
    if (b.closeTime > timeNow + Herder::MAX_TIME_SLIP_SECONDS.count())
    {
        CLOG_TRACE(Herder,
                   "Close time too far in future for slot {}, got {} vs {}",
                   slotIndex, b.closeTime, timeNow);
        return false;
    }
    return true;
}

pogcvmDriver::ValidationLevel
HerderpogcvmDriver::validateValueHelper(uint64_t slotIndex, POGchainValue const& b,
                                     bool nomination) const
{
    uint64_t lastCloseTime;
    ZoneScoped;
    if (b.ext.v() != POGchain_VALUE_SIGNED)
    {
        CLOG_TRACE(Herder,
                   "HerderpogcvmDriver::validateValue i: {} invalid value type - "
                   "expected SIGNED",
                   slotIndex);
        return pogcvmDriver::kInvalidValue;
    }

    {
        ZoneNamedN(sigZone, "signature check", true);
        if (!mHerder.verifyPOGchainValueSignature(b))
        {
            return pogcvmDriver::kInvalidValue;
        }
    }

    auto const& lcl = mLedgerManager.getLastClosedLedgerHeader().header;
    // when checking close time, start with what we have locally
    lastCloseTime = lcl.pogcvmValue.closeTime;

    // if this value is not for our local state,
    // perform as many checks as we can
    if (slotIndex != (lcl.ledgerSeq + 1))
    {
        if (slotIndex == lcl.ledgerSeq)
        {
            // previous ledger
            if (b.closeTime != lastCloseTime)
            {
                CLOG_TRACE(Herder,
                           "Got a bad close time for ledger {}, got {} vs {}",
                           slotIndex, b.closeTime, lastCloseTime);
                return pogcvmDriver::kInvalidValue;
            }
        }
        else if (slotIndex < lcl.ledgerSeq)
        {
            // basic sanity check on older value
            if (b.closeTime >= lastCloseTime)
            {
                CLOG_TRACE(Herder,
                           "Got a bad close time for ledger {}, got {} vs {}",
                           slotIndex, b.closeTime, lastCloseTime);
                return pogcvmDriver::kInvalidValue;
            }
        }
        else if (!checkCloseTime(slotIndex, lastCloseTime, b))
        {
            // future messages must be valid compared to lastCloseTime
            return pogcvmDriver::kInvalidValue;
        }

        if (!mHerder.isTracking())
        {
            // if we're not tracking, there is not much more we can do to
            // validate
            CLOG_TRACE(Herder, "MaybeValidValue (not tracking) for slot {}",
                       slotIndex);
            return pogcvmDriver::kMaybeValidValue;
        }

        // Check slotIndex.
        if (mHerder.nextvalidationLedgerIndex() > slotIndex)
        {
            // we already moved on from this slot
            // still send it through for emitting the final messages
            CLOG_TRACE(Herder,
                       "MaybeValidValue (already moved on) for slot {}, at {}",
                       slotIndex, mHerder.nextvalidationLedgerIndex());
            return pogcvmDriver::kMaybeValidValue;
        }
        if (mHerder.nextvalidationLedgerIndex() < slotIndex)
        {
            // this is probably a bug as "tracking" means we're processing
            // messages only for smaller slots
            CLOG_ERROR(
                Herder,
                "HerderpogcvmDriver::validateValue i: {} processing a future "
                "message while tracking {} ",
                slotIndex, mHerder.trackingvalidationLedgerIndex());
            return pogcvmDriver::kInvalidValue;
        }

        // when tracking, we use the tracked time for last close time
        lastCloseTime = mHerder.trackingvalidationCloseTime();
        if (!checkCloseTime(slotIndex, lastCloseTime, b))
        {
            return pogcvmDriver::kInvalidValue;
        }

        // this is as far as we can go if we don't have the state
        CLOG_TRACE(Herder,
                   "Can't validate locally, value may be valid for slot {}",
                   slotIndex);
        return pogcvmDriver::kMaybeValidValue;
    }

    // the value is against the local state, we can perform all checks

    if (!checkCloseTime(slotIndex, lastCloseTime, b))
    {
        return pogcvmDriver::kInvalidValue;
    }

    Hash const& txSetHash = b.txSetHash;
    TxSetFramePtr txSet = mPendingEnvelopes.getTxSet(txSetHash);

    pogcvmDriver::ValidationLevel res;

    auto closeTimeOffset = b.closeTime - lastCloseTime;

    if (!txSet)
    {
        CLOG_ERROR(Herder, "validateValue i:{} unknown txSet {}", slotIndex,
                   hexAbbrev(txSetHash));

        res = pogcvmDriver::kInvalidValue;
    }
    else if (!txSet->checkValid(mApp, closeTimeOffset, closeTimeOffset))
    {
        CLOG_DEBUG(Herder,
                   "HerderpogcvmDriver::validateValue i: {} invalid txSet {}",
                   slotIndex, hexAbbrev(txSetHash));
        res = pogcvmDriver::kInvalidValue;
    }
    else
    {
        CLOG_DEBUG(Herder,
                   "HerderpogcvmDriver::validateValue i: {} valid txSet {}",
                   slotIndex, hexAbbrev(txSetHash));
        res = pogcvmDriver::kFullyValidatedValue;
    }
    return res;
}

pogcvmDriver::ValidationLevel
HerderpogcvmDriver::validateValue(uint64_t slotIndex, Value const& value,
                               bool nomination)
{
    ZoneScoped;
    POGchainValue b;
    try
    {
        ZoneNamedN(xdrZone, "XDR deserialize", true);
        xdr::xdr_from_opaque(value, b);
    }
    catch (...)
    {
        mpogcvmMetrics.mValueInvalid.Mark();
        return pogcvmDriver::kInvalidValue;
    }

    pogcvmDriver::ValidationLevel res =
        validateValueHelper(slotIndex, b, nomination);
    if (res != pogcvmDriver::kInvalidValue)
    {
        auto const& lcl = mLedgerManager.getLastClosedLedgerHeader();

        LedgerUpgradeType lastUpgradeType = LEDGER_UPGRADE_VERSION;
        // check upgrades
        for (size_t i = 0;
             i < b.upgrades.size() && res != pogcvmDriver::kInvalidValue; i++)
        {
            LedgerUpgradeType thisUpgradeType;
            if (!mUpgrades.isValid(b.upgrades[i], thisUpgradeType, nomination,
                                   mApp.getConfig(), lcl.header))
            {
                CLOG_TRACE(
                    Herder,
                    "HerderpogcvmDriver::validateValue invalid step at index {}",
                    i);
                res = pogcvmDriver::kInvalidValue;
            }
            else if (i != 0 && (lastUpgradeType >= thisUpgradeType))
            {
                CLOG_TRACE(Herder,
                           "HerderpogcvmDriver::validateValue out of "
                           "order upgrade step at index {}",
                           i);
                res = pogcvmDriver::kInvalidValue;
            }

            lastUpgradeType = thisUpgradeType;
        }
    }

    if (res)
    {
        mpogcvmMetrics.mValueValid.Mark();
    }
    else
    {
        mpogcvmMetrics.mValueInvalid.Mark();
    }
    return res;
}

ValueWrapperPtr
HerderpogcvmDriver::extractValidValue(uint64_t slotIndex, Value const& value)
{
    ZoneScoped;
    POGchainValue b;
    try
    {
        xdr::xdr_from_opaque(value, b);
    }
    catch (...)
    {
        return nullptr;
    }
    ValueWrapperPtr res;
    if (validateValueHelper(slotIndex, b, true) ==
        pogcvmDriver::kFullyValidatedValue)
    {
        auto const& lcl = mLedgerManager.getLastClosedLedgerHeader();

        // remove the upgrade steps we don't like
        LedgerUpgradeType thisUpgradeType;
        for (auto it = b.upgrades.begin(); it != b.upgrades.end();)
        {
            if (!mUpgrades.isValid(*it, thisUpgradeType, true, mApp.getConfig(),
                                   lcl.header))
            {
                it = b.upgrades.erase(it);
            }
            else
            {
                it++;
            }
        }

        res = wrapPOGchainValue(b);
    }

    return res;
}

// value marshaling

std::string
HerderpogcvmDriver::toShortString(NodeID const& pk) const
{
    return mApp.getConfig().toShortString(pk);
}

std::string
HerderpogcvmDriver::getValueString(Value const& v) const
{
    POGchainValue b;
    if (v.empty())
    {
        return "[:empty:]";
    }

    try
    {
        xdr::xdr_from_opaque(v, b);

        return POGchainValueToString(mApp.getConfig(), b);
    }
    catch (...)
    {
        return "[:invalid:]";
    }
}

// timer handling
void
HerderpogcvmDriver::timerCallbackWrapper(uint64_t slotIndex, int timerID,
                                      std::function<void()> cb)
{
    // reschedule timers for future slots when tracking
    if (mHerder.isTracking() && mHerder.nextvalidationLedgerIndex() != slotIndex)
    {
        CLOG_WARNING(
            Herder, "Herder rescheduled timer {} for slot {} with next slot {}",
            timerID, slotIndex, mHerder.nextvalidationLedgerIndex());
        setupTimer(slotIndex, timerID, std::chrono::seconds(1),
                   std::bind(&HerderpogcvmDriver::timerCallbackWrapper, this,
                             slotIndex, timerID, cb));
    }
    else
    {
        auto pogcvmTimingIt = mpogcvmExecutionTimes.find(slotIndex);
        if (pogcvmTimingIt != mpogcvmExecutionTimes.end())
        {
            auto& pogcvmTiming = pogcvmTimingIt->second;
            if (timerID == Slot::BALLOT_PROTOCOL_TIMER)
            {
                // Timeout happened in between first prepare and externalize
                ++pogcvmTiming.mPrepareTimeoutCount;
            }
            else
            {
                if (!pogcvmTiming.mPrepareStart)
                {
                    // Timeout happened between nominate and first prepare
                    ++pogcvmTiming.mNominationTimeoutCount;
                }
            }
        }

        cb();
    }
}

void
HerderpogcvmDriver::setupTimer(uint64_t slotIndex, int timerID,
                            std::chrono::milliseconds timeout,
                            std::function<void()> cb)
{
    // don't setup timers for old slots
    if (slotIndex <= mApp.getHerder().trackingvalidationLedgerIndex())
    {
        mpogcvmTimers.erase(slotIndex);
        return;
    }

    auto& slotTimers = mpogcvmTimers[slotIndex];

    auto it = slotTimers.find(timerID);
    if (it == slotTimers.end())
    {
        it = slotTimers.emplace(timerID, std::make_unique<VirtualTimer>(mApp))
                 .first;
    }
    auto& timer = *it->second;
    timer.cancel();
    if (cb)
    {
        timer.expires_from_now(timeout);
        timer.async_wait(std::bind(&HerderpogcvmDriver::timerCallbackWrapper, this,
                                   slotIndex, timerID, cb),
                         &VirtualTimer::onFailureNoop);
    }
}

// returns true if l < r
// lh, rh are the hashes of l,h
static bool
compareTxSets(TxSetFrameConstPtr l, TxSetFrameConstPtr r, Hash const& lh,
              Hash const& rh, LedgerHeader const& header, Hash const& s)
{
    if (l == nullptr)
    {
        return r != nullptr;
    }
    if (r == nullptr)
    {
        return false;
    }
    auto lSize = l->size(header);
    auto rSize = r->size(header);
    if (lSize < rSize)
    {
        return true;
    }
    else if (lSize > rSize)
    {
        return false;
    }
    if (header.ledgerVersion >= 11)
    {
        auto lFee = l->getTotalFees(header);
        auto rFee = r->getTotalFees(header);
        if (lFee < rFee)
        {
            return true;
        }
        else if (lFee > rFee)
        {
            return false;
        }
    }
    return lessThanXored(lh, rh, s);
}

ValueWrapperPtr
HerderpogcvmDriver::combineCandidates(uint64_t slotIndex,
                                   ValueWrapperPtrSet const& candidates)
{
    ZoneScoped;
    CLOG_DEBUG(Herder, "Combining {} candidates", candidates.size());
    mpogcvmMetrics.mCombinedCandidates.Mark(candidates.size());

    std::map<LedgerUpgradeType, LedgerUpgrade> upgrades;

    std::set<TransactionFramePtr> aggSet;

    auto const& lcl = mLedgerManager.getLastClosedLedgerHeader();

    Hash candidatesHash;

    std::vector<POGchainValue> candidateValues;

    for (auto const& c : candidates)
    {
        candidateValues.emplace_back();
        POGchainValue& sv = candidateValues.back();

        xdr::xdr_from_opaque(c->getValue(), sv);
        candidatesHash ^= sha256(c->getValue());

        for (auto const& upgrade : sv.upgrades)
        {
            LedgerUpgrade lupgrade;
            xdr::xdr_from_opaque(upgrade, lupgrade);
            auto it = upgrades.find(lupgrade.type());
            if (it == upgrades.end())
            {
                upgrades.emplace(std::make_pair(lupgrade.type(), lupgrade));
            }
            else
            {
                LedgerUpgrade& clUpgrade = it->second;
                switch (lupgrade.type())
                {
                case LEDGER_UPGRADE_VERSION:
                    // pick the highest version
                    clUpgrade.newLedgerVersion() =
                        std::max(clUpgrade.newLedgerVersion(),
                                 lupgrade.newLedgerVersion());
                    break;
                case LEDGER_UPGRADE_BASE_FEE:
                    // take the max fee
                    clUpgrade.newBaseFee() =
                        std::max(clUpgrade.newBaseFee(), lupgrade.newBaseFee());
                    break;
                case LEDGER_UPGRADE_MAX_TX_SET_SIZE:
                    // take the max tx set size
                    clUpgrade.newMaxTxSetSize() =
                        std::max(clUpgrade.newMaxTxSetSize(),
                                 lupgrade.newMaxTxSetSize());
                    break;
                case LEDGER_UPGRADE_BASE_RESERVE:
                    // take the max base reserve
                    clUpgrade.newBaseReserve() = std::max(
                        clUpgrade.newBaseReserve(), lupgrade.newBaseReserve());
                    break;
                default:
                    // should never get there with values that are not valid
                    throw std::runtime_error("invalid upgrade step");
                }
            }
        }
    }

    POGchainValue comp;
    // take the txSet with the biggest size, highest xored hash that we have
    {
        auto highest = candidateValues.cend();
        TxSetFrameConstPtr highestTxSet;
        for (auto it = candidateValues.cbegin(); it != candidateValues.cend();
             ++it)
        {
            auto const& sv = *it;
            auto const cTxSet = mPendingEnvelopes.getTxSet(sv.txSetHash);
            if (cTxSet && cTxSet->previousLedgerHash() == lcl.hash &&
                (!highestTxSet ||
                 compareTxSets(highestTxSet, cTxSet, highest->txSetHash,
                               sv.txSetHash, lcl.header, candidatesHash)))
            {
                highest = it;
                highestTxSet = cTxSet;
            }
        };
        if (highest == candidateValues.cend())
        {
            throw std::runtime_error(
                "No highest candidate transaction set found");
        }
        comp = *highest;
    }
    comp.upgrades.clear();
    for (auto const& upgrade : upgrades)
    {
        Value v(xdr::xdr_to_opaque(upgrade.second));
        comp.upgrades.emplace_back(v.begin(), v.end());
    }

    auto res = wrapPOGchainValue(comp);
    return res;
}

bool
HerderpogcvmDriver::toPOGchainValue(Value const& v, POGchainValue& sv)
{
    try
    {
        xdr::xdr_from_opaque(v, sv);
    }
    catch (...)
    {
        return false;
    }
    return true;
}

void
HerderpogcvmDriver::valueExternalized(uint64_t slotIndex, Value const& value)
{
    ZoneScoped;
    auto it = mpogcvmTimers.begin(); // cancel all timers below this slot
    while (it != mpogcvmTimers.end() && it->first <= slotIndex)
    {
        it = mpogcvmTimers.erase(it);
    }

    POGchainValue b;
    try
    {
        xdr::xdr_from_opaque(value, b);
    }
    catch (...)
    {
        // This may not be possible as all messages are validated and should
        // therefore contain a valid POGchainValue.
        CLOG_ERROR(Herder, "HerderpogcvmDriver::valueExternalized "
                           "Externalized POGchainValue malformed");
        CLOG_ERROR(Herder, "{}", REPORT_INTERNAL_BUG);
        // no point in continuing as 'b' contains garbage at this point
        abort();
    }

    // externalize may trigger on older slots:
    //  * when the current instance starts up
    //  * when getting back in sync (a gap potentially opened)
    // in both cases do limited processing on older slots; more importantly,
    // deliver externalize events to LedgerManager
    bool isLatestSlot =
        slotIndex > mApp.getHerder().trackingvalidationLedgerIndex();

    // Only update tracking state when newer slot comes in
    if (isLatestSlot)
    {
        // log information from older ledger to increase the chances that
        // all messages made it
        if (slotIndex > 2)
        {
            logQuorumInformation(slotIndex - 2);
        }

        if (mCurrentValue)
        {
            // stop nomination
            // this may or may not be the ledger that is currently externalizing
            // in both cases, we want to stop nomination as:
            // either we're closing the current ledger (typical case)
            // or we're going to trigger catchup from history
            mpogcvm.stopNomination(mLedgerSeqNominating);
            mCurrentValue.reset();
        }

        if (!mHerder.isTracking())
        {
            stateChanged();
        }

        mHerder.setTrackingpogcvmState(slotIndex, b, /* isTrackingNetwork */ true);

        // record lag
        recordpogcvmExternalizeEvent(slotIndex, mpogcvm.getLocalNodeID(), false);

        recordpogcvmExecutionMetrics(slotIndex);

        mHerder.valueExternalized(slotIndex, b, isLatestSlot);

        // update externalize time so that we don't include the time spent in
        // `mHerder.valueExternalized`
        recordpogcvmExternalizeEvent(slotIndex, mpogcvm.getLocalNodeID(), true);
    }
    else
    {
        mHerder.valueExternalized(slotIndex, b, isLatestSlot);
    }
}

void
HerderpogcvmDriver::logQuorumInformation(uint64_t index)
{
    std::string res;
    auto v = mApp.getHerder().getJsonQuorumInfo(mpogcvm.getLocalNodeID(), true,
                                                false, index);
    auto qset = v.get("qset", "");
    if (!qset.empty())
    {
        Json::FastWriter fw;
        CLOG_INFO(Herder, "Quorum information for {} : {}", index,
                  fw.write(qset));
    }
}

void
HerderpogcvmDriver::nominate(uint64_t slotIndex, POGchainValue const& value,
                          TxSetFramePtr proposedSet,
                          POGchainValue const& previousValue)
{
    ZoneScoped;
    mCurrentValue = wrapPOGchainValue(value);
    mLedgerSeqNominating = static_cast<uint32_t>(slotIndex);

    auto valueHash = xdrSha256(mCurrentValue->getValue());
    CLOG_DEBUG(Herder,
               "HerderpogcvmDriver::triggerNextLedger txSet.size: {} "
               "previousLedgerHash: {} value: {} slot: {}",
               proposedSet->mTransactions.size(),
               hexAbbrev(proposedSet->previousLedgerHash()),
               hexAbbrev(valueHash), slotIndex);

    auto prevValue = xdr::xdr_to_opaque(previousValue);
    mpogcvm.nominate(slotIndex, mCurrentValue, prevValue);
}

pogcvmQuorumSetPtr
HerderpogcvmDriver::getQSet(Hash const& qSetHash)
{
    return mPendingEnvelopes.getQSet(qSetHash);
}

void
HerderpogcvmDriver::ballotDidHearFromQuorum(uint64_t, pogcvmBallot const&)
{
}

void
HerderpogcvmDriver::nominatingValue(uint64_t slotIndex, Value const& value)
{
    CLOG_DEBUG(Herder, "nominatingValue i:{} v: {}", slotIndex,
               getValueString(value));
}

void
HerderpogcvmDriver::updatedCandidateValue(uint64_t slotIndex, Value const& value)
{
}

void
HerderpogcvmDriver::startedBallotProtocol(uint64_t slotIndex,
                                       pogcvmBallot const& ballot)
{
    recordpogcvmEvent(slotIndex, false);
}
void
HerderpogcvmDriver::acceptedBallotPrepared(uint64_t slotIndex,
                                        pogcvmBallot const& ballot)
{
}

void
HerderpogcvmDriver::confirmedBallotPrepared(uint64_t slotIndex,
                                         pogcvmBallot const& ballot)
{
}

void
HerderpogcvmDriver::acceptedCommit(uint64_t slotIndex, pogcvmBallot const& ballot)
{
}

std::optional<VirtualClock::time_point>
HerderpogcvmDriver::getPrepareStart(uint64_t slotIndex)
{
    std::optional<VirtualClock::time_point> res;
    auto it = mpogcvmExecutionTimes.find(slotIndex);
    if (it != mpogcvmExecutionTimes.end())
    {
        res = it->second.mPrepareStart;
    }
    return res;
}

Json::Value
HerderpogcvmDriver::getQsetLagInfo(bool summary, bool fullKeys)
{
    Json::Value ret;
    double totalLag = 0;
    int numNodes = 0;

    auto qSet = getpogcvm().getLocalQuorumSet();
    LocalNode::forAllNodes(qSet, [&](NodeID const& n) {
        auto lag = getExternalizeLag(n);
        if (lag > 0)
        {
            if (!summary)
            {
                ret[toStrKey(n, fullKeys)] = static_cast<Json::UInt64>(lag);
            }
            else
            {
                totalLag += lag;
                numNodes++;
            }
        }
        return true;
    });

    if (summary && numNodes > 0)
    {
        double avgLag = totalLag / numNodes;
        ret = static_cast<Json::UInt64>(avgLag);
    }

    return ret;
}

double
HerderpogcvmDriver::getExternalizeLag(NodeID const& id) const
{
    auto n = mQSetLag.find(id);

    if (n == mQSetLag.end())
    {
        return 0.0;
    }

    return n->second.GetSnapshot().get75thPercentile();
}

void
HerderpogcvmDriver::recordpogcvmEvent(uint64_t slotIndex, bool isNomination)
{

    auto& timing = mpogcvmExecutionTimes[slotIndex];
    VirtualClock::time_point start = mApp.getClock().now();

    if (isNomination)
    {
        timing.mNominationStart =
            std::make_optional<VirtualClock::time_point>(start);
    }
    else
    {
        timing.mPrepareStart =
            std::make_optional<VirtualClock::time_point>(start);
    }
}

void
HerderpogcvmDriver::recordpogcvmExternalizeEvent(uint64_t slotIndex, NodeID const& id,
                                           bool forceUpdateSelf)
{
    auto& timing = mpogcvmExecutionTimes[slotIndex];
    auto now = mApp.getClock().now();

    if (!timing.mFirstExternalize)
    {
        timing.mFirstExternalize =
            std::make_optional<VirtualClock::time_point>(now);
    }

    if (id == mpogcvm.getLocalNodeID())
    {
        if (!timing.mSelfExternalize)
        {
            recordLogTiming(*timing.mFirstExternalize, now,
                            mpogcvmMetrics.mFirstToSelfExternalizeLag,
                            "first to self externalize lag",
                            std::chrono::nanoseconds::zero(), slotIndex);
        }
        if (!timing.mSelfExternalize || forceUpdateSelf)
        {
            timing.mSelfExternalize =
                std::make_optional<VirtualClock::time_point>(now);
        }
    }
    else
    {
        // Record externalize delay
        if (timing.mSelfExternalize)
        {
            recordLogTiming(
                *timing.mSelfExternalize, now,
                mpogcvmMetrics.mSelfToOthersExternalizeLag,
                fmt::format(FMT_STRING("self to {} externalize lag"),
                            toShortString(id)),
                std::chrono::nanoseconds::zero(), slotIndex);
        }

        // Record lag for other nodes
        auto& lag = mQSetLag[id];
        recordLogTiming(*timing.mFirstExternalize, now, lag,
                        fmt::format(FMT_STRING("first to {} externalize lag"),
                                    toShortString(id)),
                        std::chrono::nanoseconds::zero(), slotIndex);
    }
}

void
HerderpogcvmDriver::recordLogTiming(VirtualClock::time_point start,
                                 VirtualClock::time_point end,
                                 medida::Timer& timer,
                                 std::string const& logStr,
                                 std::chrono::nanoseconds threshold,
                                 uint64_t slotIndex)
{
    auto delta =
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    CLOG_DEBUG(
        Herder, "{} delta for slot {} is {} ms", logStr, slotIndex,
        std::chrono::duration_cast<std::chrono::milliseconds>(delta).count());
    if (delta >= threshold)
    {
        timer.Update(delta);
    }
};

void
HerderpogcvmDriver::recordpogcvmExecutionMetrics(uint64_t slotIndex)
{
    auto externalizeStart = mApp.getClock().now();

    // Use threshold of 0 in case of a single node
    auto& qset = mApp.getConfig().QUORUM_SET;
    auto isSingleNode = qset.innerSets.size() == 0 &&
                        qset.validators.size() == 1 &&
                        qset.validators[0] == getpogcvm().getLocalNodeID();
    auto threshold = isSingleNode ? std::chrono::nanoseconds::zero()
                                  : Herder::TIMERS_THRESHOLD_NANOSEC;

    auto pogcvmTimingIt = mpogcvmExecutionTimes.find(slotIndex);
    if (pogcvmTimingIt == mpogcvmExecutionTimes.end())
    {
        return;
    }

    auto& pogcvmTiming = pogcvmTimingIt->second;

    mNominateTimeout.Update(pogcvmTiming.mNominationTimeoutCount);
    mPrepareTimeout.Update(pogcvmTiming.mPrepareTimeoutCount);

    // Compute nomination time
    if (pogcvmTiming.mNominationStart && pogcvmTiming.mPrepareStart)
    {
        recordLogTiming(*pogcvmTiming.mNominationStart, *pogcvmTiming.mPrepareStart,
                        mpogcvmMetrics.mNominateToPrepare, "Nominate", threshold,
                        slotIndex);
    }

    // Compute prepare time
    if (pogcvmTiming.mPrepareStart)
    {
        recordLogTiming(*pogcvmTiming.mPrepareStart, externalizeStart,
                        mpogcvmMetrics.mPrepareToExternalize, "Prepare", threshold,
                        slotIndex);
    }
}

void
HerderpogcvmDriver::purgeSlots(uint64_t maxSlotIndex)
{
    // Clean up timings map
    auto it = mpogcvmExecutionTimes.begin();
    while (it != mpogcvmExecutionTimes.end() && it->first < maxSlotIndex)
    {
        it = mpogcvmExecutionTimes.erase(it);
    }

    getpogcvm().purgeSlots(maxSlotIndex);
}

void
HerderpogcvmDriver::clearpogcvmExecutionEvents()
{
    mpogcvmExecutionTimes.clear();
}

// Value handling
class pogcvmHerderValueWrapper : public ValueWrapper
{
    HerderImpl& mHerder;

    TxSetFramePtr mTxSet;

  public:
    explicit pogcvmHerderValueWrapper(POGchainValue const& sv, Value const& value,
                                   HerderImpl& herder)
        : ValueWrapper(value), mHerder(herder)
    {
        mTxSet = mHerder.getTxSet(sv.txSetHash);
        if (!mTxSet)
        {
            throw std::runtime_error(fmt::format(
                FMT_STRING(
                    "pogcvmHerderValueWrapper tried to bind an unknown tx set {}"),
                hexAbbrev(sv.txSetHash)));
        }
    }
};

ValueWrapperPtr
HerderpogcvmDriver::wrapValue(Value const& val)
{
    POGchainValue sv;
    auto b = mHerder.getHerderpogcvmDriver().toPOGchainValue(val, sv);
    if (!b)
    {
        throw std::runtime_error(
            fmt::format(FMT_STRING("Invalid value in pogcvmHerderValueWrapper {}"),
                        binToHex(val)));
    }
    auto res = std::make_shared<pogcvmHerderValueWrapper>(sv, val, mHerder);
    return res;
}

ValueWrapperPtr
HerderpogcvmDriver::wrapPOGchainValue(POGchainValue const& sv)
{
    auto val = xdr::xdr_to_opaque(sv);
    auto res = std::make_shared<pogcvmHerderValueWrapper>(sv, val, mHerder);
    return res;
}
}
