#pragma once

// Copyright 2017 POGchain Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "herder/Herder.h"
#include "herder/TxSetFrame.h"
#include "medida/timer.h"
#include "pogcvm/pogcvmDriver.h"
#include "xdr/POGchain-ledger.h"
#include <optional>

namespace medida
{
class Counter;
class Meter;
class Histogram;
}

namespace POGchain
{
class Application;
class HerderImpl;
class LedgerManager;
class PendingEnvelopes;
class pogcvm;
class Upgrades;
class VirtualTimer;
struct POGchainValue;
struct pogcvmEnvelope;

class HerderpogcvmDriver : public pogcvmDriver
{
  public:
    HerderpogcvmDriver(Application& app, HerderImpl& herder,
                    Upgrades const& upgrades,
                    PendingEnvelopes& pendingEnvelopes);
    ~HerderpogcvmDriver();

    void bootstrap();
    void stateChanged();

    pogcvm&
    getpogcvm()
    {
        return mpogcvm;
    }

    void recordpogcvmExecutionMetrics(uint64_t slotIndex);
    void recordpogcvmEvent(uint64_t slotIndex, bool isNomination);
    void recordpogcvmExternalizeEvent(uint64_t slotIndex, NodeID const& id,
                                   bool forceUpdateSelf);

    // envelope handling
    pogcvmEnvelopeWrapperPtr wrapEnvelope(pogcvmEnvelope const& envelope) override;
    void signEnvelope(pogcvmEnvelope& envelope) override;
    void emitEnvelope(pogcvmEnvelope const& envelope) override;

    // value validation
    pogcvmDriver::ValidationLevel validateValue(uint64_t slotIndex,
                                             Value const& value,
                                             bool nomination) override;
    ValueWrapperPtr extractValidValue(uint64_t slotIndex,
                                      Value const& value) override;

    // value marshaling
    std::string toShortString(NodeID const& pk) const override;
    std::string getValueString(Value const& v) const override;

    // timer handling
    void setupTimer(uint64_t slotIndex, int timerID,
                    std::chrono::milliseconds timeout,
                    std::function<void()> cb) override;

    // hashing support
    Hash getHashOf(std::vector<xdr::opaque_vec<>> const& vals) const override;

    //  pogcvm
    ValueWrapperPtr
    combineCandidates(uint64_t slotIndex,
                      ValueWrapperPtrSet const& candidates) override;
    void valueExternalized(uint64_t slotIndex, Value const& value) override;

    // Submit a value to consider for slotIndex
    // previousValue is the value from slotIndex-1
    void nominate(uint64_t slotIndex, POGchainValue const& value,
                  TxSetFramePtr proposedSet, POGchainValue const& previousValue);

    pogcvmQuorumSetPtr getQSet(Hash const& qSetHash) override;

    // listeners
    void ballotDidHearFromQuorum(uint64_t slotIndex,
                                 pogcvmBallot const& ballot) override;
    void nominatingValue(uint64_t slotIndex, Value const& value) override;
    void updatedCandidateValue(uint64_t slotIndex, Value const& value) override;
    void startedBallotProtocol(uint64_t slotIndex,
                               pogcvmBallot const& ballot) override;
    void acceptedBallotPrepared(uint64_t slotIndex,
                                pogcvmBallot const& ballot) override;
    void confirmedBallotPrepared(uint64_t slotIndex,
                                 pogcvmBallot const& ballot) override;
    void acceptedCommit(uint64_t slotIndex, pogcvmBallot const& ballot) override;

    std::optional<VirtualClock::time_point> getPrepareStart(uint64_t slotIndex);

    // converts a Value into a POGchainValue
    // returns false on error
    bool toPOGchainValue(Value const& v, POGchainValue& sv);

    // validate close time as much as possible
    bool checkCloseTime(uint64_t slotIndex, uint64_t lastCloseTime,
                        POGchainValue const& b) const;

    // wraps a *valid* POGchainValue (throws if it can't find txSet/qSet)
    ValueWrapperPtr wrapPOGchainValue(POGchainValue const& sv);

    ValueWrapperPtr wrapValue(Value const& sv) override;

    // clean up older slots
    void purgeSlots(uint64_t maxSlotIndex);

    double getExternalizeLag(NodeID const& id) const;

    Json::Value getQsetLagInfo(bool summary, bool fullKeys);

  private:
    Application& mApp;
    HerderImpl& mHerder;
    LedgerManager& mLedgerManager;
    Upgrades const& mUpgrades;
    PendingEnvelopes& mPendingEnvelopes;
    pogcvm mpogcvm;

    struct pogcvmMetrics
    {
        medida::Meter& mEnvelopeSign;

        medida::Meter& mValueValid;
        medida::Meter& mValueInvalid;

        // listeners
        medida::Meter& mCombinedCandidates;

        // Timers for nomination and ballot protocols
        medida::Timer& mNominateToPrepare;
        medida::Timer& mPrepareToExternalize;

        // Timers tracking externalize messages
        medida::Timer& mFirstToSelfExternalizeLag;
        medida::Timer& mSelfToOthersExternalizeLag;

        pogcvmMetrics(Application& app);
    };

    pogcvmMetrics mpogcvmMetrics;

    // Nomination timeouts per ledger
    medida::Histogram& mNominateTimeout;
    // Prepare timeouts per ledger
    medida::Histogram& mPrepareTimeout;

    // Externalize lag tracking for nodes in qset
    UnorderedMap<NodeID, medida::Timer> mQSetLag;

    struct pogcvmTiming
    {
        std::optional<VirtualClock::time_point> mNominationStart;
        std::optional<VirtualClock::time_point> mPrepareStart;

        // Nomination timeouts before first prepare
        int64_t mNominationTimeoutCount{0};
        // Prepare timeouts before externalize
        int64_t mPrepareTimeoutCount{0};

        // externalize timing information
        std::optional<VirtualClock::time_point> mFirstExternalize;
        std::optional<VirtualClock::time_point> mSelfExternalize;
    };

    // Map of time points for each slot to measure key protocol metrics:
    // * nomination to first prepare
    // * first prepare to externalize
    std::map<uint64_t, pogcvmTiming> mpogcvmExecutionTimes;

    uint32_t mLedgerSeqNominating;
    ValueWrapperPtr mCurrentValue;

    // timers used by pogcvm
    // indexed by slotIndex, timerID
    std::map<uint64_t, std::map<int, std::unique_ptr<VirtualTimer>>> mpogcvmTimers;

    pogcvmDriver::ValidationLevel validateValueHelper(uint64_t slotIndex,
                                                   POGchainValue const& sv,
                                                   bool nomination) const;

    void logQuorumInformation(uint64_t index);

    void clearpogcvmExecutionEvents();

    void timerCallbackWrapper(uint64_t slotIndex, int timerID,
                              std::function<void()> cb);

    void recordLogTiming(VirtualClock::time_point start,
                         VirtualClock::time_point end, medida::Timer& timer,
                         std::string const& logStr,
                         std::chrono::nanoseconds threshold,
                         uint64_t slotIndex);
};
}
