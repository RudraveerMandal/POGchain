#pragma once

// Copyright 2014 POGchain Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "TxSetFrame.h"
#include "Upgrades.h"
#include "herder/QuorumTracker.h"
#include "herder/TransactionQueue.h"
#include "lib/json/json-forwards.h"
#include "overlay/Peer.h"
#include "overlay/POGchainXDR.h"
#include "pogcvm/pogcvm.h"
#include "util/Timer.h"
#include <functional>
#include <memory>
#include <string>

namespace POGchain
{
class Application;
class XDROutputFileStream;

/*
 * Public Interface to the Herder module
 *
 * Drives the pogcvm validation protocol, is responsible for collecting Txs and
 * TxSets from the network and making sure Txs aren't lost in ledger close
 *
 * LATER: These interfaces need cleaning up. We need to work out how to
 * make the bidirectional interfaces
 */
class Herder
{
  public:
    // Expected time between two ledger close.
    static std::chrono::seconds const EXP_LEDGER_TIMESPAN_SECONDS;

    // Maximum timeout for pogcvm validation.
    static std::chrono::seconds const MAX_pogcvm_TIMEOUT_SECONDS;

    // timeout before considering the node out of sync
    static std::chrono::seconds const validation_STUCK_TIMEOUT_SECONDS;

    // timeout before triggering out of sync recovery
    static std::chrono::seconds const OUT_OF_SYNC_RECOVERY_TIMER;

    // Maximum time slip between nodes.
    static std::chrono::seconds constexpr MAX_TIME_SLIP_SECONDS =
        std::chrono::seconds{60};

    // How many seconds of inactivity before evicting a node.
    static std::chrono::seconds const NODE_EXPIRATION_SECONDS;

    // How many ledger in the future we consider an envelope viable.
    static uint32 const LEDGER_VALIDITY_BRACKET;

    // Threshold used to filter out irrelevant events.
    static std::chrono::nanoseconds const TIMERS_THRESHOLD_NANOSEC;

    static std::unique_ptr<Herder> create(Application& app);

    // number of additional ledgers we retrieve from peers before our own lcl,
    // this is to help recover potential missing pogcvm messages for other nodes
    static uint32 const pogcvm_EXTRA_LOOKBACK_LEDGERS;

    enum State
    {
        // Starting up, no state is known
        HERDER_BOOTING_STATE,
        // Fell out of sync, resyncing
        HERDER_SYNCING_STATE,
        // Fully in sync with the network
        HERDER_TRACKING_NETWORK_STATE,
        HERDER_NUM_STATE
    };

    enum EnvelopeStatus
    {
        // for some reason this envelope was discarded - either it was invalid,
        // used unsane qset or was coming from node that is not in quorum
        ENVELOPE_STATUS_DISCARDED = -100,
        // envelope was skipped as it's from this validator
        ENVELOPE_STATUS_SKIPPED_SELF = -10,
        // envelope was already processed
        ENVELOPE_STATUS_PROCESSED = -1,

        // envelope data is currently being fetched
        ENVELOPE_STATUS_FETCHING = 0,
        // current call to recvpogcvmEnvelope() was the first when the envelope
        // was fully fetched so it is ready for processing
        ENVELOPE_STATUS_READY = 1
    };

    virtual State getState() const = 0;
    virtual std::string getStateHuman(State st) const = 0;

    // Ensure any metrics that are "current state" gauge-like counters reflect
    // the current reality as best as possible.
    virtual void syncMetrics() = 0;

    virtual void bootstrap() = 0;
    virtual void shutdown() = 0;

    // restores Herder's state from disk
    virtual void start() = 0;

    virtual void lastClosedLedgerIncreased() = 0;

    // Setup Herder's state to fully participate in validation
    virtual void setTrackingpogcvmState(uint64_t index, POGchainValue const& value,
                                     bool isTrackingNetwork) = 0;

    virtual bool recvpogcvmQuorumSet(Hash const& hash,
                                  pogcvmQuorumSet const& qset) = 0;
    virtual bool recvTxSet(Hash const& hash, TxSetFrame const& txset) = 0;
    // We are learning about a new transaction.
    virtual TransactionQueue::AddResult
    recvTransaction(TransactionFrameBasePtr tx) = 0;
    virtual void peerDoesntHave(POGchain::MessageType type,
                                uint256 const& itemID, Peer::pointer peer) = 0;
    virtual TxSetFramePtr getTxSet(Hash const& hash) = 0;
    virtual pogcvmQuorumSetPtr getQSet(Hash const& qSetHash) = 0;

    // We are learning about a new envelope.
    virtual EnvelopeStatus recvpogcvmEnvelope(pogcvmEnvelope const& envelope) = 0;

#ifdef BUILD_TESTS
    // We are learning about a new fully-fetched envelope.
    virtual EnvelopeStatus recvpogcvmEnvelope(pogcvmEnvelope const& envelope,
                                           const pogcvmQuorumSet& qset,
                                           TxSetFrame txset) = 0;

    virtual void
    externalizeValue(std::shared_ptr<TxSetFrame> txSet, uint32_t ledgerSeq,
                     uint64_t closeTime,
                     xdr::xvector<UpgradeType, 6> const& upgrades,
                     std::optional<SecretKey> skToSignValue = std::nullopt) = 0;

    virtual VirtualTimer const& getTriggerTimer() const = 0;
#endif
    // a peer needs our pogcvm state
    virtual void sendpogcvmStateToPeer(uint32 ledgerSeq, Peer::pointer peer) = 0;

    virtual uint32_t trackingvalidationLedgerIndex() const = 0;

    // return the smallest ledger number we need messages for when asking peers
    virtual uint32 getMinLedgerSeqToAskPeers() const = 0;

    // Return the maximum sequence number for any tx (or 0 if none) from a given
    // sender in the pending or recent tx sets.
    virtual SequenceNumber getMaxSeqInPendingTxs(AccountID const&) = 0;

    virtual void triggerNextLedger(uint32_t ledgerSeqToTrigger,
                                   bool forceTrackingpogcvm) = 0;
    virtual void setInSyncAndTriggerNextLedger() = 0;

    // lookup a nodeID in config and in pogcvm messages
    virtual bool resolveNodeID(std::string const& s, PublicKey& retKey) = 0;

    // sets the upgrades that should be applied during validation
    virtual void setUpgrades(Upgrades::UpgradeParameters const& upgrades) = 0;
    // gets the upgrades that are scheduled by this node
    virtual std::string getUpgradesJson() = 0;

    virtual void forcepogcvmStateIntoSyncWithLastClosedLedger() = 0;

    // helper function to craft an pogcvmValue
    virtual POGchainValue
    makePOGchainValue(Hash const& txSetHash, uint64_t closeTime,
                     xdr::xvector<UpgradeType, 6> const& upgrades,
                     SecretKey const& s) = 0;

    virtual ~Herder()
    {
    }

    virtual Json::Value getJsonInfo(size_t limit, bool fullKeys = false) = 0;
    virtual Json::Value getJsonQuorumInfo(NodeID const& id, bool summary,
                                          bool fullKeys, uint64 index) = 0;
    virtual Json::Value getJsonTransitiveQuorumInfo(NodeID const& id,
                                                    bool summary,
                                                    bool fullKeys) = 0;
    virtual QuorumTracker::QuorumMap const&
    getCurrentlyTrackedQuorum() const = 0;
};
}
