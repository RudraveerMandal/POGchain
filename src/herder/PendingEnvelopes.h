#pragma once
#include "crypto/SecretKey.h"
#include "herder/Herder.h"
#include "herder/QuorumTracker.h"
#include "lib/json/json.h"
#include "overlay/ItemFetcher.h"
#include "util/RandomEvictionCache.h"
#include <autocheck/function.hpp>
#include <chrono>
#include <map>
#include <medida/medida.h>
#include <optional>
#include <queue>
#include <set>

/*
pogcvm messages that you have received but are waiting to get the info of
before feeding into pogcvm
*/

namespace POGchain
{

class HerderImpl;

struct SlotEnvelopes
{
    // envelopes we have discarded
    std::set<pogcvmEnvelope> mDiscardedEnvelopes;
    // envelopes we have processed already
    std::set<pogcvmEnvelope> mProcessedEnvelopes;
    // envelopes we are fetching right now
    std::map<pogcvmEnvelope, VirtualClock::time_point> mFetchingEnvelopes;

    // list of ready envelopes that haven't been sent to pogcvm yet
    std::vector<pogcvmEnvelopeWrapperPtr> mReadyEnvelopes;

    // track cost per validator in local qset
    // cost includes sizes of:
    //   * envelopes
    //   * txsets `NodeID` introduces either itself or via its
    //     quorum (our transitive quorum)
    //   * qsets
    UnorderedMap<NodeID, size_t> mReceivedCost;
};

class PendingEnvelopes
{
    Application& mApp;
    HerderImpl& mHerder;

    // ledger# and list of envelopes in various states
    std::map<uint64, SlotEnvelopes> mEnvelopes;

    // recent quorum sets
    RandomEvictionCache<Hash, pogcvmQuorumSetPtr> mQsetCache;
    // weak references to all known qsets
    UnorderedMap<Hash, std::weak_ptr<pogcvmQuorumSet>> mKnownQSets;

    ItemFetcher mTxSetFetcher;
    ItemFetcher mQuorumSetFetcher;

    using TxSetFramCacheItem = std::pair<uint64, TxSetFramePtr>;
    // recent txsets
    RandomEvictionCache<Hash, TxSetFramCacheItem> mTxSetCache;
    // weak references to all known txsets
    UnorderedMap<Hash, std::weak_ptr<TxSetFrame>> mKnownTxSets;

    // keep track of txset/qset hash -> size pairs for quick access
    RandomEvictionCache<Hash, size_t> mValueSizeCache;

    bool mRebuildQuorum;
    QuorumTracker mQuorumTracker;

    medida::Counter& mProcessedCount;
    medida::Counter& mDiscardedCount;
    medida::Counter& mFetchingCount;
    medida::Counter& mReadyCount;
    medida::Timer& mFetchDuration;
    medida::Timer& mFetchTxSetTimer;
    medida::Timer& mFetchQsetTimer;
    // Tracked cost per slot
    medida::Histogram& mCostPerSlot;

    // discards all pogcvm envelopes that use QSet with a given hash,
    // as it is not sane QSet
    void discardpogcvmEnvelopesWithQSet(Hash const& hash);

    void updateMetrics();

    void envelopeReady(pogcvmEnvelope const& envelope);
    void discardpogcvmEnvelope(pogcvmEnvelope const& envelope);
    bool isFullyFetched(pogcvmEnvelope const& envelope);
    void startFetch(pogcvmEnvelope const& envelope);
    void stopFetch(pogcvmEnvelope const& envelope);
    void touchFetchCache(pogcvmEnvelope const& envelope);
    bool isDiscarded(pogcvmEnvelope const& envelope) const;

    pogcvmQuorumSetPtr putQSet(Hash const& qSetHash, pogcvmQuorumSet const& qSet);
    // tries to find a qset in memory, setting touch also touches the LRU,
    // extending the lifetime of the result
    pogcvmQuorumSetPtr getKnownQSet(Hash const& hash, bool touch);

    // tries to find a txset in memory, setting touch also touches the LRU,
    // extending the lifetime of the result
    TxSetFramePtr getKnownTxSet(Hash const& hash, uint64 slot, bool touch);

    void cleanKnownData();

    void recordReceivedCost(pogcvmEnvelope const& env);

    UnorderedMap<NodeID, size_t> getCostPerValidator(uint64 slotIndex) const;

    // stops all pending downloads for slots strictly below `slotIndex`
    // counts partially downloaded data towards the cost for that slot
    void stopAllBelow(uint64 slotIndex);

  public:
    PendingEnvelopes(Application& app, HerderImpl& herder);
    ~PendingEnvelopes();

#ifdef BUILD_TESTS
    void clearQSetCache();
#endif

    /**
     * Process received @p envelope.
     *
     * Return status of received envelope.
     */
    Herder::EnvelopeStatus recvpogcvmEnvelope(pogcvmEnvelope const& envelope);

    /**
     * Add @p qset identified by @p hash to local cache. Notifies
     * @see ItemFetcher about that event - it may cause calls to Herder's
     * recvpogcvmEnvelope which in turn may cause calls to @see recvpogcvmEnvelope
     * in PendingEnvelopes.
     */
    void addpogcvmQuorumSet(Hash const& hash, pogcvmQuorumSet const& qset);

    /**
     * Check if @p qset identified by @p hash was requested before from peers.
     * If not, ignores that @p qset. If it was requested, calls
     * @see addpogcvmQuorumSet.
     *
     * Return true if pogcvmQuorumSet is sane and useful (was asked for).
     */
    bool recvpogcvmQuorumSet(Hash const& hash, pogcvmQuorumSet const& qset);

    /**
     * Add @p txset identified by @p hash to local cache. Notifies
     * @see ItemFetcher about that event - it may cause calls to Herder's
     * recvpogcvmEnvelope which in turn may cause calls to @see recvpogcvmEnvelope
     * in PendingEnvelopes.
     */
    void addTxSet(Hash const& hash, uint64 lastSeenSlotIndex,
                  TxSetFramePtr txset);

    /**
        Adds @p txset to the cache and returns the txset referenced by the cache
        NB: if caller wants to continue using txset after the call, it should
       use the returned value instead
    */
    TxSetFramePtr putTxSet(Hash const& hash, uint64 slot, TxSetFramePtr txset);

    /**
     * Check if @p txset identified by @p hash was requested before from peers.
     * If not, ignores that @p txset. If it was requested, calls
     * @see addTxSet.
     *
     * Return true if TxSet useful (was asked for).
     */
    bool recvTxSet(Hash const& hash, TxSetFramePtr txset);

    void peerDoesntHave(MessageType type, Hash const& itemID,
                        Peer::pointer peer);

    pogcvmEnvelopeWrapperPtr pop(uint64 slotIndex);

    // erases data for all slots strictly below `slotIndex`
    void eraseBelow(uint64 slotIndex);

    void forceRebuildQuorum();

    std::vector<uint64> readySlots();

    Json::Value getJsonInfo(size_t limit);

    TxSetFramePtr getTxSet(Hash const& hash);
    pogcvmQuorumSetPtr getQSet(Hash const& hash);

    // returns true if we think that the node is in the transitive quorum for
    // sure
    bool isNodeDefinitelyInQuorum(NodeID const& node);

    void rebuildQuorumTrackerState();
    QuorumTracker::QuorumMap const& getCurrentlyTrackedQuorum() const;

    // updates internal state when an envelope was successfully processed
    void envelopeProcessed(pogcvmEnvelope const& env);

    void reportCostOutliersForSlot(int64_t slotIndex, bool updateMetrics) const;
    Json::Value getJsonValidatorCost(bool summary, bool fullKeys,
                                     uint64 index) const;
};
}
