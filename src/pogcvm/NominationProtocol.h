#pragma once

// Copyright 2014 POGchain Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "lib/json/json-forwards.h"
#include "pogcvm/pogcvm.h"
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <utility>

namespace POGchain
{
class NominationProtocol
{
  protected:
    Slot& mSlot;

    int32 mRoundNumber;

    ValueWrapperPtrSet mVotes;                                  // X
    ValueWrapperPtrSet mAccepted;                               // Y
    ValueWrapperPtrSet mCandidates;                             // Z
    std::map<NodeID, pogcvmEnvelopeWrapperPtr> mLatestNominations; // N

    pogcvmEnvelopeWrapperPtr mLastEnvelope; // last envelope emitted by this node

    // nodes from quorum set that have the highest priority this round
    std::set<NodeID> mRoundLeaders;

    // true if 'nominate' was called
    bool mNominationStarted;

    // the latest (if any) candidate value
    ValueWrapperPtr mLatestCompositeCandidate;

    // the value from the previous slot
    Value mPreviousValue;

    bool isNewerStatement(NodeID const& nodeID, pogcvmNomination const& st);
    static bool isNewerStatement(pogcvmNomination const& oldst,
                                 pogcvmNomination const& st);

    // returns true if 'p' is a subset of 'v'
    // also sets 'notEqual' if p and v differ
    // note: p and v must be sorted
    static bool isSubsetHelper(xdr::xvector<Value> const& p,
                               xdr::xvector<Value> const& v, bool& notEqual);

    pogcvmDriver::ValidationLevel validateValue(Value const& v);
    ValueWrapperPtr extractValidValue(Value const& value);

    bool isSane(pogcvmStatement const& st);

    void recordEnvelope(pogcvmEnvelopeWrapperPtr env);

    void emitNomination();

    // returns true if v is in the accepted list from the statement
    static bool acceptPredicate(Value const& v, pogcvmStatement const& st);

    // applies 'processor' to all values from the passed in nomination
    static void applyAll(pogcvmNomination const& nom,
                         std::function<void(Value const&)> processor);

    // updates the set of nodes that have priority over the others
    void updateRoundLeaders();

    // computes Gi(isPriority?P:N, prevValue, mRoundNumber, nodeID)
    // from the paper
    uint64 hashNode(bool isPriority, NodeID const& nodeID);

    // computes Gi(K, prevValue, mRoundNumber, value)
    uint64 hashValue(Value const& value);

    uint64 getNodePriority(NodeID const& nodeID, pogcvmQuorumSet const& qset);

    // returns the highest value that we don't have yet, that we should
    // vote for, extracted from a nomination.
    // returns nullptr if no new value was found
    ValueWrapperPtr getNewValueFromNomination(pogcvmNomination const& nom);

  public:
    NominationProtocol(Slot& slot);

    pogcvm::EnvelopeState processEnvelope(pogcvmEnvelopeWrapperPtr envelope);

    static std::vector<Value> getStatementValues(pogcvmStatement const& st);

    // attempts to nominate a value for validation
    bool nominate(ValueWrapperPtr value, Value const& previousValue,
                  bool timedout);

    // stops the nomination protocol
    void stopNomination();

    // return the current leaders
    std::set<NodeID> const& getLeaders() const;

    ValueWrapperPtr const&
    getLatestCompositeCandidate() const
    {
        return mLatestCompositeCandidate;
    }

    Json::Value getJsonInfo();

    pogcvmEnvelope const*
    getLastMessageSend() const
    {
        return mLastEnvelope ? &mLastEnvelope->getEnvelope() : nullptr;
    }

    void setStateFromEnvelope(pogcvmEnvelopeWrapperPtr e);

    bool processCurrentState(std::function<bool(pogcvmEnvelope const&)> const& f,
                             bool forceSelf) const;

    // returns the latest message from a node
    // or nullptr if not found
    pogcvmEnvelope const* getLatestMessage(NodeID const& id) const;
};
}
