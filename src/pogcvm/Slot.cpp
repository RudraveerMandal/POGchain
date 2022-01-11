// Copyright 2014 POGchain Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "Slot.h"

#include "crypto/Hex.h"
#include "lib/json/json.h"
#include "main/ErrorMessages.h"
#include "pogcvm/LocalNode.h"
#include "pogcvm/QuorumSetUtils.h"
#include "util/GlobalChecks.h"
#include "util/Logging.h"
#include "util/XDROperators.h"
#include "xdrpp/marshal.h"
#include <ctime>
#include <functional>

namespace POGchain
{
using namespace std::placeholders;

Slot::Slot(uint64 slotIndex, pogcvm& pogcvm)
    : mSlotIndex(slotIndex)
    , mpogcvm(pogcvm)
    , mBallotProtocol(*this)
    , mNominationProtocol(*this)
    , mFullyValidated(pogcvm.getLocalNode()->isValidator())
    , mGotVBlocking(false)
{
}

ValueWrapperPtr const&
Slot::getLatestCompositeCandidate()
{
    return mNominationProtocol.getLatestCompositeCandidate();
}

std::vector<pogcvmEnvelope>
Slot::getLatestMessagesSend() const
{
    std::vector<pogcvmEnvelope> res;
    if (mFullyValidated)
    {
        pogcvmEnvelope const* e;
        e = mNominationProtocol.getLastMessageSend();
        if (e)
        {
            res.emplace_back(*e);
        }
        e = mBallotProtocol.getLastMessageSend();
        if (e)
        {
            res.emplace_back(*e);
        }
    }
    return res;
}

void
Slot::setStateFromEnvelope(pogcvmEnvelopeWrapperPtr env)
{
    auto& e = env->getEnvelope();
    if (e.statement.nodeID == getpogcvm().getLocalNodeID() &&
        e.statement.slotIndex == mSlotIndex)
    {
        auto prev = getLatestMessage(e.statement.nodeID) != nullptr;

        if (e.statement.pledges.type() == pogcvmStatementType::pogcvm_ST_NOMINATE)
        {
            mNominationProtocol.setStateFromEnvelope(env);
        }
        else
        {
            mBallotProtocol.setStateFromEnvelope(env);
        }

        if (!prev)
        {
            maybeSetGotVBlocking();
        }
    }
    else
    {
        CLOG_TRACE(pogcvm, "Slot::setStateFromEnvelope invalid envelope i: {} {}",
                   getSlotIndex(), mpogcvm.envToStr(e));
    }
}

void
Slot::processCurrentState(std::function<bool(pogcvmEnvelope const&)> const& f,
                          bool forceSelf) const
{
    mNominationProtocol.processCurrentState(f, forceSelf) &&
        mBallotProtocol.processCurrentState(f, forceSelf);
}

pogcvmEnvelope const*
Slot::getLatestMessage(NodeID const& id) const
{
    auto m = mBallotProtocol.getLatestMessage(id);
    if (m == nullptr)
    {
        m = mNominationProtocol.getLatestMessage(id);
    }
    return m;
}

std::vector<pogcvmEnvelope>
Slot::getExternalizingState() const
{
    return mBallotProtocol.getExternalizingState();
}

void
Slot::recordStatement(pogcvmStatement const& st)
{
    mStatementsHistory.emplace_back(
        HistoricalStatement{std::time(nullptr), st, mFullyValidated});
    CLOG_DEBUG(pogcvm, "new statement:  i: {} st: {} validated: {}",
               getSlotIndex(), mpogcvm.envToStr(st, false),
               (mFullyValidated ? "true" : "false"));
}

pogcvm::EnvelopeState
Slot::processEnvelope(pogcvmEnvelopeWrapperPtr envelope, bool self)
{
    dbgAssert(envelope->getStatement().slotIndex == mSlotIndex);

    CLOG_TRACE(pogcvm, "Slot::processEnvelope i: {} {}", getSlotIndex(),
               mpogcvm.envToStr(envelope->getEnvelope()));

    pogcvm::EnvelopeState res;

    try
    {
        auto& st = envelope->getStatement();
        auto prev = getLatestMessage(st.nodeID) != nullptr;

        if (st.pledges.type() == pogcvmStatementType::pogcvm_ST_NOMINATE)
        {
            res = mNominationProtocol.processEnvelope(envelope);
        }
        else
        {
            res = mBallotProtocol.processEnvelope(envelope, self);
        }

        if (!prev && res == pogcvm::VALID)
        {
            maybeSetGotVBlocking();
        }
    }
    catch (...)
    {
        CLOG_FATAL(pogcvm, "pogcvm context ({}): ",
                   mpogcvm.getDriver().toShortString(mpogcvm.getLocalNodeID()));
        CLOG_FATAL(pogcvm, "{}", getJsonInfo().toStyledString());
        CLOG_FATAL(pogcvm, "Exception processing pogcvm messages at {}, envelope: {}",
                   mSlotIndex, mpogcvm.envToStr(envelope->getEnvelope()));
        CLOG_FATAL(pogcvm, "{}", REPORT_INTERNAL_BUG);

        throw;
    }
    return res;
}

bool
Slot::abandonBallot()
{
    return mBallotProtocol.abandonBallot(0);
}

bool
Slot::bumpState(Value const& value, bool force)
{

    return mBallotProtocol.bumpState(value, force);
}

bool
Slot::nominate(ValueWrapperPtr value, Value const& previousValue, bool timedout)
{
    return mNominationProtocol.nominate(value, previousValue, timedout);
}

void
Slot::stopNomination()
{
    mNominationProtocol.stopNomination();
}

std::set<NodeID>
Slot::getNominationLeaders() const
{
    return mNominationProtocol.getLeaders();
}

bool
Slot::isFullyValidated() const
{
    return mFullyValidated;
}

void
Slot::setFullyValidated(bool fullyValidated)
{
    mFullyValidated = fullyValidated;
}

pogcvmEnvelope
Slot::createEnvelope(pogcvmStatement const& statement)
{
    pogcvmEnvelope envelope;

    envelope.statement = statement;
    auto& mySt = envelope.statement;
    mySt.nodeID = getpogcvm().getLocalNodeID();
    mySt.slotIndex = getSlotIndex();

    mpogcvm.getDriver().signEnvelope(envelope);

    return envelope;
}

Hash
Slot::getCompanionQuorumSetHashFromStatement(pogcvmStatement const& st)
{
    Hash h;
    switch (st.pledges.type())
    {
    case pogcvm_ST_PREPARE:
        h = st.pledges.prepare().quorumSetHash;
        break;
    case pogcvm_ST_CONFIRM:
        h = st.pledges.confirm().quorumSetHash;
        break;
    case pogcvm_ST_EXTERNALIZE:
        h = st.pledges.externalize().commitQuorumSetHash;
        break;
    case pogcvm_ST_NOMINATE:
        h = st.pledges.nominate().quorumSetHash;
        break;
    default:
        dbgAbort();
    }
    return h;
}

std::vector<Value>
Slot::getStatementValues(pogcvmStatement const& st)
{
    std::vector<Value> res;
    if (st.pledges.type() == pogcvm_ST_NOMINATE)
    {
        res = NominationProtocol::getStatementValues(st);
    }
    else
    {
        auto vals = BallotProtocol::getStatementValues(st);
        res.reserve(vals.size());
        for (auto const& v : vals)
        {
            res.emplace_back(v);
        }
    }
    return res;
}

pogcvmQuorumSetPtr
Slot::getQuorumSetFromStatement(pogcvmStatement const& st)
{
    pogcvmQuorumSetPtr res;
    pogcvmStatementType t = st.pledges.type();

    if (t == pogcvm_ST_EXTERNALIZE)
    {
        res = LocalNode::getSingletonQSet(st.nodeID);
    }
    else
    {
        Hash h;
        if (t == pogcvm_ST_PREPARE)
        {
            h = st.pledges.prepare().quorumSetHash;
        }
        else if (t == pogcvm_ST_CONFIRM)
        {
            h = st.pledges.confirm().quorumSetHash;
        }
        else if (t == pogcvm_ST_NOMINATE)
        {
            h = st.pledges.nominate().quorumSetHash;
        }
        else
        {
            dbgAbort();
        }
        res = getpogcvmDriver().getQSet(h);
    }
    return res;
}

Json::Value
Slot::getJsonInfo(bool fullKeys)
{
    Json::Value ret;
    std::map<Hash, pogcvmQuorumSetPtr> qSetsUsed;

    int count = 0;
    for (auto const& item : mStatementsHistory)
    {
        Json::Value& v = ret["statements"][count++];
        v.append((Json::UInt64)item.mWhen);
        v.append(mpogcvm.envToStr(item.mStatement, fullKeys));
        v.append(item.mValidated);

        Hash const& qSetHash =
            getCompanionQuorumSetHashFromStatement(item.mStatement);
        auto qSet = getpogcvmDriver().getQSet(qSetHash);
        if (qSet)
        {
            qSetsUsed.insert(std::make_pair(qSetHash, qSet));
        }
    }

    auto& qSets = ret["quorum_sets"];
    for (auto const& q : qSetsUsed)
    {
        qSets[hexAbbrev(q.first)] = getLocalNode()->toJson(*q.second, fullKeys);
    }

    ret["validated"] = mFullyValidated;
    ret["nomination"] = mNominationProtocol.getJsonInfo();
    ret["ballotProtocol"] = mBallotProtocol.getJsonInfo();

    return ret;
}

Json::Value
Slot::getJsonQuorumInfo(NodeID const& id, bool summary, bool fullKeys)
{
    Json::Value ret = mBallotProtocol.getJsonQuorumInfo(id, summary, fullKeys);
    if (getLocalNode()->isValidator())
    {
        ret["validated"] = isFullyValidated();
    }
    return ret;
}

bool
Slot::federatedAccept(StatementPredicate voted, StatementPredicate accepted,
                      std::map<NodeID, pogcvmEnvelopeWrapperPtr> const& envs)
{
    // Checks if the nodes that claimed to accept the statement form a
    // v-blocking set
    if (LocalNode::isVBlocking(getLocalNode()->getQuorumSet(), envs, accepted))
    {
        return true;
    }

    // Checks if the set of nodes that accepted or voted for it form a quorum

    auto ratifyFilter = [&](pogcvmStatement const& st) {
        bool res;
        res = accepted(st) || voted(st);
        return res;
    };

    if (LocalNode::isQuorum(
            getLocalNode()->getQuorumSet(), envs,
            std::bind(&Slot::getQuorumSetFromStatement, this, _1),
            ratifyFilter))
    {
        return true;
    }

    return false;
}

bool
Slot::federatedRatify(StatementPredicate voted,
                      std::map<NodeID, pogcvmEnvelopeWrapperPtr> const& envs)
{
    return LocalNode::isQuorum(
        getLocalNode()->getQuorumSet(), envs,
        std::bind(&Slot::getQuorumSetFromStatement, this, _1), voted);
}

std::shared_ptr<LocalNode>
Slot::getLocalNode()
{
    return mpogcvm.getLocalNode();
}

std::vector<pogcvmEnvelope>
Slot::getEntireCurrentState()
{
    std::vector<pogcvmEnvelope> res;
    processCurrentState(
        [&](pogcvmEnvelope const& e) {
            res.emplace_back(e);
            return true;
        },
        true);
    return res;
}

void
Slot::maybeSetGotVBlocking()
{
    if (mGotVBlocking)
    {
        // was already set
        return;
    }
    std::vector<NodeID> nodes;

    auto& qSet = getLocalNode()->getQuorumSet();

    LocalNode::forAllNodes(qSet, [&](NodeID const& id) {
        auto latest = getLatestMessage(id);
        if (latest)
        {
            nodes.emplace_back(id);
        }
        return true;
    });

    mGotVBlocking = LocalNode::isVBlocking(qSet, nodes);

    if (mGotVBlocking)
    {
        CLOG_TRACE(pogcvm, "Got v-blocking for {}", mSlotIndex);
    }
}
}
