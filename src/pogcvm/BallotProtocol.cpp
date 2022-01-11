// Copyright 2014 POGchain Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "BallotProtocol.h"

#include "Slot.h"
#include "crypto/Hex.h"
#include "lib/json/json.h"
#include "pogcvm/LocalNode.h"
#include "pogcvm/QuorumSetUtils.h"
#include "util/GlobalChecks.h"
#include "util/Logging.h"
#include "util/XDROperators.h"
#include "xdrpp/marshal.h"
#include <Tracy.hpp>
#include <functional>
#include <numeric>
#include <sstream>

namespace POGchain
{
using namespace std::placeholders;

// max number of transitions that can occur from processing one message
static const int MAX_ADVANCE_SLOT_RECURSION = 50;

BallotProtocol::BallotProtocol(Slot& slot)
    : mSlot(slot)
    , mHeardFromQuorum(false)
    , mPhase(pogcvm_PHASE_PREPARE)
    , mCurrentMessageLevel(0)
{
}

bool
BallotProtocol::isNewerStatement(NodeID const& nodeID, pogcvmStatement const& st)
{
    auto oldp = mLatestEnvelopes.find(nodeID);
    bool res = false;

    if (oldp == mLatestEnvelopes.end())
    {
        res = true;
    }
    else
    {
        res = isNewerStatement(oldp->second->getStatement(), st);
    }
    return res;
}

bool
BallotProtocol::isNewerStatement(pogcvmStatement const& oldst,
                                 pogcvmStatement const& st)
{
    bool res = false;

    // total ordering described in pogcvm paper.
    auto t = st.pledges.type();

    // statement type (PREPARE < CONFIRM < EXTERNALIZE)
    if (oldst.pledges.type() != t)
    {
        res = (oldst.pledges.type() < t);
    }
    else
    {
        // can't have duplicate EXTERNALIZE statements
        if (t == pogcvmStatementType::pogcvm_ST_EXTERNALIZE)
        {
            res = false;
        }
        else if (t == pogcvmStatementType::pogcvm_ST_CONFIRM)
        {
            // sorted by (b, p, p', h) (p' = 0 implicitly)
            auto const& oldC = oldst.pledges.confirm();
            auto const& c = st.pledges.confirm();
            int compBallot = compareBallots(oldC.ballot, c.ballot);
            if (compBallot < 0)
            {
                res = true;
            }
            else if (compBallot == 0)
            {
                if (oldC.nPrepared == c.nPrepared)
                {
                    res = (oldC.nH < c.nH);
                }
                else
                {
                    res = (oldC.nPrepared < c.nPrepared);
                }
            }
        }
        else
        {
            // Lexicographical order between PREPARE statements:
            // (b, p, p', h)
            auto const& oldPrep = oldst.pledges.prepare();
            auto const& prep = st.pledges.prepare();

            int compBallot = compareBallots(oldPrep.ballot, prep.ballot);
            if (compBallot < 0)
            {
                res = true;
            }
            else if (compBallot == 0)
            {
                compBallot = compareBallots(oldPrep.prepared, prep.prepared);
                if (compBallot < 0)
                {
                    res = true;
                }
                else if (compBallot == 0)
                {
                    compBallot = compareBallots(oldPrep.preparedPrime,
                                                prep.preparedPrime);
                    if (compBallot < 0)
                    {
                        res = true;
                    }
                    else if (compBallot == 0)
                    {
                        res = (oldPrep.nH < prep.nH);
                    }
                }
            }
        }
    }

    return res;
}

void
BallotProtocol::recordEnvelope(pogcvmEnvelopeWrapperPtr env)
{
    auto const& st = env->getStatement();
    auto oldp = mLatestEnvelopes.find(st.nodeID);
    if (oldp == mLatestEnvelopes.end())
    {
        mLatestEnvelopes.insert(std::make_pair(st.nodeID, env));
    }
    else
    {
        oldp->second = env;
    }
    mSlot.recordStatement(env->getStatement());
}

pogcvm::EnvelopeState
BallotProtocol::processEnvelope(pogcvmEnvelopeWrapperPtr envelope, bool self)
{
    ZoneScoped;
    dbgAssert(envelope->getStatement().slotIndex == mSlot.getSlotIndex());

    pogcvmStatement const& statement = envelope->getStatement();
    NodeID const& nodeID = statement.nodeID;

    if (!isStatementSane(statement, self))
    {
        if (self)
        {
            CLOG_ERROR(pogcvm, "not sane statement from self, skipping   e: {}",
                       mSlot.getpogcvm().envToStr(envelope->getEnvelope()));
        }

        return pogcvm::EnvelopeState::INVALID;
    }

    if (!isNewerStatement(nodeID, statement))
    {
        if (self)
        {
            CLOG_ERROR(pogcvm, "stale statement from self, skipping   e: {}",
                       mSlot.getpogcvm().envToStr(envelope->getEnvelope()));
        }
        else
        {
            CLOG_TRACE(pogcvm, "stale statement, skipping  i: {}",
                       mSlot.getSlotIndex());
        }

        return pogcvm::EnvelopeState::INVALID;
    }

    auto validationRes = validateValues(statement);

    // If the value is not valid, we just ignore it.
    if (validationRes == pogcvmDriver::kInvalidValue)
    {
        if (self)
        {
            CLOG_ERROR(pogcvm, "invalid value from self, skipping   e: {}",
                       mSlot.getpogcvm().envToStr(envelope->getEnvelope()));
        }
        else
        {
            CLOG_TRACE(pogcvm, "invalid value  i: {}", mSlot.getSlotIndex());
        }

        return pogcvm::EnvelopeState::INVALID;
    }

    if (mPhase != pogcvm_PHASE_EXTERNALIZE)
    {
        if (validationRes == pogcvmDriver::kMaybeValidValue)
        {
            mSlot.setFullyValidated(false);
        }

        recordEnvelope(envelope);
        advanceSlot(statement);
        return pogcvm::EnvelopeState::VALID;
    }

    // note: this handles also our own messages
    // in particular our final EXTERNALIZE message
    dbgAssert(mPhase == pogcvm_PHASE_EXTERNALIZE);
    if (mCommit->getBallot().value == getWorkingBallot(statement).value)
    {
        recordEnvelope(envelope);
        return pogcvm::EnvelopeState::VALID;
    }

    if (self)
    {
        CLOG_ERROR(pogcvm,
                   "externalize statement with invalid value from "
                   "self, skipping e: {}",
                   mSlot.getpogcvm().envToStr(envelope->getEnvelope()));
    }

    return pogcvm::EnvelopeState::INVALID;
}

bool
BallotProtocol::isStatementSane(pogcvmStatement const& st, bool self)
{
    auto qSet = mSlot.getQuorumSetFromStatement(st);
    const char* errString = nullptr;
    bool res = qSet != nullptr && isQuorumSetSane(*qSet, false, errString);
    if (!res)
    {
        CLOG_DEBUG(pogcvm, "Invalid quorum set received : {}",
                   (errString ? errString : "<empty>"));

        return false;
    }

    switch (st.pledges.type())
    {
    case pogcvmStatementType::pogcvm_ST_PREPARE:
    {
        auto const& p = st.pledges.prepare();
        // self is allowed to have b = 0 (as long as it never gets emitted)
        bool isOK = self || p.ballot.counter > 0;

        isOK = isOK &&
               ((!p.preparedPrime || !p.prepared) ||
                (areBallotsLessAndIncompatible(*p.preparedPrime, *p.prepared)));

        isOK =
            isOK && (p.nH == 0 || (p.prepared && p.nH <= p.prepared->counter));

        // c != 0 -> c <= h <= b
        isOK = isOK && (p.nC == 0 || (p.nH != 0 && p.ballot.counter >= p.nH &&
                                      p.nH >= p.nC));

        if (!isOK)
        {
            CLOG_TRACE(pogcvm, "Malformed PREPARE message");
            res = false;
        }
    }
    break;
    case pogcvmStatementType::pogcvm_ST_CONFIRM:
    {
        auto const& c = st.pledges.confirm();
        // c <= h <= b
        res = c.ballot.counter > 0;
        res = res && (c.nH <= c.ballot.counter);
        res = res && (c.nCommit <= c.nH);
        if (!res)
        {
            CLOG_TRACE(pogcvm, "Malformed CONFIRM message");
        }
    }
    break;
    case pogcvmStatementType::pogcvm_ST_EXTERNALIZE:
    {
        auto const& e = st.pledges.externalize();

        res = e.commit.counter > 0;
        res = res && e.nH >= e.commit.counter;

        if (!res)
        {
            CLOG_TRACE(pogcvm, "Malformed EXTERNALIZE message");
        }
    }
    break;
    default:
        dbgAbort();
    }

    return res;
}

bool
BallotProtocol::abandonBallot(uint32 n)
{
    ZoneScoped;
    CLOG_TRACE(pogcvm, "BallotProtocol::abandonBallot");
    bool res = false;
    auto v = mSlot.getLatestCompositeCandidate();

    if (!v || v->getValue().empty())
    {
        if (mCurrentBallot)
        {
            v = mCurrentBallot->getWValue();
        }
    }
    if (v && !v->getValue().empty())
    {
        if (n == 0)
        {
            res = bumpState(v->getValue(), true);
        }
        else
        {
            res = bumpState(v->getValue(), n);
        }
    }
    return res;
}

bool
BallotProtocol::bumpState(Value const& value, bool force)
{
    uint32 n;
    if (!force && mCurrentBallot)
    {
        return false;
    }

    n = mCurrentBallot ? (mCurrentBallot->getBallot().counter + 1) : 1;

    return bumpState(value, n);
}

bool
BallotProtocol::bumpState(Value const& value, uint32 n)
{
    ZoneScoped;
    if (mPhase != pogcvm_PHASE_PREPARE && mPhase != pogcvm_PHASE_CONFIRM)
    {
        return false;
    }

    pogcvmBallot newb;

    newb.counter = n;

    if (mValueOverride)
    {
        // we use the value that we saw confirmed prepared
        // or that we at least voted to commit to
        newb.value = mValueOverride->getValue();
    }
    else
    {
        newb.value = value;
    }

    CLOG_TRACE(pogcvm, "BallotProtocol::bumpState i: {} v: {}",
               mSlot.getSlotIndex(), mSlot.getpogcvm().ballotToStr(newb));

    bool updated = updateCurrentValue(newb);

    if (updated)
    {
        emitCurrentStateStatement();
        checkHeardFromQuorum();
    }

    return updated;
}

// updates the local state based to the specified ballot
// (that could be a prepared ballot) enforcing invariants
bool
BallotProtocol::updateCurrentValue(pogcvmBallot const& ballot)
{
    ZoneScoped;
    if (mPhase != pogcvm_PHASE_PREPARE && mPhase != pogcvm_PHASE_CONFIRM)
    {
        return false;
    }

    bool updated = false;
    if (!mCurrentBallot)
    {
        bumpToBallot(ballot, true);
        updated = true;
    }
    else
    {
        dbgAssert(compareBallots(mCurrentBallot->getBallot(), ballot) <= 0);

        if (mCommit && !areBallotsCompatible(mCommit->getBallot(), ballot))
        {
            return false;
        }

        int comp = compareBallots(mCurrentBallot->getBallot(), ballot);
        if (comp < 0)
        {
            bumpToBallot(ballot, true);
            updated = true;
        }
        else if (comp > 0)
        {
            // this code probably changes with the final version
            // of the conciliator

            // this case may happen if the other nodes are not
            // following the protocol (and we end up with a smaller value)
            // not sure what is the best way to deal
            // with this situation
            CLOG_ERROR(pogcvm,
                       "BallotProtocol::updateCurrentValue attempt to bump to "
                       "a smaller value");
            // can't just bump to the value as we may already have
            // statements at counter+1
            return false;
        }
    }

    checkInvariants();

    return updated;
}

void
BallotProtocol::bumpToBallot(pogcvmBallot const& ballot, bool check)
{
    ZoneScoped;
    ZoneValue(static_cast<int64_t>(mSlot.getSlotIndex()));
    ZoneValue(static_cast<int64_t>(ballot.counter));

    CLOG_TRACE(pogcvm, "BallotProtocol::bumpToBallot i: {} b: {}",
               mSlot.getSlotIndex(), mSlot.getpogcvm().ballotToStr(ballot));

    // `bumpToBallot` should be never called once we committed.
    dbgAssert(mPhase != pogcvm_PHASE_EXTERNALIZE);

    if (check)
    {
        // We should move mCurrentBallot monotonically only
        dbgAssert(!mCurrentBallot ||
                  compareBallots(ballot, mCurrentBallot->getBallot()) >= 0);
    }

    bool gotBumped = !mCurrentBallot ||
                     (mCurrentBallot->getBallot().counter != ballot.counter);

    if (!mCurrentBallot)
    {
        mSlot.getpogcvmDriver().startedBallotProtocol(mSlot.getSlotIndex(),
                                                   ballot);
    }

    mCurrentBallot = makeBallot(ballot);

    // note: we have to clear some fields (and recompute them based on latest
    // messages)
    // invariant: h.value = b.value
    if (mHighBallot && !areBallotsCompatible(mCurrentBallot->getBallot(),
                                             mHighBallot->getBallot()))
    {
        mHighBallot.reset();
        // invariant: c set only when h is set
        mCommit.reset();
    }

    if (gotBumped)
    {
        mHeardFromQuorum = false;
    }
}

void
BallotProtocol::startBallotProtocolTimer()
{
    std::chrono::milliseconds timeout = mSlot.getpogcvmDriver().computeTimeout(
        mCurrentBallot->getBallot().counter);

    std::shared_ptr<Slot> slot = mSlot.shared_from_this();
    mSlot.getpogcvmDriver().setupTimer(
        mSlot.getSlotIndex(), Slot::BALLOT_PROTOCOL_TIMER, timeout,
        [slot]() { slot->getBallotProtocol().ballotProtocolTimerExpired(); });
}

void
BallotProtocol::stopBallotProtocolTimer()
{
    std::shared_ptr<Slot> slot = mSlot.shared_from_this();
    mSlot.getpogcvmDriver().setupTimer(mSlot.getSlotIndex(),
                                    Slot::BALLOT_PROTOCOL_TIMER,
                                    std::chrono::seconds::zero(), nullptr);
}

void
BallotProtocol::ballotProtocolTimerExpired()
{
    abandonBallot(0);
}

pogcvmStatement
BallotProtocol::createStatement(pogcvmStatementType const& type)
{
    ZoneScoped;
    pogcvmStatement statement;

    checkInvariants();

    statement.pledges.type(type);
    switch (type)
    {
    case pogcvmStatementType::pogcvm_ST_PREPARE:
    {
        auto& p = statement.pledges.prepare();
        p.quorumSetHash = getLocalNode()->getQuorumSetHash();
        if (mCurrentBallot)
        {
            p.ballot = mCurrentBallot->getBallot();
        }
        if (mCommit)
        {
            p.nC = mCommit->getBallot().counter;
        }
        if (mPrepared)
        {
            p.prepared.activate() = mPrepared->getBallot();
        }
        if (mPreparedPrime)
        {
            p.preparedPrime.activate() = mPreparedPrime->getBallot();
        }
        if (mHighBallot)
        {
            p.nH = mHighBallot->getBallot().counter;
        }
    }
    break;
    case pogcvmStatementType::pogcvm_ST_CONFIRM:
    {
        auto& c = statement.pledges.confirm();
        c.quorumSetHash = getLocalNode()->getQuorumSetHash();
        c.ballot = mCurrentBallot->getBallot();
        c.nPrepared = mPrepared->getBallot().counter;
        c.nCommit = mCommit->getBallot().counter;
        c.nH = mHighBallot->getBallot().counter;
    }
    break;
    case pogcvmStatementType::pogcvm_ST_EXTERNALIZE:
    {
        auto& e = statement.pledges.externalize();
        e.commit = mCommit->getBallot();
        e.nH = mHighBallot->getBallot().counter;
        e.commitQuorumSetHash = getLocalNode()->getQuorumSetHash();
    }
    break;
    default:
        dbgAbort();
    }

    return statement;
}

void
BallotProtocol::emitCurrentStateStatement()
{
    ZoneScoped;
    pogcvmStatementType t;

    switch (mPhase)
    {
    case pogcvm_PHASE_PREPARE:
        t = pogcvm_ST_PREPARE;
        break;
    case pogcvm_PHASE_CONFIRM:
        t = pogcvm_ST_CONFIRM;
        break;
    case pogcvm_PHASE_EXTERNALIZE:
        t = pogcvm_ST_EXTERNALIZE;
        break;
    default:
        dbgAbort();
    }

    pogcvmStatement statement = createStatement(t);
    pogcvmEnvelope envelope = mSlot.createEnvelope(statement);

    bool canEmit = (mCurrentBallot != nullptr);

    // if we generate the same envelope, don't process it again
    // this can occur when updating h in PREPARE phase
    // as statements only keep track of h.n (but h.x could be different)
    auto lastEnv = mLatestEnvelopes.find(mSlot.getpogcvm().getLocalNodeID());

    if (lastEnv == mLatestEnvelopes.end() ||
        !(lastEnv->second->getEnvelope() == envelope))
    {
        auto envW = mSlot.getpogcvmDriver().wrapEnvelope(envelope);
        if (mSlot.processEnvelope(envW, true) == pogcvm::EnvelopeState::VALID)
        {
            if (canEmit && (!mLastEnvelope ||
                            isNewerStatement(mLastEnvelope->getStatement(),
                                             envelope.statement)))
            {
                mLastEnvelope = envW;
                // this will no-op if invoked from advanceSlot
                // as advanceSlot consolidates all messages sent
                sendLatestEnvelope();
            }
        }
        else
        {
            // there is a bug in the application if it queued up
            // a statement for itself that it considers invalid
            throw std::runtime_error("moved to a bad state (ballot protocol)");
        }
    }
}

void
BallotProtocol::checkInvariants()
{
    if (mCurrentBallot)
    {
        dbgAssert(mCurrentBallot->getBallot().counter != 0);
    }
    if (mPrepared && mPreparedPrime)
    {
        dbgAssert(areBallotsLessAndIncompatible(mPreparedPrime->getBallot(),
                                                mPrepared->getBallot()));
    }
    if (mHighBallot)
    {
        dbgAssert(mCurrentBallot);
        dbgAssert(areBallotsLessAndCompatible(mHighBallot->getBallot(),
                                              mCurrentBallot->getBallot()));
    }
    if (mCommit)
    {
        dbgAssert(mCurrentBallot);
        dbgAssert(areBallotsLessAndCompatible(mCommit->getBallot(),
                                              mHighBallot->getBallot()));
        dbgAssert(areBallotsLessAndCompatible(mHighBallot->getBallot(),
                                              mCurrentBallot->getBallot()));
    }

    switch (mPhase)
    {
    case pogcvm_PHASE_PREPARE:
        break;
    case pogcvm_PHASE_CONFIRM:
        dbgAssert(mCommit);
        break;
    case pogcvm_PHASE_EXTERNALIZE:
        dbgAssert(mCommit);
        dbgAssert(mHighBallot);
        break;
    default:
        dbgAbort();
    }
}

std::set<pogcvmBallot>
BallotProtocol::getPrepareCandidates(pogcvmStatement const& hint)
{
    ZoneScoped;
    std::set<pogcvmBallot> hintBallots;

    switch (hint.pledges.type())
    {
    case pogcvm_ST_PREPARE:
    {
        auto const& prep = hint.pledges.prepare();
        hintBallots.insert(prep.ballot);
        if (prep.prepared)
        {
            hintBallots.insert(*prep.prepared);
        }
        if (prep.preparedPrime)
        {
            hintBallots.insert(*prep.preparedPrime);
        }
    }
    break;
    case pogcvm_ST_CONFIRM:
    {
        auto const& con = hint.pledges.confirm();
        hintBallots.insert(pogcvmBallot(con.nPrepared, con.ballot.value));
        hintBallots.insert(pogcvmBallot(UINT32_MAX, con.ballot.value));
    }
    break;
    case pogcvm_ST_EXTERNALIZE:
    {
        auto const& ext = hint.pledges.externalize();
        hintBallots.insert(pogcvmBallot(UINT32_MAX, ext.commit.value));
    }
    break;
    default:
        abort();
    };

    std::set<pogcvmBallot> candidates;

    while (!hintBallots.empty())
    {
        auto last = --hintBallots.end();
        pogcvmBallot topVote = *last;
        hintBallots.erase(last);

        auto const& val = topVote.value;

        // find candidates that may have been prepared
        for (auto const& e : mLatestEnvelopes)
        {
            pogcvmStatement const& st = e.second->getStatement();
            switch (st.pledges.type())
            {
            case pogcvm_ST_PREPARE:
            {
                auto const& prep = st.pledges.prepare();
                if (areBallotsLessAndCompatible(prep.ballot, topVote))
                {
                    candidates.insert(prep.ballot);
                }
                if (prep.prepared &&
                    areBallotsLessAndCompatible(*prep.prepared, topVote))
                {
                    candidates.insert(*prep.prepared);
                }
                if (prep.preparedPrime &&
                    areBallotsLessAndCompatible(*prep.preparedPrime, topVote))
                {
                    candidates.insert(*prep.preparedPrime);
                }
            }
            break;
            case pogcvm_ST_CONFIRM:
            {
                auto const& con = st.pledges.confirm();
                if (areBallotsCompatible(topVote, con.ballot))
                {
                    candidates.insert(topVote);
                    if (con.nPrepared < topVote.counter)
                    {
                        candidates.insert(pogcvmBallot(con.nPrepared, val));
                    }
                }
            }
            break;
            case pogcvm_ST_EXTERNALIZE:
            {
                auto const& ext = st.pledges.externalize();
                if (areBallotsCompatible(topVote, ext.commit))
                {
                    candidates.insert(topVote);
                }
            }
            break;
            default:
                abort();
            }
        }
    }

    return candidates;
}

bool
BallotProtocol::updateCurrentIfNeeded(pogcvmBallot const& h)
{
    bool didWork = false;
    if (!mCurrentBallot || compareBallots(mCurrentBallot->getBallot(), h) < 0)
    {
        bumpToBallot(h, true);
        didWork = true;
    }
    return didWork;
}

bool
BallotProtocol::attemptAcceptPrepared(pogcvmStatement const& hint)
{
    ZoneScoped;
    if (mPhase != pogcvm_PHASE_PREPARE && mPhase != pogcvm_PHASE_CONFIRM)
    {
        return false;
    }

    auto candidates = getPrepareCandidates(hint);

    // see if we can accept any of the candidates, starting with the highest
    for (auto cur = candidates.rbegin(); cur != candidates.rend(); cur++)
    {
        pogcvmBallot ballot = *cur;

        if (mPhase == pogcvm_PHASE_CONFIRM)
        {
            // only consider the ballot if it may help us increase
            // p (note: at this point, p ~ c)
            if (!areBallotsLessAndCompatible(mPrepared->getBallot(), ballot))
            {
                continue;
            }
            dbgAssert(areBallotsCompatible(mCommit->getBallot(), ballot));
        }

        // if we already prepared this ballot, don't bother checking again

        // if ballot <= p' ballot is neither a candidate for p nor p'
        if (mPreparedPrime &&
            compareBallots(ballot, mPreparedPrime->getBallot()) <= 0)
        {
            continue;
        }

        if (mPrepared)
        {
            // if ballot is already covered by p, skip
            if (areBallotsLessAndCompatible(ballot, mPrepared->getBallot()))
            {
                continue;
            }
            // otherwise, there is a chance it increases p'
        }

        bool accepted = federatedAccept(
            // checks if any node is voting for this ballot
            [&ballot](pogcvmStatement const& st) {
                bool res;

                switch (st.pledges.type())
                {
                case pogcvm_ST_PREPARE:
                {
                    auto const& p = st.pledges.prepare();
                    res = areBallotsLessAndCompatible(ballot, p.ballot);
                }
                break;
                case pogcvm_ST_CONFIRM:
                {
                    auto const& c = st.pledges.confirm();
                    res = areBallotsCompatible(ballot, c.ballot);
                }
                break;
                case pogcvm_ST_EXTERNALIZE:
                {
                    auto const& e = st.pledges.externalize();
                    res = areBallotsCompatible(ballot, e.commit);
                }
                break;
                default:
                    res = false;
                    dbgAbort();
                }

                return res;
            },
            std::bind(&BallotProtocol::hasPreparedBallot, ballot, _1));
        if (accepted)
        {
            return setAcceptPrepared(ballot);
        }
    }

    return false;
}

bool
BallotProtocol::setAcceptPrepared(pogcvmBallot const& ballot)
{
    ZoneScoped;
    CLOG_TRACE(pogcvm, "BallotProtocol::setAcceptPrepared i: {} b: {}",
               mSlot.getSlotIndex(), mSlot.getpogcvm().ballotToStr(ballot));

    // update our state
    bool didWork = setPrepared(ballot);

    // check if we also need to clear 'c'
    if (mCommit && mHighBallot)
    {
        if ((mPrepared &&
             areBallotsLessAndIncompatible(mHighBallot->getBallot(),
                                           mPrepared->getBallot())) ||
            (mPreparedPrime &&
             areBallotsLessAndIncompatible(mHighBallot->getBallot(),
                                           mPreparedPrime->getBallot())))
        {
            dbgAssert(mPhase == pogcvm_PHASE_PREPARE);
            mCommit.reset();
            didWork = true;
        }
    }

    if (didWork)
    {
        mSlot.getpogcvmDriver().acceptedBallotPrepared(mSlot.getSlotIndex(),
                                                    ballot);
        emitCurrentStateStatement();
    }

    return didWork;
}

bool
BallotProtocol::attemptConfirmPrepared(pogcvmStatement const& hint)
{
    ZoneScoped;
    if (mPhase != pogcvm_PHASE_PREPARE)
    {
        return false;
    }

    // check if we could accept this ballot as prepared
    if (!mPrepared)
    {
        return false;
    }

    auto candidates = getPrepareCandidates(hint);

    // see if we can accept any of the candidates, starting with the highest
    pogcvmBallot newH;
    bool newHfound = false;
    auto cur = candidates.rbegin();
    for (; cur != candidates.rend(); cur++)
    {
        pogcvmBallot ballot = *cur;

        // only consider it if we can potentially raise h
        if (mHighBallot &&
            compareBallots(mHighBallot->getBallot(), ballot) >= 0)
        {
            break;
        }

        bool ratified = federatedRatify(
            std::bind(&BallotProtocol::hasPreparedBallot, ballot, _1));
        if (ratified)
        {
            newH = ballot;
            newHfound = true;
            break;
        }
    }

    bool res = false;

    if (newHfound)
    {
        pogcvmBallot newC;
        // now, look for newC (left as 0 if no update)
        // step (3) from the paper
        pogcvmBallot b =
            mCurrentBallot ? mCurrentBallot->getBallot() : pogcvmBallot();
        if (!mCommit &&
            (!mPrepared ||
             !areBallotsLessAndIncompatible(newH, mPrepared->getBallot())) &&
            (!mPreparedPrime ||
             !areBallotsLessAndIncompatible(newH, mPreparedPrime->getBallot())))
        {
            // continue where we left off (cur is at newH at this point)
            for (; cur != candidates.rend(); cur++)
            {
                pogcvmBallot ballot = *cur;
                if (compareBallots(ballot, b) < 0)
                {
                    break;
                }
                // c and h must be compatible
                if (!areBallotsLessAndCompatible(*cur, newH))
                {
                    continue;
                }
                bool ratified = federatedRatify(
                    std::bind(&BallotProtocol::hasPreparedBallot, ballot, _1));
                if (ratified)
                {
                    newC = ballot;
                }
                else
                {
                    break;
                }
            }
        }
        res = setConfirmPrepared(newC, newH);
    }
    return res;
}

bool
BallotProtocol::commitPredicate(pogcvmBallot const& ballot, Interval const& check,
                                pogcvmStatement const& st)
{
    bool res = false;
    auto const& pl = st.pledges;
    switch (pl.type())
    {
    case pogcvm_ST_PREPARE:
        break;
    case pogcvm_ST_CONFIRM:
    {
        auto const& c = pl.confirm();
        if (areBallotsCompatible(ballot, c.ballot))
        {
            res = c.nCommit <= check.first && check.second <= c.nH;
        }
    }
    break;
    case pogcvm_ST_EXTERNALIZE:
    {
        auto const& e = pl.externalize();
        if (areBallotsCompatible(ballot, e.commit))
        {
            res = e.commit.counter <= check.first;
        }
    }
    break;
    default:
        dbgAbort();
    }
    return res;
}

bool
BallotProtocol::setConfirmPrepared(pogcvmBallot const& newC, pogcvmBallot const& newH)
{
    ZoneScoped;
    CLOG_TRACE(pogcvm, "BallotProtocol::setConfirmPrepared i: {} h: {}",
               mSlot.getSlotIndex(), mSlot.getpogcvm().ballotToStr(newH));

    bool didWork = false;

    // remember newH's value
    mValueOverride = mSlot.getpogcvmDriver().wrapValue(newH.value);

    // we don't set c/h if we're not on a compatible ballot
    if (!mCurrentBallot ||
        areBallotsCompatible(mCurrentBallot->getBallot(), newH))
    {
        if (!mHighBallot || compareBallots(newH, mHighBallot->getBallot()) > 0)
        {
            didWork = true;
            mHighBallot = makeBallot(newH);
        }

        if (newC.counter != 0)
        {
            dbgAssert(!mCommit);
            mCommit = makeBallot(newC);
            didWork = true;
        }

        if (didWork)
        {
            mSlot.getpogcvmDriver().confirmedBallotPrepared(mSlot.getSlotIndex(),
                                                         newH);
        }
    }

    // always perform step (8) with the computed value of h
    didWork = updateCurrentIfNeeded(newH) || didWork;

    if (didWork)
    {
        emitCurrentStateStatement();
    }

    return didWork;
}

void
BallotProtocol::findExtendedInterval(Interval& candidate,
                                     std::set<uint32> const& boundaries,
                                     std::function<bool(Interval const&)> pred)
{
    // iterate through interesting boundaries, starting from the top
    for (auto it = boundaries.rbegin(); it != boundaries.rend(); it++)
    {
        uint32 b = *it;

        Interval cur;
        if (candidate.first == 0)
        {
            // first, find the high bound
            cur = Interval(b, b);
        }
        else if (b > candidate.second) // invalid
        {
            continue;
        }
        else
        {
            cur.first = b;
            cur.second = candidate.second;
        }

        if (pred(cur))
        {
            candidate = cur;
        }
        else if (candidate.first != 0)
        {
            // could not extend further
            break;
        }
    }
}

std::set<uint32>
BallotProtocol::getCommitBoundariesFromStatements(pogcvmBallot const& ballot)
{
    std::set<uint32> res;
    for (auto const& env : mLatestEnvelopes)
    {
        auto const& pl = env.second->getStatement().pledges;
        switch (pl.type())
        {
        case pogcvm_ST_PREPARE:
        {
            auto const& p = pl.prepare();
            if (areBallotsCompatible(ballot, p.ballot))
            {
                if (p.nC)
                {
                    res.emplace(p.nC);
                    res.emplace(p.nH);
                }
            }
        }
        break;
        case pogcvm_ST_CONFIRM:
        {
            auto const& c = pl.confirm();
            if (areBallotsCompatible(ballot, c.ballot))
            {
                res.emplace(c.nCommit);
                res.emplace(c.nH);
            }
        }
        break;
        case pogcvm_ST_EXTERNALIZE:
        {
            auto const& e = pl.externalize();
            if (areBallotsCompatible(ballot, e.commit))
            {
                res.emplace(e.commit.counter);
                res.emplace(e.nH);
                res.emplace(UINT32_MAX);
            }
        }
        break;
        default:
            dbgAbort();
        }
    }
    return res;
}

bool
BallotProtocol::attemptAcceptCommit(pogcvmStatement const& hint)
{
    ZoneScoped;
    if (mPhase != pogcvm_PHASE_PREPARE && mPhase != pogcvm_PHASE_CONFIRM)
    {
        return false;
    }

    // extracts value from hint
    // note: ballot.counter is only used for logging purpose as we're looking at
    // possible value to commit
    pogcvmBallot ballot;
    switch (hint.pledges.type())
    {
    case pogcvmStatementType::pogcvm_ST_PREPARE:
    {
        auto const& prep = hint.pledges.prepare();
        if (prep.nC != 0)
        {
            ballot = pogcvmBallot(prep.nH, prep.ballot.value);
        }
        else
        {
            return false;
        }
    }
    break;
    case pogcvmStatementType::pogcvm_ST_CONFIRM:
    {
        auto const& con = hint.pledges.confirm();
        ballot = pogcvmBallot(con.nH, con.ballot.value);
    }
    break;
    case pogcvmStatementType::pogcvm_ST_EXTERNALIZE:
    {
        auto const& ext = hint.pledges.externalize();
        ballot = pogcvmBallot(ext.nH, ext.commit.value);
        break;
    }
    default:
        abort();
    };

    if (mPhase == pogcvm_PHASE_CONFIRM)
    {
        if (!areBallotsCompatible(ballot, mHighBallot->getBallot()))
        {
            return false;
        }
    }

    auto pred = [&ballot, this](Interval const& cur) -> bool {
        return federatedAccept(
            [&](pogcvmStatement const& st) -> bool {
                bool res = false;
                auto const& pl = st.pledges;
                switch (pl.type())
                {
                case pogcvm_ST_PREPARE:
                {
                    auto const& p = pl.prepare();
                    if (areBallotsCompatible(ballot, p.ballot))
                    {
                        if (p.nC != 0)
                        {
                            res = p.nC <= cur.first && cur.second <= p.nH;
                        }
                    }
                }
                break;
                case pogcvm_ST_CONFIRM:
                {
                    auto const& c = pl.confirm();
                    if (areBallotsCompatible(ballot, c.ballot))
                    {
                        res = c.nCommit <= cur.first;
                    }
                }
                break;
                case pogcvm_ST_EXTERNALIZE:
                {
                    auto const& e = pl.externalize();
                    if (areBallotsCompatible(ballot, e.commit))
                    {
                        res = e.commit.counter <= cur.first;
                    }
                }
                break;
                default:
                    dbgAbort();
                }
                return res;
            },
            std::bind(&BallotProtocol::commitPredicate, ballot, cur, _1));
    };

    // build the boundaries to scan
    std::set<uint32> boundaries = getCommitBoundariesFromStatements(ballot);

    if (boundaries.empty())
    {
        return false;
    }

    // now, look for the high interval
    Interval candidate;

    findExtendedInterval(candidate, boundaries, pred);

    bool res = false;

    if (candidate.first != 0)
    {
        if (mPhase != pogcvm_PHASE_CONFIRM ||
            candidate.second > mHighBallot->getBallot().counter)
        {
            pogcvmBallot c = pogcvmBallot(candidate.first, ballot.value);
            pogcvmBallot h = pogcvmBallot(candidate.second, ballot.value);
            res = setAcceptCommit(c, h);
        }
    }

    return res;
}

bool
BallotProtocol::setAcceptCommit(pogcvmBallot const& c, pogcvmBallot const& h)
{
    ZoneScoped;
    CLOG_TRACE(pogcvm, "BallotProtocol::setAcceptCommit i: {} new c: {} new h: {}",
               mSlot.getSlotIndex(), mSlot.getpogcvm().ballotToStr(c),
               mSlot.getpogcvm().ballotToStr(h));

    bool didWork = false;

    // remember h's value
    mValueOverride = mSlot.getpogcvmDriver().wrapValue(h.value);

    if (!mHighBallot || !mCommit ||
        compareBallots(mHighBallot->getBallot(), h) != 0 ||
        compareBallots(mCommit->getBallot(), c) != 0)
    {
        mCommit = makeBallot(c);
        mHighBallot = makeBallot(h);

        didWork = true;
    }

    if (mPhase == pogcvm_PHASE_PREPARE)
    {
        mPhase = pogcvm_PHASE_CONFIRM;
        if (mCurrentBallot &&
            !areBallotsLessAndCompatible(h, mCurrentBallot->getBallot()))
        {
            bumpToBallot(h, false);
        }
        mPreparedPrime.reset();

        didWork = true;
    }

    if (didWork)
    {
        updateCurrentIfNeeded(mHighBallot->getBallot());

        mSlot.getpogcvmDriver().acceptedCommit(mSlot.getSlotIndex(), h);
        emitCurrentStateStatement();
    }

    return didWork;
}

static uint32
statementBallotCounter(pogcvmStatement const& st)
{
    switch (st.pledges.type())
    {
    case pogcvm_ST_PREPARE:
        return st.pledges.prepare().ballot.counter;
    case pogcvm_ST_CONFIRM:
        return st.pledges.confirm().ballot.counter;
    case pogcvm_ST_EXTERNALIZE:
        return UINT32_MAX;
    default:
        // Should never be called with pogcvm_ST_NOMINATE.
        abort();
    }
}

static bool
hasVBlockingSubsetStrictlyAheadOf(
    std::shared_ptr<LocalNode> localNode,
    std::map<NodeID, pogcvmEnvelopeWrapperPtr> const& map, uint32_t n)
{
    return LocalNode::isVBlocking(
        localNode->getQuorumSet(), map,
        [&](pogcvmStatement const& st) { return statementBallotCounter(st) > n; });
}

// Step 9 from the paper (Feb 2016):
//
//   If ∃ S ⊆ M such that the set of senders {v_m | m ∈ S} is v-blocking
//   and ∀m ∈ S, b_m.n > b_v.n, then set b <- <n, z> where n is the lowest
//   counter for which no such S exists.
//
// a.k.a 4th rule for setting ballot.counter in the internet-draft (v03):
//
//   If nodes forming a blocking threshold all have ballot.counter values
//   greater than the local ballot.counter, then the local node immediately
//   cancels any pending timer, increases ballot.counter to the lowest
//   value such that this is no longer the case, and if appropriate
//   according to the rules above arms a new timer. Note that the blocking
//   threshold may include ballots from pogcvmCommit messages as well as
//   pogcvmExternalize messages, which implicitly have an infinite ballot
//   counter.

bool
BallotProtocol::attemptBump()
{
    ZoneScoped;
    if (mPhase == pogcvm_PHASE_PREPARE || mPhase == pogcvm_PHASE_CONFIRM)
    {

        // First check to see if this condition applies at all. If there
        // is no v-blocking set ahead of the local node, there's nothing
        // to do, return early.
        auto localNode = getLocalNode();
        uint32 localCounter =
            mCurrentBallot ? mCurrentBallot->getBallot().counter : 0;
        if (!hasVBlockingSubsetStrictlyAheadOf(localNode, mLatestEnvelopes,
                                               localCounter))
        {
            return false;
        }

        // Collect all possible counters we might need to advance to.
        std::set<uint32> allCounters;
        for (auto const& e : mLatestEnvelopes)
        {
            uint32_t c = statementBallotCounter(e.second->getStatement());
            if (c > localCounter)
                allCounters.insert(c);
        }

        // If we got to here, implicitly there _was_ a v-blocking subset
        // with counters above the local counter; we just need to find a
        // minimal n at which that's no longer true. So check them in
        // order, starting from the smallest.
        for (uint32_t n : allCounters)
        {
            if (!hasVBlockingSubsetStrictlyAheadOf(localNode, mLatestEnvelopes,
                                                   n))
            {
                // Move to n.
                return abandonBallot(n);
            }
        }
    }
    return false;
}

bool
BallotProtocol::attemptConfirmCommit(pogcvmStatement const& hint)
{
    ZoneScoped;
    if (mPhase != pogcvm_PHASE_CONFIRM)
    {
        return false;
    }

    if (!mHighBallot || !mCommit)
    {
        return false;
    }

    // extracts value from hint
    // note: ballot.counter is only used for logging purpose
    pogcvmBallot ballot;
    switch (hint.pledges.type())
    {
    case pogcvmStatementType::pogcvm_ST_PREPARE:
    {
        return false;
    }
    break;
    case pogcvmStatementType::pogcvm_ST_CONFIRM:
    {
        auto const& con = hint.pledges.confirm();
        ballot = pogcvmBallot(con.nH, con.ballot.value);
    }
    break;
    case pogcvmStatementType::pogcvm_ST_EXTERNALIZE:
    {
        auto const& ext = hint.pledges.externalize();
        ballot = pogcvmBallot(ext.nH, ext.commit.value);
        break;
    }
    default:
        abort();
    };

    if (!areBallotsCompatible(ballot, mCommit->getBallot()))
    {
        return false;
    }

    std::set<uint32> boundaries = getCommitBoundariesFromStatements(ballot);
    Interval candidate;

    auto pred = [&ballot, this](Interval const& cur) -> bool {
        return federatedRatify(
            std::bind(&BallotProtocol::commitPredicate, ballot, cur, _1));
    };

    findExtendedInterval(candidate, boundaries, pred);

    bool res = candidate.first != 0;
    if (res)
    {
        pogcvmBallot c = pogcvmBallot(candidate.first, ballot.value);
        pogcvmBallot h = pogcvmBallot(candidate.second, ballot.value);
        return setConfirmCommit(c, h);
    }
    return res;
}

bool
BallotProtocol::setConfirmCommit(pogcvmBallot const& c, pogcvmBallot const& h)
{
    ZoneScoped;
    CLOG_TRACE(pogcvm,
               "BallotProtocol::setConfirmCommit i: {} new c: {} new h: {}",
               mSlot.getSlotIndex(), mSlot.getpogcvm().ballotToStr(c),
               mSlot.getpogcvm().ballotToStr(h));

    mCommit = makeBallot(c);
    mHighBallot = makeBallot(h);
    updateCurrentIfNeeded(mHighBallot->getBallot());

    mPhase = pogcvm_PHASE_EXTERNALIZE;

    emitCurrentStateStatement();

    mSlot.stopNomination();

    mSlot.getpogcvmDriver().valueExternalized(mSlot.getSlotIndex(),
                                           mCommit->getBallot().value);

    return true;
}

bool
BallotProtocol::hasPreparedBallot(pogcvmBallot const& ballot,
                                  pogcvmStatement const& st)
{
    bool res;

    switch (st.pledges.type())
    {
    case pogcvm_ST_PREPARE:
    {
        auto const& p = st.pledges.prepare();
        res =
            (p.prepared && areBallotsLessAndCompatible(ballot, *p.prepared)) ||
            (p.preparedPrime &&
             areBallotsLessAndCompatible(ballot, *p.preparedPrime));
    }
    break;
    case pogcvm_ST_CONFIRM:
    {
        auto const& c = st.pledges.confirm();
        pogcvmBallot prepared(c.nPrepared, c.ballot.value);
        res = areBallotsLessAndCompatible(ballot, prepared);
    }
    break;
    case pogcvm_ST_EXTERNALIZE:
    {
        auto const& e = st.pledges.externalize();
        res = areBallotsCompatible(ballot, e.commit);
    }
    break;
    default:
        res = false;
        dbgAbort();
    }

    return res;
}

Hash
BallotProtocol::getCompanionQuorumSetHashFromStatement(pogcvmStatement const& st)
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
    default:
        dbgAbort();
    }
    return h;
}

pogcvmBallot
BallotProtocol::getWorkingBallot(pogcvmStatement const& st)
{
    pogcvmBallot res;
    switch (st.pledges.type())
    {
    case pogcvm_ST_PREPARE:
        res = st.pledges.prepare().ballot;
        break;
    case pogcvm_ST_CONFIRM:
    {
        auto const& con = st.pledges.confirm();
        res = pogcvmBallot(con.nCommit, con.ballot.value);
    }
    break;
    case pogcvm_ST_EXTERNALIZE:
        res = st.pledges.externalize().commit;
        break;
    default:
        dbgAbort();
    }
    return res;
}

bool
BallotProtocol::setPrepared(pogcvmBallot const& ballot)
{
    bool didWork = false;

    // p and p' are the two highest prepared and incompatible ballots
    if (mPrepared)
    {
        int comp = compareBallots(mPrepared->getBallot(), ballot);
        if (comp < 0)
        {
            // as we're replacing p, we see if we should also replace p'
            if (!areBallotsCompatible(mPrepared->getBallot(), ballot))
            {
                mPreparedPrime = std::make_unique<pogcvmBallotWrapper>(*mPrepared);
            }
            mPrepared = makeBallot(ballot);
            didWork = true;
        }
        else if (comp > 0)
        {
            // check if we should update only p', this happens
            // either p' was NULL
            // or p' gets replaced by ballot
            //      (p' < ballot and ballot is incompatible with p)
            // note, the later check is here out of paranoia as this function is
            // not called with a value that would not allow us to make progress

            if (!mPreparedPrime ||
                ((compareBallots(mPreparedPrime->getBallot(), ballot) < 0) &&
                 !areBallotsCompatible(mPrepared->getBallot(), ballot)))
            {
                mPreparedPrime = makeBallot(ballot);
                didWork = true;
            }
        }
    }
    else
    {
        mPrepared = makeBallot(ballot);
        didWork = true;
    }
    return didWork;
}

int
BallotProtocol::compareBallots(std::unique_ptr<pogcvmBallot> const& b1,
                               std::unique_ptr<pogcvmBallot> const& b2)
{
    int res;
    if (b1 && b2)
    {
        res = compareBallots(*b1, *b2);
    }
    else if (b1 && !b2)
    {
        res = 1;
    }
    else if (!b1 && b2)
    {
        res = -1;
    }
    else
    {
        res = 0;
    }
    return res;
}

int
BallotProtocol::compareBallots(pogcvmBallot const& b1, pogcvmBallot const& b2)
{
    if (b1.counter < b2.counter)
    {
        return -1;
    }
    else if (b2.counter < b1.counter)
    {
        return 1;
    }
    // ballots are also strictly ordered by value
    if (b1.value < b2.value)
    {
        return -1;
    }
    else if (b2.value < b1.value)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

bool
BallotProtocol::areBallotsCompatible(pogcvmBallot const& b1, pogcvmBallot const& b2)
{
    return b1.value == b2.value;
}

bool
BallotProtocol::areBallotsLessAndIncompatible(pogcvmBallot const& b1,
                                              pogcvmBallot const& b2)
{
    return (compareBallots(b1, b2) <= 0) && !areBallotsCompatible(b1, b2);
}

bool
BallotProtocol::areBallotsLessAndCompatible(pogcvmBallot const& b1,
                                            pogcvmBallot const& b2)
{
    return (compareBallots(b1, b2) <= 0) && areBallotsCompatible(b1, b2);
}

void
BallotProtocol::setStateFromEnvelope(pogcvmEnvelopeWrapperPtr e)
{
    ZoneScoped;
    if (mCurrentBallot)
    {
        throw std::runtime_error(
            "Cannot set state after starting ballot protocol");
    }

    recordEnvelope(e);

    mLastEnvelope = e;
    mLastEnvelopeEmit = mLastEnvelope;

    auto const& pl = e->getStatement().pledges;

    switch (pl.type())
    {
    case pogcvmStatementType::pogcvm_ST_PREPARE:
    {
        auto const& prep = pl.prepare();
        auto const& b = prep.ballot;
        bumpToBallot(b, true);
        if (prep.prepared)
        {
            mPrepared = makeBallot(*prep.prepared);
        }
        if (prep.preparedPrime)
        {
            mPreparedPrime = makeBallot(*prep.preparedPrime);
        }
        if (prep.nH)
        {
            mHighBallot = makeBallot(prep.nH, b.value);
        }
        if (prep.nC)
        {
            mCommit = makeBallot(prep.nC, b.value);
        }
        mPhase = pogcvm_PHASE_PREPARE;
    }
    break;
    case pogcvmStatementType::pogcvm_ST_CONFIRM:
    {
        auto const& c = pl.confirm();
        auto const& v = c.ballot.value;
        bumpToBallot(c.ballot, true);
        mPrepared = makeBallot(c.nPrepared, v);
        mHighBallot = makeBallot(c.nH, v);
        mCommit = makeBallot(c.nCommit, v);
        mPhase = pogcvm_PHASE_CONFIRM;
    }
    break;
    case pogcvmStatementType::pogcvm_ST_EXTERNALIZE:
    {
        auto const& ext = pl.externalize();
        auto const& v = ext.commit.value;
        bumpToBallot(pogcvmBallot(UINT32_MAX, v), true);
        mPrepared = makeBallot(UINT32_MAX, v);
        mHighBallot = makeBallot(ext.nH, v);
        mCommit = makeBallot(ext.commit);
        mPhase = pogcvm_PHASE_EXTERNALIZE;
    }
    break;
    default:
        dbgAbort();
    }
}

bool
BallotProtocol::processCurrentState(
    std::function<bool(pogcvmEnvelope const&)> const& f, bool forceSelf) const
{
    for (auto const& n : mLatestEnvelopes)
    {
        // only return messages for self if the slot is fully validated
        if (forceSelf || !(n.first == mSlot.getpogcvm().getLocalNodeID()) ||
            mSlot.isFullyValidated())
        {
            if (!f(n.second->getEnvelope()))
            {
                return false;
            }
        }
    }
    return true;
}

pogcvmEnvelope const*
BallotProtocol::getLatestMessage(NodeID const& id) const
{
    auto it = mLatestEnvelopes.find(id);
    if (it != mLatestEnvelopes.end())
    {
        return &it->second->getEnvelope();
    }
    return nullptr;
}

std::vector<pogcvmEnvelope>
BallotProtocol::getExternalizingState() const
{
    std::vector<pogcvmEnvelope> res;
    if (mPhase == pogcvm_PHASE_EXTERNALIZE)
    {
        res.reserve(mLatestEnvelopes.size());
        for (auto const& n : mLatestEnvelopes)
        {
            if (!(n.first == mSlot.getpogcvm().getLocalNodeID()))
            {
                // good approximation: statements with the value that
                // externalized
                // we could filter more using mConfirmedPrepared as well
                if (areBallotsCompatible(
                        getWorkingBallot(n.second->getStatement()),
                        mCommit->getBallot()))
                {
                    res.emplace_back(n.second->getEnvelope());
                }
            }
            else if (mSlot.isFullyValidated())
            {
                // only return messages for self if the slot is fully validated
                res.emplace_back(n.second->getEnvelope());
            }
        }
    }
    return res;
}

void
BallotProtocol::advanceSlot(pogcvmStatement const& hint)
{
    ZoneScoped;
    mCurrentMessageLevel++;
    CLOG_TRACE(pogcvm, "BallotProtocol::advanceSlot {} {}", mCurrentMessageLevel,
               getLocalState());

    if (mCurrentMessageLevel >= MAX_ADVANCE_SLOT_RECURSION)
    {
        throw std::runtime_error(
            "maximum number of transitions reached in advanceSlot");
    }

    // attempt* methods will queue up messages, causing advanceSlot to be
    // called recursively

    // done in order so that we follow the steps from the white paper in
    // order
    // allowing the state to be updated properly

    bool didWork = false;

    didWork = attemptAcceptPrepared(hint) || didWork;

    didWork = attemptConfirmPrepared(hint) || didWork;

    didWork = attemptAcceptCommit(hint) || didWork;

    didWork = attemptConfirmCommit(hint) || didWork;

    // only bump after we're done with everything else
    if (mCurrentMessageLevel == 1)
    {
        bool didBump = false;
        do
        {
            // attemptBump may invoke advanceSlot recursively
            didBump = attemptBump();
            didWork = didBump || didWork;
        } while (didBump);

        checkHeardFromQuorum();
    }

    CLOG_TRACE(pogcvm, "BallotProtocol::advanceSlot {} - exiting {}",
               mCurrentMessageLevel, getLocalState());

    --mCurrentMessageLevel;

    if (didWork)
    {
        sendLatestEnvelope();
    }
}

std::set<Value>
BallotProtocol::getStatementValues(pogcvmStatement const& st)
{
    std::set<Value> values;

    switch (st.pledges.type())
    {
    case pogcvmStatementType::pogcvm_ST_PREPARE:
    {
        auto const& prep = st.pledges.prepare();
        auto const& b = prep.ballot;
        if (b.counter != 0)
        {
            values.insert(prep.ballot.value);
        }
        if (prep.prepared)
        {
            values.insert(prep.prepared->value);
        }
        if (prep.preparedPrime)
        {
            values.insert(prep.preparedPrime->value);
        }
    }
    break;
    case pogcvmStatementType::pogcvm_ST_CONFIRM:
        values.insert(st.pledges.confirm().ballot.value);
        break;
    case pogcvmStatementType::pogcvm_ST_EXTERNALIZE:
        values.insert(st.pledges.externalize().commit.value);
        break;
    default:
        abort();
    }
    return values;
}

pogcvmDriver::ValidationLevel
BallotProtocol::validateValues(pogcvmStatement const& st)
{
    ZoneScoped;
    std::set<Value> values;

    values = getStatementValues(st);

    if (values.empty())
    {
        // This shouldn't happen
        return pogcvmDriver::kInvalidValue;
    }

    pogcvmDriver::ValidationLevel res = std::accumulate(
        values.begin(), values.end(), pogcvmDriver::kFullyValidatedValue,
        [&](pogcvmDriver::ValidationLevel lv, POGchain::Value const& v) {
            if (lv > pogcvmDriver::kInvalidValue)
            {
                auto tr = mSlot.getpogcvmDriver().validateValue(
                    mSlot.getSlotIndex(), v, false);
                lv = std::min(tr, lv);
            }
            return lv;
        });

    return res;
}

void
BallotProtocol::sendLatestEnvelope()
{
    ZoneScoped;
    // emit current envelope if needed
    if (mCurrentMessageLevel == 0 && mLastEnvelope && mSlot.isFullyValidated())
    {
        if (!mLastEnvelopeEmit || mLastEnvelope != mLastEnvelopeEmit)
        {
            mLastEnvelopeEmit = mLastEnvelope;
            mSlot.getpogcvmDriver().emitEnvelope(mLastEnvelopeEmit->getEnvelope());
        }
    }
}

std::array<const char*, BallotProtocol::pogcvm_PHASE_NUM>
    BallotProtocol::phaseNames = std::array{"PREPARE", "FINISH", "EXTERNALIZE"};

Json::Value
BallotProtocol::getJsonInfo()
{
    Json::Value ret;
    ret["heard"] = mHeardFromQuorum;
    ret["ballot"] = ballotToStr(mCurrentBallot);
    ret["phase"] = phaseNames[mPhase];

    ret["state"] = getLocalState();
    return ret;
}

Json::Value
BallotProtocol::getJsonQuorumInfo(NodeID const& id, bool summary, bool fullKeys)
{
    Json::Value ret;
    auto& phase = ret["phase"];

    // find the state of the node `id`
    pogcvmBallot b;
    Hash qSetHash;

    auto stateit = mLatestEnvelopes.find(id);
    if (stateit == mLatestEnvelopes.end())
    {
        phase = "unknown";
        if (id == mSlot.getLocalNode()->getNodeID())
        {
            qSetHash = mSlot.getLocalNode()->getQuorumSetHash();
        }
    }
    else
    {
        auto const& st = stateit->second->getStatement();

        switch (st.pledges.type())
        {
        case pogcvmStatementType::pogcvm_ST_PREPARE:
            phase = "PREPARE";
            b = st.pledges.prepare().ballot;
            break;
        case pogcvmStatementType::pogcvm_ST_CONFIRM:
            phase = "CONFIRM";
            b = st.pledges.confirm().ballot;
            break;
        case pogcvmStatementType::pogcvm_ST_EXTERNALIZE:
            phase = "EXTERNALIZE";
            b = st.pledges.externalize().commit;
            break;
        default:
            dbgAbort();
        }
        // use the companion set here even for externalize to capture
        // the view of the quorum set during validation
        qSetHash = mSlot.getCompanionQuorumSetHashFromStatement(st);
    }

    Json::Value& disagree = ret["disagree"];
    Json::Value& missing = ret["missing"];
    Json::Value& delayed = ret["delayed"];

    int n_missing = 0, n_disagree = 0, n_delayed = 0;

    int agree = 0;
    auto qSet = mSlot.getpogcvmDriver().getQSet(qSetHash);
    if (!qSet)
    {
        phase = "expired";
        return ret;
    }
    LocalNode::forAllNodes(*qSet, [&](NodeID const& n) {
        auto it = mLatestEnvelopes.find(n);
        if (it == mLatestEnvelopes.end())
        {
            if (!summary)
            {
                missing.append(mSlot.getpogcvmDriver().toStrKey(n, fullKeys));
            }
            n_missing++;
        }
        else
        {
            auto& st = it->second->getStatement();
            if (areBallotsCompatible(getWorkingBallot(st), b))
            {
                agree++;
                auto t = st.pledges.type();
                if (!(t == pogcvmStatementType::pogcvm_ST_EXTERNALIZE ||
                      (t == pogcvmStatementType::pogcvm_ST_CONFIRM &&
                       st.pledges.confirm().ballot.counter == UINT32_MAX)))
                {
                    if (!summary)
                    {
                        delayed.append(
                            mSlot.getpogcvmDriver().toStrKey(n, fullKeys));
                    }
                    n_delayed++;
                }
            }
            else
            {
                if (!summary)
                {
                    disagree.append(mSlot.getpogcvmDriver().toStrKey(n, fullKeys));
                }
                n_disagree++;
            }
        }
        return true;
    });
    if (summary)
    {
        missing = n_missing;
        disagree = n_disagree;
        delayed = n_delayed;
    }

    auto f = LocalNode::findClosestVBlocking(
        *qSet, mLatestEnvelopes,
        [&](pogcvmStatement const& st) {
            return areBallotsCompatible(getWorkingBallot(st), b);
        },
        &id);
    ret["fail_at"] = static_cast<int>(f.size());

    if (!summary)
    {
        auto& f_ex = ret["fail_with"];
        for (auto const& n : f)
        {
            f_ex.append(mSlot.getpogcvmDriver().toStrKey(n, fullKeys));
        }
        ret["value"] = getLocalNode()->toJson(*qSet, fullKeys);
    }

    ret["hash"] = hexAbbrev(qSetHash);
    ret["agree"] = agree;

    return ret;
}

std::string
BallotProtocol::getLocalState() const
{
    std::ostringstream oss;

    oss << "i: " << mSlot.getSlotIndex() << " | " << phaseNames[mPhase]
        << " | b: " << ballotToStr(mCurrentBallot)
        << " | p: " << ballotToStr(mPrepared)
        << " | p': " << ballotToStr(mPreparedPrime)
        << " | h: " << ballotToStr(mHighBallot)
        << " | c: " << ballotToStr(mCommit)
        << " | M: " << mLatestEnvelopes.size();
    return oss.str();
}

std::shared_ptr<LocalNode>
BallotProtocol::getLocalNode()
{
    return mSlot.getpogcvm().getLocalNode();
}

bool
BallotProtocol::federatedAccept(StatementPredicate voted,
                                StatementPredicate accepted)
{
    ZoneScoped;
    return mSlot.federatedAccept(voted, accepted, mLatestEnvelopes);
}

bool
BallotProtocol::federatedRatify(StatementPredicate voted)
{
    ZoneScoped;
    return mSlot.federatedRatify(voted, mLatestEnvelopes);
}

void
BallotProtocol::checkHeardFromQuorum()
{
    // this method is safe to call regardless of the transitions of the other
    // nodes on the network:
    // we guarantee that other nodes can only transition to higher counters
    // (messages are ignored upstream)
    // therefore the local node will not flip flop between "seen" and "not seen"
    // for a given counter on the local node
    if (mCurrentBallot)
    {
        ZoneScoped;
        if (LocalNode::isQuorum(
                getLocalNode()->getQuorumSet(), mLatestEnvelopes,
                std::bind(&Slot::getQuorumSetFromStatement, &mSlot, _1),
                [&](pogcvmStatement const& st) {
                    bool res;
                    if (st.pledges.type() == pogcvm_ST_PREPARE)
                    {
                        res = mCurrentBallot->getBallot().counter <=
                              st.pledges.prepare().ballot.counter;
                    }
                    else
                    {
                        res = true;
                    }
                    return res;
                }))
        {
            bool oldHQ = mHeardFromQuorum;
            mHeardFromQuorum = true;
            if (!oldHQ)
            {
                // if we transition from not heard -> heard, we start the timer
                mSlot.getpogcvmDriver().ballotDidHearFromQuorum(
                    mSlot.getSlotIndex(), mCurrentBallot->getBallot());
                if (mPhase != pogcvm_PHASE_EXTERNALIZE)
                {
                    startBallotProtocolTimer();
                }
            }
            if (mPhase == pogcvm_PHASE_EXTERNALIZE)
            {
                stopBallotProtocolTimer();
            }
        }
        else
        {
            mHeardFromQuorum = false;
            stopBallotProtocolTimer();
        }
    }
}

BallotProtocol::pogcvmBallotWrapperUPtr
BallotProtocol::makeBallot(pogcvmBallot const& b) const
{
    auto res = std::make_unique<pogcvmBallotWrapper>(
        b.counter, mSlot.getpogcvmDriver().wrapValue(b.value));
    return res;
}

BallotProtocol::pogcvmBallotWrapperUPtr
BallotProtocol::makeBallot(uint32 c, Value const& v) const
{
    return makeBallot(pogcvmBallot(c, v));
}

std::string
BallotProtocol::ballotToStr(
    BallotProtocol::pogcvmBallotWrapperUPtr const& ballot) const
{
    std::string res;
    if (ballot)
    {
        res = mSlot.getpogcvm().ballotToStr(ballot->getBallot());
    }
    else
    {
        res = "(<null_ballot>)";
    }
    return res;
}
}
