// Copyright 2014 POGchain Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0
#include "util/asio.h"

#include "crypto/Hex.h"
#include "crypto/SHA.h"
#include "lib/catch.hpp"
#include "pogcvm/LocalNode.h"
#include "pogcvm/pogcvm.h"
#include "pogcvm/Slot.h"
#include "simulation/Simulation.h"
#include "util/Logging.h"
#include "util/Math.h"
#include "util/XDROperators.h"
#include "xdrpp/marshal.h"
#include "xdrpp/printer.h"
#include <fmt/format.h>

// General convention in this file is that numbers in parenthesis
// refer to the rule number in the related protocol from the white paper
// For example (2) in the ballot protocol refers to:
// If phi = PREPARE and m lets v confirm new higher ballots prepared,
// then raise h to the highest such ballot and set z = h.x

namespace POGchain
{

// x < y < z < zz
// k can be anything
static Value xValue, yValue, zValue, zzValue, kValue;

static void
setupValues()
{
    std::vector<Value> v;
    std::string d = fmt::format("SEED_VALUE_DATA_{}", gRandomEngine());
    for (int i = 0; i < 4; i++)
    {
        auto h = sha256(fmt::format("{}/{}", d, i));
        v.emplace_back(xdr::xdr_to_opaque(h));
    }
    std::sort(v.begin(), v.end());
    xValue = v[0];
    yValue = v[1];
    zValue = v[2];
    zzValue = v[3];

    // kValue is independent
    auto kHash = sha256(d);
    kValue = xdr::xdr_to_opaque(kHash);
}

class Testpogcvm : public pogcvmDriver
{
  public:
    pogcvm mpogcvm;

    Testpogcvm(NodeID const& nodeID, pogcvmQuorumSet const& qSetLocal,
            bool isValidator = true)
        : mpogcvm(*this, nodeID, isValidator, qSetLocal)
    {
        mPriorityLookup = [&](NodeID const& n) {
            return (n == mpogcvm.getLocalNodeID()) ? 1000 : 1;
        };

        mHashValueCalculator = [&](Value const& v) { return 0; };

        auto localQSet =
            std::make_shared<pogcvmQuorumSet>(mpogcvm.getLocalQuorumSet());
        storeQuorumSet(localQSet);
    }

    void
    signEnvelope(pogcvmEnvelope&) override
    {
    }

    void
    storeQuorumSet(pogcvmQuorumSetPtr qSet)
    {
        Hash qSetHash = sha256(xdr::xdr_to_opaque(*qSet.get()));
        mQuorumSets[qSetHash] = qSet;
    }

    pogcvmDriver::ValidationLevel
    validateValue(uint64 slotIndex, Value const& value,
                  bool nomination) override
    {
        return pogcvmDriver::kFullyValidatedValue;
    }

    void
    ballotDidHearFromQuorum(uint64 slotIndex, pogcvmBallot const& ballot) override
    {
        mHeardFromQuorums[slotIndex].push_back(ballot);
    }

    void
    valueExternalized(uint64 slotIndex, Value const& value) override
    {
        if (mExternalizedValues.find(slotIndex) != mExternalizedValues.end())
        {
            throw std::out_of_range("Value already externalized");
        }
        mExternalizedValues[slotIndex] = value;
    }

    pogcvmQuorumSetPtr
    getQSet(Hash const& qSetHash) override
    {
        if (mQuorumSets.find(qSetHash) != mQuorumSets.end())
        {

            return mQuorumSets[qSetHash];
        }
        return pogcvmQuorumSetPtr();
    }

    void
    emitEnvelope(pogcvmEnvelope const& envelope) override
    {
        mEnvs.push_back(envelope);
    }

    // used to test BallotProtocol and bypass nomination
    bool
    bumpState(uint64 slotIndex, Value const& v)
    {
        return mpogcvm.getSlot(slotIndex, true)->bumpState(v, true);
    }

    bool
    nominate(uint64 slotIndex, Value const& value, bool timedout)
    {
        auto wv = wrapValue(value);
        return mpogcvm.getSlot(slotIndex, true)->nominate(wv, value, timedout);
    }

    // only used by nomination protocol
    ValueWrapperPtr
    combineCandidates(uint64 slotIndex,
                      ValueWrapperPtrSet const& candidates) override
    {
        REQUIRE(candidates.size() == mExpectedCandidates.size());
        auto it1 = candidates.begin();
        auto it2 = mExpectedCandidates.end();
        for (; it1 != candidates.end() && it2 != mExpectedCandidates.end();
             it1++, it2++)
        {
            REQUIRE((*it1)->getValue() == *it2);
        }

        REQUIRE(!mCompositeValue.empty());

        return wrapValue(mCompositeValue);
    }

    std::set<Value> mExpectedCandidates;
    Value mCompositeValue;

    Hash
    getHashOf(std::vector<xdr::opaque_vec<>> const& vals) const override
    {
        SHA256 hasher;
        for (auto const& v : vals)
        {
            hasher.add(v);
        }
        return hasher.finish();
    }

    // override the internal hashing scheme in order to make tests
    // more predictable.
    uint64
    computeHashNode(uint64 slotIndex, Value const& prev, bool isPriority,
                    int32_t roundNumber, NodeID const& nodeID) override
    {
        uint64 res;
        if (isPriority)
        {
            res = mPriorityLookup(nodeID);
        }
        else
        {
            res = 0;
        }
        return res;
    }

    // override the value hashing, to make tests more predictable.
    uint64
    computeValueHash(uint64 slotIndex, Value const& prev, int32_t roundNumber,
                     Value const& value) override
    {
        return mHashValueCalculator(value);
    }

    std::function<uint64(NodeID const&)> mPriorityLookup;
    std::function<uint64(Value const&)> mHashValueCalculator;

    std::map<Hash, pogcvmQuorumSetPtr> mQuorumSets;
    std::vector<pogcvmEnvelope> mEnvs;
    std::map<uint64, Value> mExternalizedValues;
    std::map<uint64, std::vector<pogcvmBallot>> mHeardFromQuorums;

    struct TimerData
    {
        std::chrono::milliseconds mAbsoluteTimeout;
        std::function<void()> mCallback;
    };
    std::map<int, TimerData> mTimers;
    std::chrono::milliseconds mCurrentTimerOffset{0};

    void
    setupTimer(uint64 slotIndex, int timerID, std::chrono::milliseconds timeout,
               std::function<void()> cb) override
    {
        mTimers[timerID] =
            TimerData{mCurrentTimerOffset +
                          (cb ? timeout : std::chrono::milliseconds::zero()),
                      cb};
    }

    TimerData
    getBallotProtocolTimer()
    {
        return mTimers[Slot::BALLOT_PROTOCOL_TIMER];
    }

    // pretends the time moved forward
    std::chrono::milliseconds
    bumpTimerOffset()
    {
        // increase by more than the maximum timeout
        mCurrentTimerOffset += std::chrono::hours(5);
        return mCurrentTimerOffset;
    }

    // returns true if a ballot protocol timer exists (in the past or future)
    bool
    hasBallotTimer()
    {
        return !!getBallotProtocolTimer().mCallback;
    }

    // returns true if the ballot protocol timer is scheduled in the future
    // false if scheduled in the past
    // this method is mostly used to verify that the timer *would* have fired
    bool
    hasBallotTimerUpcoming()
    {
        // timer must be scheduled in the past or future
        REQUIRE(hasBallotTimer());
        return mCurrentTimerOffset < getBallotProtocolTimer().mAbsoluteTimeout;
    }

    Value const&
    getLatestCompositeCandidate(uint64 slotIndex)
    {
        return mpogcvm.getSlot(slotIndex, true)
            ->getLatestCompositeCandidate()
            ->getValue();
    }

    void
    receiveEnvelope(pogcvmEnvelope const& envelope)
    {
        auto envW = mpogcvm.getDriver().wrapEnvelope(envelope);
        mpogcvm.receiveEnvelope(envW);
    }

    Slot&
    getSlot(uint64 index)
    {
        return *mpogcvm.getSlot(index, false);
    }

    std::vector<pogcvmEnvelope>
    getEntireState(uint64 index)
    {
        auto v = mpogcvm.getSlot(index, false)->getEntireCurrentState();
        return v;
    }

    pogcvmEnvelope
    getCurrentEnvelope(uint64 index, NodeID const& id)
    {
        auto r = getEntireState(index);
        auto it = std::find_if(r.begin(), r.end(), [&](pogcvmEnvelope const& e) {
            return e.statement.nodeID == id;
        });
        if (it != r.end())
        {
            return *it;
        }
        throw std::runtime_error("not found");
    }

    std::set<NodeID>
    getNominationLeaders(uint64 slotIndex)
    {
        return mpogcvm.getSlot(slotIndex, false)->getNominationLeaders();
    }
};

static pogcvmEnvelope
makeEnvelope(SecretKey const& secretKey, uint64 slotIndex,
             pogcvmStatement const& statement)
{
    pogcvmEnvelope envelope;
    envelope.statement = statement;
    envelope.statement.nodeID = secretKey.getPublicKey();
    envelope.statement.slotIndex = slotIndex;

    envelope.signature = secretKey.sign(xdr::xdr_to_opaque(envelope.statement));

    return envelope;
}

static pogcvmEnvelope
makeExternalize(SecretKey const& secretKey, Hash const& qSetHash,
                uint64 slotIndex, pogcvmBallot const& commitBallot, uint32 nH)
{
    pogcvmStatement st;
    st.pledges.type(pogcvm_ST_EXTERNALIZE);
    auto& ext = st.pledges.externalize();
    ext.commit = commitBallot;
    ext.nH = nH;
    ext.commitQuorumSetHash = qSetHash;

    return makeEnvelope(secretKey, slotIndex, st);
}

static pogcvmEnvelope
makeConfirm(SecretKey const& secretKey, Hash const& qSetHash, uint64 slotIndex,
            uint32 prepareCounter, pogcvmBallot const& b, uint32 nC, uint32 nH)
{
    pogcvmStatement st;
    st.pledges.type(pogcvm_ST_CONFIRM);
    auto& con = st.pledges.confirm();
    con.ballot = b;
    con.nPrepared = prepareCounter;
    con.nCommit = nC;
    con.nH = nH;
    con.quorumSetHash = qSetHash;

    return makeEnvelope(secretKey, slotIndex, st);
}

static pogcvmEnvelope
makePrepare(SecretKey const& secretKey, Hash const& qSetHash, uint64 slotIndex,
            pogcvmBallot const& ballot, pogcvmBallot* prepared = nullptr,
            uint32 nC = 0, uint32 nH = 0, pogcvmBallot* preparedPrime = nullptr)
{
    pogcvmStatement st;
    st.pledges.type(pogcvm_ST_PREPARE);
    auto& p = st.pledges.prepare();
    p.ballot = ballot;
    p.quorumSetHash = qSetHash;
    if (prepared)
    {
        p.prepared.activate() = *prepared;
    }

    p.nC = nC;
    p.nH = nH;

    if (preparedPrime)
    {
        p.preparedPrime.activate() = *preparedPrime;
    }

    return makeEnvelope(secretKey, slotIndex, st);
}

static pogcvmEnvelope
makeNominate(SecretKey const& secretKey, Hash const& qSetHash, uint64 slotIndex,
             std::vector<Value> votes, std::vector<Value> accepted)
{
    std::sort(votes.begin(), votes.end());
    std::sort(accepted.begin(), accepted.end());

    pogcvmStatement st;
    st.pledges.type(pogcvm_ST_NOMINATE);
    auto& nom = st.pledges.nominate();
    nom.quorumSetHash = qSetHash;
    for (auto const& v : votes)
    {
        nom.votes.emplace_back(v);
    }
    for (auto const& a : accepted)
    {
        nom.accepted.emplace_back(a);
    }
    return makeEnvelope(secretKey, slotIndex, st);
}

void
verifyPrepare(pogcvmEnvelope const& actual, SecretKey const& secretKey,
              Hash const& qSetHash, uint64 slotIndex, pogcvmBallot const& ballot,
              pogcvmBallot* prepared = nullptr, uint32 nC = 0, uint32 nH = 0,
              pogcvmBallot* preparedPrime = nullptr)
{
    auto exp = makePrepare(secretKey, qSetHash, slotIndex, ballot, prepared, nC,
                           nH, preparedPrime);
    REQUIRE(exp.statement == actual.statement);
}

void
verifyConfirm(pogcvmEnvelope const& actual, SecretKey const& secretKey,
              Hash const& qSetHash, uint64 slotIndex, uint32 nPrepared,
              pogcvmBallot const& b, uint32 nC, uint32 nH)
{
    auto exp =
        makeConfirm(secretKey, qSetHash, slotIndex, nPrepared, b, nC, nH);
    REQUIRE(exp.statement == actual.statement);
}

void
verifyExternalize(pogcvmEnvelope const& actual, SecretKey const& secretKey,
                  Hash const& qSetHash, uint64 slotIndex,
                  pogcvmBallot const& commit, uint32 nH)
{
    auto exp = makeExternalize(secretKey, qSetHash, slotIndex, commit, nH);
    REQUIRE(exp.statement == actual.statement);
}

void
verifyNominate(pogcvmEnvelope const& actual, SecretKey const& secretKey,
               Hash const& qSetHash, uint64 slotIndex, std::vector<Value> votes,
               std::vector<Value> accepted)
{
    auto exp = makeNominate(secretKey, qSetHash, slotIndex, votes, accepted);
    REQUIRE(exp.statement == actual.statement);
}

TEST_CASE("vblocking and quorum", "[pogcvm]")
{
    setupValues();
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);
    SIMULATION_CREATE_NODE(3);

    pogcvmQuorumSet qSet;
    qSet.threshold = 3;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);
    qSet.validators.push_back(v3NodeID);

    std::vector<NodeID> nodeSet;
    nodeSet.push_back(v0NodeID);

    REQUIRE(LocalNode::isQuorumSlice(qSet, nodeSet) == false);
    REQUIRE(LocalNode::isVBlocking(qSet, nodeSet) == false);

    nodeSet.push_back(v2NodeID);

    REQUIRE(LocalNode::isQuorumSlice(qSet, nodeSet) == false);
    REQUIRE(LocalNode::isVBlocking(qSet, nodeSet) == true);

    nodeSet.push_back(v3NodeID);
    REQUIRE(LocalNode::isQuorumSlice(qSet, nodeSet) == true);
    REQUIRE(LocalNode::isVBlocking(qSet, nodeSet) == true);

    nodeSet.push_back(v1NodeID);
    REQUIRE(LocalNode::isQuorumSlice(qSet, nodeSet) == true);
    REQUIRE(LocalNode::isVBlocking(qSet, nodeSet) == true);
}

TEST_CASE("v blocking distance", "[pogcvm]")
{
    setupValues();
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);
    SIMULATION_CREATE_NODE(3);
    SIMULATION_CREATE_NODE(4);
    SIMULATION_CREATE_NODE(5);
    SIMULATION_CREATE_NODE(6);
    SIMULATION_CREATE_NODE(7);

    pogcvmQuorumSet qSet;
    qSet.threshold = 2;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);

    auto check = [&](pogcvmQuorumSet const& qSetCheck, std::set<NodeID> const& s,
                     size_t expected) {
        auto r = LocalNode::findClosestVBlocking(qSetCheck, s, nullptr);
        REQUIRE(expected == r.size());
    };

    std::set<NodeID> good;
    good.insert(v0NodeID);

    // already v-blocking
    check(qSet, good, 0);

    good.insert(v1NodeID);
    // either v0 or v1
    check(qSet, good, 1);

    good.insert(v2NodeID);
    // any 2 of v0..v2
    check(qSet, good, 2);

    pogcvmQuorumSet qSubSet1;
    qSubSet1.threshold = 1;
    qSubSet1.validators.push_back(v3NodeID);
    qSubSet1.validators.push_back(v4NodeID);
    qSubSet1.validators.push_back(v5NodeID);
    qSet.innerSets.push_back(qSubSet1);

    good.insert(v3NodeID);
    // any 3 of v0..v3
    check(qSet, good, 3);

    good.insert(v4NodeID);
    // v0..v2
    check(qSet, good, 3);

    qSet.threshold = 1;
    // v0..v4
    check(qSet, good, 5);

    good.insert(v5NodeID);
    // v0..v5
    check(qSet, good, 6);

    pogcvmQuorumSet qSubSet2;
    qSubSet2.threshold = 2;
    qSubSet2.validators.push_back(v6NodeID);
    qSubSet2.validators.push_back(v7NodeID);

    qSet.innerSets.push_back(qSubSet2);
    // v0..v5
    check(qSet, good, 6);

    good.insert(v6NodeID);
    // v0..v5
    check(qSet, good, 6);

    good.insert(v7NodeID);
    // v0..v5 and one of 6,7
    check(qSet, good, 7);

    qSet.threshold = 4;
    // v6, v7
    check(qSet, good, 2);

    qSet.threshold = 3;
    // v0..v2
    check(qSet, good, 3);

    qSet.threshold = 2;
    // v0..v2 and one of v6,v7
    check(qSet, good, 4);
}

typedef std::function<pogcvmEnvelope(SecretKey const& sk)> genEnvelope;

using namespace std::placeholders;

static genEnvelope
makePrepareGen(Hash const& qSetHash, pogcvmBallot const& ballot,
               pogcvmBallot* prepared = nullptr, uint32 nC = 0, uint32 nH = 0,
               pogcvmBallot* preparedPrime = nullptr)
{
    return std::bind(makePrepare, _1, std::cref(qSetHash), 0, std::cref(ballot),
                     prepared, nC, nH, preparedPrime);
}

static genEnvelope
makeConfirmGen(Hash const& qSetHash, uint32 prepareCounter, pogcvmBallot const& b,
               uint32 nC, uint32 nH)
{
    return std::bind(makeConfirm, _1, std::cref(qSetHash), 0, prepareCounter,
                     std::cref(b), nC, nH);
}

static genEnvelope
makeExternalizeGen(Hash const& qSetHash, pogcvmBallot const& commitBallot,
                   uint32 nH)
{
    return std::bind(makeExternalize, _1, std::cref(qSetHash), 0,
                     std::cref(commitBallot), nH);
}

TEST_CASE("ballot protocol 5", "[pogcvm][ballotprotocol]")
{
    setupValues();
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);
    SIMULATION_CREATE_NODE(3);
    SIMULATION_CREATE_NODE(4);

    // we need 5 nodes to avoid sharing various thresholds:
    // v-blocking set size: 2
    // threshold: 4 = 3 + self or 4 others
    pogcvmQuorumSet qSet;
    qSet.threshold = 4;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);
    qSet.validators.push_back(v3NodeID);
    qSet.validators.push_back(v4NodeID);

    uint256 qSetHash = sha256(xdr::xdr_to_opaque(qSet));

    Testpogcvm pogcvm(v0SecretKey.getPublicKey(), qSet);

    pogcvm.storeQuorumSet(std::make_shared<pogcvmQuorumSet>(qSet));
    uint256 qSetHash0 = pogcvm.mpogcvm.getLocalNode()->getQuorumSetHash();

    REQUIRE(xValue < yValue);
    REQUIRE(yValue < zValue);
    REQUIRE(zValue < zzValue);

    CLOG_INFO(pogcvm, "");
    CLOG_INFO(pogcvm, "BEGIN TEST");

    auto recvVBlockingChecks = [&](genEnvelope gen, bool withChecks) {
        pogcvmEnvelope e1 = gen(v1SecretKey);
        pogcvmEnvelope e2 = gen(v2SecretKey);

        pogcvm.bumpTimerOffset();

        // nothing should happen with first message
        size_t i = pogcvm.mEnvs.size();
        pogcvm.receiveEnvelope(e1);
        if (withChecks)
        {
            REQUIRE(pogcvm.mEnvs.size() == i);
        }
        i++;
        pogcvm.receiveEnvelope(e2);
        if (withChecks)
        {
            REQUIRE(pogcvm.mEnvs.size() == i);
        }
    };

    auto recvVBlocking = std::bind(recvVBlockingChecks, _1, true);

    auto recvQuorumChecksEx = [&](genEnvelope gen, bool withChecks,
                                  bool delayedQuorum, bool checkUpcoming) {
        pogcvmEnvelope e1 = gen(v1SecretKey);
        pogcvmEnvelope e2 = gen(v2SecretKey);
        pogcvmEnvelope e3 = gen(v3SecretKey);
        pogcvmEnvelope e4 = gen(v4SecretKey);

        pogcvm.bumpTimerOffset();

        pogcvm.receiveEnvelope(e1);
        pogcvm.receiveEnvelope(e2);
        size_t i = pogcvm.mEnvs.size() + 1;
        pogcvm.receiveEnvelope(e3);
        if (withChecks && !delayedQuorum)
        {
            REQUIRE(pogcvm.mEnvs.size() == i);
        }
        if (checkUpcoming && !delayedQuorum)
        {
            REQUIRE(pogcvm.hasBallotTimerUpcoming());
        }
        // nothing happens with an extra vote (unless we're in delayedQuorum)
        pogcvm.receiveEnvelope(e4);
        if (withChecks && delayedQuorum)
        {
            REQUIRE(pogcvm.mEnvs.size() == i);
        }
        if (checkUpcoming && delayedQuorum)
        {
            REQUIRE(pogcvm.hasBallotTimerUpcoming());
        }
    };
    // doesn't check timers
    auto recvQuorumChecks = std::bind(recvQuorumChecksEx, _1, _2, _3, false);
    // checks enabled, no delayed quorum
    auto recvQuorumEx = std::bind(recvQuorumChecksEx, _1, true, false, _2);
    // checks enabled, no delayed quorum, no check timers
    auto recvQuorum = std::bind(recvQuorumEx, _1, false);

    auto nodesAllPledgeToCommit = [&]() {
        pogcvmBallot b(1, xValue);
        pogcvmEnvelope prepare1 = makePrepare(v1SecretKey, qSetHash, 0, b);
        pogcvmEnvelope prepare2 = makePrepare(v2SecretKey, qSetHash, 0, b);
        pogcvmEnvelope prepare3 = makePrepare(v3SecretKey, qSetHash, 0, b);
        pogcvmEnvelope prepare4 = makePrepare(v4SecretKey, qSetHash, 0, b);

        REQUIRE(pogcvm.bumpState(0, xValue));
        REQUIRE(pogcvm.mEnvs.size() == 1);

        verifyPrepare(pogcvm.mEnvs[0], v0SecretKey, qSetHash0, 0, b);

        pogcvm.receiveEnvelope(prepare1);
        REQUIRE(pogcvm.mEnvs.size() == 1);
        REQUIRE(pogcvm.mHeardFromQuorums[0].size() == 0);

        pogcvm.receiveEnvelope(prepare2);
        REQUIRE(pogcvm.mEnvs.size() == 1);
        REQUIRE(pogcvm.mHeardFromQuorums[0].size() == 0);

        pogcvm.receiveEnvelope(prepare3);
        REQUIRE(pogcvm.mEnvs.size() == 2);
        REQUIRE(pogcvm.mHeardFromQuorums[0].size() == 1);
        REQUIRE(pogcvm.mHeardFromQuorums[0][0] == b);

        // We have a quorum including us

        verifyPrepare(pogcvm.mEnvs[1], v0SecretKey, qSetHash0, 0, b, &b);

        pogcvm.receiveEnvelope(prepare4);
        REQUIRE(pogcvm.mEnvs.size() == 2);

        pogcvmEnvelope prepared1 = makePrepare(v1SecretKey, qSetHash, 0, b, &b);
        pogcvmEnvelope prepared2 = makePrepare(v2SecretKey, qSetHash, 0, b, &b);
        pogcvmEnvelope prepared3 = makePrepare(v3SecretKey, qSetHash, 0, b, &b);
        pogcvmEnvelope prepared4 = makePrepare(v4SecretKey, qSetHash, 0, b, &b);

        pogcvm.receiveEnvelope(prepared4);
        pogcvm.receiveEnvelope(prepared3);
        REQUIRE(pogcvm.mEnvs.size() == 2);

        pogcvm.receiveEnvelope(prepared2);
        REQUIRE(pogcvm.mEnvs.size() == 3);

        // confirms prepared
        verifyPrepare(pogcvm.mEnvs[2], v0SecretKey, qSetHash0, 0, b, &b, b.counter,
                      b.counter);

        // extra statement doesn't do anything
        pogcvm.receiveEnvelope(prepared1);
        REQUIRE(pogcvm.mEnvs.size() == 3);
    };

    SECTION("bumpState x")
    {
        REQUIRE(pogcvm.bumpState(0, xValue));
        REQUIRE(pogcvm.mEnvs.size() == 1);

        pogcvmBallot expectedBallot(1, xValue);

        verifyPrepare(pogcvm.mEnvs[0], v0SecretKey, qSetHash0, 0, expectedBallot);
    }

    SECTION("start <1,x>")
    {
        // no timer is set
        REQUIRE(!pogcvm.hasBallotTimer());

        Value const& aValue = xValue;
        Value const& bValue = zValue;
        Value const& midValue = yValue;
        Value const& bigValue = zzValue;

        pogcvmBallot A1(1, aValue);
        pogcvmBallot B1(1, bValue);
        pogcvmBallot Mid1(1, midValue);
        pogcvmBallot Big1(1, bigValue);

        pogcvmBallot A2 = A1;
        A2.counter++;

        pogcvmBallot A3 = A2;
        A3.counter++;

        pogcvmBallot A4 = A3;
        A4.counter++;

        pogcvmBallot A5 = A4;
        A5.counter++;

        pogcvmBallot AInf(UINT32_MAX, aValue), BInf(UINT32_MAX, bValue);

        pogcvmBallot B2 = B1;
        B2.counter++;

        pogcvmBallot B3 = B2;
        B3.counter++;

        pogcvmBallot Mid2 = Mid1;
        Mid2.counter++;

        pogcvmBallot Big2 = Big1;
        Big2.counter++;

        REQUIRE(pogcvm.bumpState(0, aValue));
        REQUIRE(pogcvm.mEnvs.size() == 1);
        REQUIRE(!pogcvm.hasBallotTimer());

        SECTION("prepared A1")
        {
            recvQuorumEx(makePrepareGen(qSetHash, A1), true);

            REQUIRE(pogcvm.mEnvs.size() == 2);
            verifyPrepare(pogcvm.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &A1);

            SECTION("bump prepared A2")
            {
                // bump to (2,a)

                pogcvm.bumpTimerOffset();
                REQUIRE(pogcvm.bumpState(0, aValue));
                REQUIRE(pogcvm.mEnvs.size() == 3);
                verifyPrepare(pogcvm.mEnvs[2], v0SecretKey, qSetHash0, 0, A2, &A1);
                REQUIRE(!pogcvm.hasBallotTimer());

                recvQuorumEx(makePrepareGen(qSetHash, A2), true);
                REQUIRE(pogcvm.mEnvs.size() == 4);
                verifyPrepare(pogcvm.mEnvs[3], v0SecretKey, qSetHash0, 0, A2, &A2);

                SECTION("Confirm prepared A2")
                {
                    recvQuorum(makePrepareGen(qSetHash, A2, &A2));
                    REQUIRE(pogcvm.mEnvs.size() == 5);
                    verifyPrepare(pogcvm.mEnvs[4], v0SecretKey, qSetHash0, 0, A2,
                                  &A2, 2, 2);
                    REQUIRE(!pogcvm.hasBallotTimerUpcoming());

                    SECTION("Accept commit")
                    {
                        SECTION("Quorum A2")
                        {
                            recvQuorum(makePrepareGen(qSetHash, A2, &A2, 2, 2));
                            REQUIRE(pogcvm.mEnvs.size() == 6);
                            verifyConfirm(pogcvm.mEnvs[5], v0SecretKey, qSetHash0,
                                          0, 2, A2, 2, 2);
                            REQUIRE(!pogcvm.hasBallotTimerUpcoming());

                            SECTION("Quorum prepared A3")
                            {
                                recvVBlocking(
                                    makePrepareGen(qSetHash, A3, &A2, 2, 2));
                                REQUIRE(pogcvm.mEnvs.size() == 7);
                                verifyConfirm(pogcvm.mEnvs[6], v0SecretKey,
                                              qSetHash0, 0, 2, A3, 2, 2);
                                REQUIRE(!pogcvm.hasBallotTimer());

                                recvQuorumEx(
                                    makePrepareGen(qSetHash, A3, &A2, 2, 2),
                                    true);
                                REQUIRE(pogcvm.mEnvs.size() == 8);
                                verifyConfirm(pogcvm.mEnvs[7], v0SecretKey,
                                              qSetHash0, 0, 3, A3, 2, 2);

                                SECTION("Accept more commit A3")
                                {
                                    recvQuorum(makePrepareGen(qSetHash, A3, &A3,
                                                              2, 3));
                                    REQUIRE(pogcvm.mEnvs.size() == 9);
                                    verifyConfirm(pogcvm.mEnvs[8], v0SecretKey,
                                                  qSetHash0, 0, 3, A3, 2, 3);
                                    REQUIRE(!pogcvm.hasBallotTimerUpcoming());

                                    REQUIRE(pogcvm.mExternalizedValues.size() ==
                                            0);

                                    SECTION("Quorum externalize A3")
                                    {
                                        recvQuorum(makeConfirmGen(qSetHash, 3,
                                                                  A3, 2, 3));
                                        REQUIRE(pogcvm.mEnvs.size() == 10);
                                        verifyExternalize(pogcvm.mEnvs[9],
                                                          v0SecretKey,
                                                          qSetHash0, 0, A2, 3);
                                        REQUIRE(!pogcvm.hasBallotTimer());

                                        REQUIRE(
                                            pogcvm.mExternalizedValues.size() ==
                                            1);
                                        REQUIRE(pogcvm.mExternalizedValues[0] ==
                                                aValue);
                                    }
                                }
                                SECTION("v-blocking accept more A3")
                                {
                                    SECTION("Confirm A3")
                                    {
                                        recvVBlocking(makeConfirmGen(
                                            qSetHash, 3, A3, 2, 3));
                                        REQUIRE(pogcvm.mEnvs.size() == 9);
                                        verifyConfirm(pogcvm.mEnvs[8], v0SecretKey,
                                                      qSetHash0, 0, 3, A3, 2,
                                                      3);
                                        REQUIRE(!pogcvm.hasBallotTimerUpcoming());
                                    }
                                    SECTION("Externalize A3")
                                    {
                                        recvVBlocking(makeExternalizeGen(
                                            qSetHash, A2, 3));
                                        REQUIRE(pogcvm.mEnvs.size() == 9);
                                        verifyConfirm(pogcvm.mEnvs[8], v0SecretKey,
                                                      qSetHash0, 0, UINT32_MAX,
                                                      AInf, 2, UINT32_MAX);
                                        REQUIRE(!pogcvm.hasBallotTimer());
                                    }
                                    SECTION("other nodes moved to c=A4 h=A5")
                                    {
                                        SECTION("Confirm A4..5")
                                        {
                                            recvVBlocking(makeConfirmGen(
                                                qSetHash, 3, A5, 4, 5));
                                            REQUIRE(pogcvm.mEnvs.size() == 9);
                                            verifyConfirm(
                                                pogcvm.mEnvs[8], v0SecretKey,
                                                qSetHash0, 0, 3, A5, 4, 5);
                                            REQUIRE(!pogcvm.hasBallotTimer());
                                        }
                                        SECTION("Externalize A4..5")
                                        {
                                            recvVBlocking(makeExternalizeGen(
                                                qSetHash, A4, 5));
                                            REQUIRE(pogcvm.mEnvs.size() == 9);
                                            verifyConfirm(
                                                pogcvm.mEnvs[8], v0SecretKey,
                                                qSetHash0, 0, UINT32_MAX, AInf,
                                                4, UINT32_MAX);
                                            REQUIRE(!pogcvm.hasBallotTimer());
                                        }
                                    }
                                }
                            }
                            SECTION("v-blocking prepared A3")
                            {
                                recvVBlocking(
                                    makePrepareGen(qSetHash, A3, &A3, 2, 2));
                                REQUIRE(pogcvm.mEnvs.size() == 7);
                                verifyConfirm(pogcvm.mEnvs[6], v0SecretKey,
                                              qSetHash0, 0, 3, A3, 2, 2);
                                REQUIRE(!pogcvm.hasBallotTimer());
                            }
                            SECTION("v-blocking prepared A3+B3")
                            {
                                recvVBlocking(makePrepareGen(qSetHash, A3, &B3,
                                                             2, 2, &A3));
                                REQUIRE(pogcvm.mEnvs.size() == 7);
                                verifyConfirm(pogcvm.mEnvs[6], v0SecretKey,
                                              qSetHash0, 0, 3, A3, 2, 2);
                                REQUIRE(!pogcvm.hasBallotTimer());
                            }
                            SECTION("v-blocking confirm A3")
                            {
                                recvVBlocking(
                                    makeConfirmGen(qSetHash, 3, A3, 2, 2));
                                REQUIRE(pogcvm.mEnvs.size() == 7);
                                verifyConfirm(pogcvm.mEnvs[6], v0SecretKey,
                                              qSetHash0, 0, 3, A3, 2, 2);
                                REQUIRE(!pogcvm.hasBallotTimer());
                            }
                            SECTION("Hang - does not switch to B in CONFIRM")
                            {
                                SECTION("Network EXTERNALIZE")
                                {
                                    // externalize messages have a counter at
                                    // infinite
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, B2, 3));
                                    REQUIRE(pogcvm.mEnvs.size() == 7);
                                    verifyConfirm(pogcvm.mEnvs[6], v0SecretKey,
                                                  qSetHash0, 0, 2, AInf, 2, 2);
                                    REQUIRE(!pogcvm.hasBallotTimer());

                                    // stuck
                                    recvQuorumChecks(
                                        makeExternalizeGen(qSetHash, B2, 3),
                                        false, false);
                                    REQUIRE(pogcvm.mEnvs.size() == 7);
                                    REQUIRE(pogcvm.mExternalizedValues.size() ==
                                            0);
                                    // timer scheduled as there is a quorum
                                    // with (2, *)
                                    REQUIRE(pogcvm.hasBallotTimerUpcoming());
                                }
                                SECTION("Network CONFIRMS other ballot")
                                {
                                    SECTION("at same counter")
                                    {
                                        // nothing should happen here, in
                                        // particular, node should not attempt
                                        // to switch 'p'
                                        recvQuorumChecks(
                                            makeConfirmGen(qSetHash, 3, B2, 2,
                                                           3),
                                            false, false);
                                        REQUIRE(pogcvm.mEnvs.size() == 6);
                                        REQUIRE(
                                            pogcvm.mExternalizedValues.size() ==
                                            0);
                                        REQUIRE(!pogcvm.hasBallotTimerUpcoming());
                                    }
                                    SECTION("at a different counter")
                                    {
                                        recvVBlocking(makeConfirmGen(
                                            qSetHash, 3, B3, 3, 3));
                                        REQUIRE(pogcvm.mEnvs.size() == 7);
                                        verifyConfirm(pogcvm.mEnvs[6], v0SecretKey,
                                                      qSetHash0, 0, 2, A3, 2,
                                                      2);
                                        REQUIRE(!pogcvm.hasBallotTimer());

                                        recvQuorumChecks(
                                            makeConfirmGen(qSetHash, 3, B3, 3,
                                                           3),
                                            false, false);
                                        REQUIRE(pogcvm.mEnvs.size() == 7);
                                        REQUIRE(
                                            pogcvm.mExternalizedValues.size() ==
                                            0);
                                        // timer scheduled as there is a quorum
                                        // with (3, *)
                                        REQUIRE(pogcvm.hasBallotTimerUpcoming());
                                    }
                                }
                            }
                        }
                        SECTION("v-blocking")
                        {
                            SECTION("CONFIRM")
                            {
                                SECTION("CONFIRM A2")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 2, A2, 2, 2));
                                    REQUIRE(pogcvm.mEnvs.size() == 6);
                                    verifyConfirm(pogcvm.mEnvs[5], v0SecretKey,
                                                  qSetHash0, 0, 2, A2, 2, 2);
                                    REQUIRE(!pogcvm.hasBallotTimerUpcoming());
                                }
                                SECTION("CONFIRM A3..4")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 4, A4, 3, 4));
                                    REQUIRE(pogcvm.mEnvs.size() == 6);
                                    verifyConfirm(pogcvm.mEnvs[5], v0SecretKey,
                                                  qSetHash0, 0, 4, A4, 3, 4);
                                    REQUIRE(!pogcvm.hasBallotTimer());
                                }
                                SECTION("CONFIRM B2")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 2, B2, 2, 2));
                                    REQUIRE(pogcvm.mEnvs.size() == 6);
                                    verifyConfirm(pogcvm.mEnvs[5], v0SecretKey,
                                                  qSetHash0, 0, 2, B2, 2, 2);
                                    REQUIRE(!pogcvm.hasBallotTimerUpcoming());
                                }
                            }
                            SECTION("EXTERNALIZE")
                            {
                                SECTION("EXTERNALIZE A2")
                                {
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, A2, 2));
                                    REQUIRE(pogcvm.mEnvs.size() == 6);
                                    verifyConfirm(pogcvm.mEnvs[5], v0SecretKey,
                                                  qSetHash0, 0, UINT32_MAX,
                                                  AInf, 2, UINT32_MAX);
                                    REQUIRE(!pogcvm.hasBallotTimer());
                                }
                                SECTION("EXTERNALIZE B2")
                                {
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, B2, 2));
                                    REQUIRE(pogcvm.mEnvs.size() == 6);
                                    verifyConfirm(pogcvm.mEnvs[5], v0SecretKey,
                                                  qSetHash0, 0, UINT32_MAX,
                                                  BInf, 2, UINT32_MAX);
                                    REQUIRE(!pogcvm.hasBallotTimer());
                                }
                            }
                        }
                    }
                    SECTION("get conflicting prepared B")
                    {
                        SECTION("same counter")
                        {
                            recvVBlocking(makePrepareGen(qSetHash, B2, &B2));
                            REQUIRE(pogcvm.mEnvs.size() == 6);
                            verifyPrepare(pogcvm.mEnvs[5], v0SecretKey, qSetHash0,
                                          0, A2, &B2, 0, 2, &A2);
                            REQUIRE(!pogcvm.hasBallotTimerUpcoming());

                            recvQuorum(makePrepareGen(qSetHash, B2, &B2, 2, 2));
                            REQUIRE(pogcvm.mEnvs.size() == 7);
                            verifyConfirm(pogcvm.mEnvs[6], v0SecretKey, qSetHash0,
                                          0, 2, B2, 2, 2);
                            REQUIRE(!pogcvm.hasBallotTimerUpcoming());
                        }
                        SECTION("higher counter")
                        {
                            recvVBlocking(
                                makePrepareGen(qSetHash, B3, &B2, 2, 2));
                            REQUIRE(pogcvm.mEnvs.size() == 6);
                            verifyPrepare(pogcvm.mEnvs[5], v0SecretKey, qSetHash0,
                                          0, A3, &B2, 0, 2, &A2);
                            REQUIRE(!pogcvm.hasBallotTimer());

                            recvQuorumChecksEx(
                                makePrepareGen(qSetHash, B3, &B2, 2, 2), true,
                                true, true);
                            REQUIRE(pogcvm.mEnvs.size() == 7);
                            verifyConfirm(pogcvm.mEnvs[6], v0SecretKey, qSetHash0,
                                          0, 3, B3, 2, 2);
                        }
                        SECTION("higher counter mixed")
                        {
                            recvVBlocking(
                                makePrepareGen(qSetHash, A3, &B3, 0, 2, &A2));
                            REQUIRE(pogcvm.mEnvs.size() == 6);
                            // h still A2
                            // v-blocking
                            //     prepared B3 -> p = B3, p'=A2 (1)
                            //     counter 3, b = A3 (9) (same value than h)
                            // c = 0 (1)
                            verifyPrepare(pogcvm.mEnvs[5], v0SecretKey, qSetHash0,
                                          0, A3, &B3, 0, 2, &A2);
                            recvQuorumEx(
                                makePrepareGen(qSetHash, A3, &B3, 0, 2, &A2),
                                true);
                            // p=B3, p'=A3 (1)
                            // computed_h = B3
                            // b = computed_h = B3 (8)
                            // h = computed_h = B3 (2)
                            // c = h = B3 (3)
                            REQUIRE(pogcvm.mEnvs.size() == 7);
                            verifyPrepare(pogcvm.mEnvs[6], v0SecretKey, qSetHash0,
                                          0, B3, &B3, 3, 3, &A3);
                        }
                    }
                }
                SECTION("Confirm prepared mixed")
                {
                    // a few nodes prepared B2
                    recvVBlocking(makePrepareGen(qSetHash, B2, &B2, 0, 0, &A2));
                    REQUIRE(pogcvm.mEnvs.size() == 5);
                    verifyPrepare(pogcvm.mEnvs[4], v0SecretKey, qSetHash0, 0, A2,
                                  &B2, 0, 0, &A2);
                    REQUIRE(!pogcvm.hasBallotTimerUpcoming());

                    SECTION("mixed A2")
                    {
                        // causes h=A2
                        // but c = 0, as p >!~ h
                        pogcvm.bumpTimerOffset();
                        pogcvm.receiveEnvelope(
                            makePrepare(v3SecretKey, qSetHash, 0, A2, &A2));

                        REQUIRE(pogcvm.mEnvs.size() == 6);
                        verifyPrepare(pogcvm.mEnvs[5], v0SecretKey, qSetHash0, 0,
                                      A2, &B2, 0, 2, &A2);
                        REQUIRE(!pogcvm.hasBallotTimerUpcoming());

                        pogcvm.bumpTimerOffset();
                        pogcvm.receiveEnvelope(
                            makePrepare(v4SecretKey, qSetHash, 0, A2, &A2));

                        REQUIRE(pogcvm.mEnvs.size() == 6);
                        REQUIRE(!pogcvm.hasBallotTimerUpcoming());
                    }
                    SECTION("mixed B2")
                    {
                        // causes h=B2, c=B2
                        pogcvm.bumpTimerOffset();
                        pogcvm.receiveEnvelope(
                            makePrepare(v3SecretKey, qSetHash, 0, B2, &B2));

                        REQUIRE(pogcvm.mEnvs.size() == 6);
                        verifyPrepare(pogcvm.mEnvs[5], v0SecretKey, qSetHash0, 0,
                                      B2, &B2, 2, 2, &A2);
                        REQUIRE(!pogcvm.hasBallotTimerUpcoming());

                        pogcvm.bumpTimerOffset();
                        pogcvm.receiveEnvelope(
                            makePrepare(v4SecretKey, qSetHash, 0, B2, &B2));

                        REQUIRE(pogcvm.mEnvs.size() == 6);
                        REQUIRE(!pogcvm.hasBallotTimerUpcoming());
                    }
                }
            }
            SECTION("switch prepared B1 from A1")
            {
                // (p,p') = (B1, A1) [ from (A1, null) ]
                recvVBlocking(makePrepareGen(qSetHash, B1, &B1));
                REQUIRE(pogcvm.mEnvs.size() == 3);
                verifyPrepare(pogcvm.mEnvs[2], v0SecretKey, qSetHash0, 0, A1, &B1,
                              0, 0, &A1);
                REQUIRE(!pogcvm.hasBallotTimerUpcoming());

                // v-blocking with n=2 -> bump n
                recvVBlocking(makePrepareGen(qSetHash, B2));
                REQUIRE(pogcvm.mEnvs.size() == 4);
                verifyPrepare(pogcvm.mEnvs[3], v0SecretKey, qSetHash0, 0, A2, &B1,
                              0, 0, &A1);

                // move to (p,p') = (B2, A1) [update p from B1 -> B2]
                recvVBlocking(makePrepareGen(qSetHash, B2, &B2));
                REQUIRE(pogcvm.mEnvs.size() == 5);
                verifyPrepare(pogcvm.mEnvs[4], v0SecretKey, qSetHash0, 0, A2, &B2,
                              0, 0, &A1);
                REQUIRE(
                    !pogcvm.hasBallotTimer()); // no quorum (other nodes on (A,1))

                SECTION("v-blocking switches to previous value of p")
                {
                    // v-blocking with n=3 -> bump n
                    recvVBlocking(makePrepareGen(qSetHash, B3));
                    REQUIRE(pogcvm.mEnvs.size() == 6);
                    verifyPrepare(pogcvm.mEnvs[5], v0SecretKey, qSetHash0, 0, A3,
                                  &B2, 0, 0, &A1);
                    REQUIRE(!pogcvm.hasBallotTimer()); // no quorum (other nodes on
                                                    // (A,1))

                    // vBlocking set says "B1" is prepared - but we already have
                    // p=B2
                    recvVBlockingChecks(makePrepareGen(qSetHash, B3, &B1),
                                        false);
                    REQUIRE(pogcvm.mEnvs.size() == 6);
                    REQUIRE(!pogcvm.hasBallotTimer());
                }
                SECTION("switch p' to Mid2")
                {
                    // (p,p') = (B2, Mid2)
                    recvVBlocking(
                        makePrepareGen(qSetHash, B2, &B2, 0, 0, &Mid2));
                    REQUIRE(pogcvm.mEnvs.size() == 6);
                    verifyPrepare(pogcvm.mEnvs[5], v0SecretKey, qSetHash0, 0, A2,
                                  &B2, 0, 0, &Mid2);
                    REQUIRE(!pogcvm.hasBallotTimer());
                }
                SECTION("switch again Big2")
                {
                    // both p and p' get updated
                    // (p,p') = (Big2, B2)
                    recvVBlocking(
                        makePrepareGen(qSetHash, B2, &Big2, 0, 0, &B2));
                    REQUIRE(pogcvm.mEnvs.size() == 6);
                    verifyPrepare(pogcvm.mEnvs[5], v0SecretKey, qSetHash0, 0, A2,
                                  &Big2, 0, 0, &B2);
                    REQUIRE(!pogcvm.hasBallotTimer());
                }
            }
            SECTION("switch prepare B1")
            {
                recvQuorumChecks(makePrepareGen(qSetHash, B1), true, true);
                REQUIRE(pogcvm.mEnvs.size() == 3);
                verifyPrepare(pogcvm.mEnvs[2], v0SecretKey, qSetHash0, 0, A1, &B1,
                              0, 0, &A1);
                REQUIRE(!pogcvm.hasBallotTimerUpcoming());
            }
            SECTION("prepare higher counter (v-blocking)")
            {
                recvVBlocking(makePrepareGen(qSetHash, B2));
                REQUIRE(pogcvm.mEnvs.size() == 3);
                verifyPrepare(pogcvm.mEnvs[2], v0SecretKey, qSetHash0, 0, A2, &A1);
                REQUIRE(!pogcvm.hasBallotTimer());

                // more timeout from vBlocking set
                recvVBlocking(makePrepareGen(qSetHash, B3));
                REQUIRE(pogcvm.mEnvs.size() == 4);
                verifyPrepare(pogcvm.mEnvs[3], v0SecretKey, qSetHash0, 0, A3, &A1);
                REQUIRE(!pogcvm.hasBallotTimer());
            }
        }
        SECTION("prepared B (v-blocking)")
        {
            recvVBlocking(makePrepareGen(qSetHash, B1, &B1));
            REQUIRE(pogcvm.mEnvs.size() == 2);
            verifyPrepare(pogcvm.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &B1);
            REQUIRE(!pogcvm.hasBallotTimer());
        }
        SECTION("prepare B (quorum)")
        {
            recvQuorumChecksEx(makePrepareGen(qSetHash, B1), true, true, true);
            REQUIRE(pogcvm.mEnvs.size() == 2);
            verifyPrepare(pogcvm.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &B1);
        }
        SECTION("confirm (v-blocking)")
        {
            SECTION("via CONFIRM")
            {
                pogcvm.bumpTimerOffset();
                pogcvm.receiveEnvelope(
                    makeConfirm(v1SecretKey, qSetHash, 0, 3, A3, 3, 3));
                pogcvm.receiveEnvelope(
                    makeConfirm(v2SecretKey, qSetHash, 0, 4, A4, 2, 4));
                REQUIRE(pogcvm.mEnvs.size() == 2);
                verifyConfirm(pogcvm.mEnvs[1], v0SecretKey, qSetHash0, 0, 3, A3, 3,
                              3);
                REQUIRE(!pogcvm.hasBallotTimer());
            }
            SECTION("via EXTERNALIZE")
            {
                pogcvm.receiveEnvelope(
                    makeExternalize(v1SecretKey, qSetHash, 0, A2, 4));
                pogcvm.receiveEnvelope(
                    makeExternalize(v2SecretKey, qSetHash, 0, A3, 5));
                REQUIRE(pogcvm.mEnvs.size() == 2);
                verifyConfirm(pogcvm.mEnvs[1], v0SecretKey, qSetHash0, 0,
                              UINT32_MAX, AInf, 3, UINT32_MAX);
                REQUIRE(!pogcvm.hasBallotTimer());
            }
        }
    }

    // this is the same test suite than "start <1,x>" with the exception that
    // some transitions are not possible as x < z - so instead we verify that
    // nothing happens
    SECTION("start <1,z>")
    {
        // no timer is set
        REQUIRE(!pogcvm.hasBallotTimer());

        Value const& aValue = zValue;
        Value const& bValue = xValue;

        pogcvmBallot A1(1, aValue);
        pogcvmBallot B1(1, bValue);

        pogcvmBallot A2 = A1;
        A2.counter++;

        pogcvmBallot A3 = A2;
        A3.counter++;

        pogcvmBallot A4 = A3;
        A4.counter++;

        pogcvmBallot A5 = A4;
        A5.counter++;

        pogcvmBallot AInf(UINT32_MAX, aValue), BInf(UINT32_MAX, bValue);

        pogcvmBallot B2 = B1;
        B2.counter++;

        pogcvmBallot B3 = B2;
        B3.counter++;

        pogcvmBallot B4 = B3;
        B4.counter++;

        REQUIRE(pogcvm.bumpState(0, aValue));
        REQUIRE(pogcvm.mEnvs.size() == 1);
        REQUIRE(!pogcvm.hasBallotTimer());

        SECTION("prepared A1")
        {
            recvQuorumEx(makePrepareGen(qSetHash, A1), true);

            REQUIRE(pogcvm.mEnvs.size() == 2);
            verifyPrepare(pogcvm.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &A1);

            SECTION("bump prepared A2")
            {
                // bump to (2,a)

                pogcvm.bumpTimerOffset();
                REQUIRE(pogcvm.bumpState(0, aValue));
                REQUIRE(pogcvm.mEnvs.size() == 3);
                verifyPrepare(pogcvm.mEnvs[2], v0SecretKey, qSetHash0, 0, A2, &A1);
                REQUIRE(!pogcvm.hasBallotTimer());

                recvQuorumEx(makePrepareGen(qSetHash, A2), true);
                REQUIRE(pogcvm.mEnvs.size() == 4);
                verifyPrepare(pogcvm.mEnvs[3], v0SecretKey, qSetHash0, 0, A2, &A2);

                SECTION("Confirm prepared A2")
                {
                    recvQuorum(makePrepareGen(qSetHash, A2, &A2));
                    REQUIRE(pogcvm.mEnvs.size() == 5);
                    verifyPrepare(pogcvm.mEnvs[4], v0SecretKey, qSetHash0, 0, A2,
                                  &A2, 2, 2);
                    REQUIRE(!pogcvm.hasBallotTimerUpcoming());

                    SECTION("Accept commit")
                    {
                        SECTION("Quorum A2")
                        {
                            recvQuorum(makePrepareGen(qSetHash, A2, &A2, 2, 2));
                            REQUIRE(pogcvm.mEnvs.size() == 6);
                            verifyConfirm(pogcvm.mEnvs[5], v0SecretKey, qSetHash0,
                                          0, 2, A2, 2, 2);
                            REQUIRE(!pogcvm.hasBallotTimerUpcoming());

                            SECTION("Quorum prepared A3")
                            {
                                recvVBlocking(
                                    makePrepareGen(qSetHash, A3, &A2, 2, 2));
                                REQUIRE(pogcvm.mEnvs.size() == 7);
                                verifyConfirm(pogcvm.mEnvs[6], v0SecretKey,
                                              qSetHash0, 0, 2, A3, 2, 2);
                                REQUIRE(!pogcvm.hasBallotTimer());

                                recvQuorumEx(
                                    makePrepareGen(qSetHash, A3, &A2, 2, 2),
                                    true);
                                REQUIRE(pogcvm.mEnvs.size() == 8);
                                verifyConfirm(pogcvm.mEnvs[7], v0SecretKey,
                                              qSetHash0, 0, 3, A3, 2, 2);

                                SECTION("Accept more commit A3")
                                {
                                    recvQuorum(makePrepareGen(qSetHash, A3, &A3,
                                                              2, 3));
                                    REQUIRE(pogcvm.mEnvs.size() == 9);
                                    verifyConfirm(pogcvm.mEnvs[8], v0SecretKey,
                                                  qSetHash0, 0, 3, A3, 2, 3);
                                    REQUIRE(!pogcvm.hasBallotTimerUpcoming());

                                    REQUIRE(pogcvm.mExternalizedValues.size() ==
                                            0);

                                    SECTION("Quorum externalize A3")
                                    {
                                        recvQuorum(makeConfirmGen(qSetHash, 3,
                                                                  A3, 2, 3));
                                        REQUIRE(pogcvm.mEnvs.size() == 10);
                                        verifyExternalize(pogcvm.mEnvs[9],
                                                          v0SecretKey,
                                                          qSetHash0, 0, A2, 3);
                                        REQUIRE(!pogcvm.hasBallotTimer());

                                        REQUIRE(
                                            pogcvm.mExternalizedValues.size() ==
                                            1);
                                        REQUIRE(pogcvm.mExternalizedValues[0] ==
                                                aValue);
                                    }
                                }
                                SECTION("v-blocking accept more A3")
                                {
                                    SECTION("Confirm A3")
                                    {
                                        recvVBlocking(makeConfirmGen(
                                            qSetHash, 3, A3, 2, 3));
                                        REQUIRE(pogcvm.mEnvs.size() == 9);
                                        verifyConfirm(pogcvm.mEnvs[8], v0SecretKey,
                                                      qSetHash0, 0, 3, A3, 2,
                                                      3);
                                        REQUIRE(!pogcvm.hasBallotTimerUpcoming());
                                    }
                                    SECTION("Externalize A3")
                                    {
                                        recvVBlocking(makeExternalizeGen(
                                            qSetHash, A2, 3));
                                        REQUIRE(pogcvm.mEnvs.size() == 9);
                                        verifyConfirm(pogcvm.mEnvs[8], v0SecretKey,
                                                      qSetHash0, 0, UINT32_MAX,
                                                      AInf, 2, UINT32_MAX);
                                        REQUIRE(!pogcvm.hasBallotTimer());
                                    }
                                    SECTION("other nodes moved to c=A4 h=A5")
                                    {
                                        SECTION("Confirm A4..5")
                                        {
                                            recvVBlocking(makeConfirmGen(
                                                qSetHash, 3, A5, 4, 5));
                                            REQUIRE(pogcvm.mEnvs.size() == 9);
                                            verifyConfirm(
                                                pogcvm.mEnvs[8], v0SecretKey,
                                                qSetHash0, 0, 3, A5, 4, 5);
                                            REQUIRE(!pogcvm.hasBallotTimer());
                                        }
                                        SECTION("Externalize A4..5")
                                        {
                                            recvVBlocking(makeExternalizeGen(
                                                qSetHash, A4, 5));
                                            REQUIRE(pogcvm.mEnvs.size() == 9);
                                            verifyConfirm(
                                                pogcvm.mEnvs[8], v0SecretKey,
                                                qSetHash0, 0, UINT32_MAX, AInf,
                                                4, UINT32_MAX);
                                            REQUIRE(!pogcvm.hasBallotTimer());
                                        }
                                    }
                                }
                            }
                            SECTION("v-blocking prepared A3")
                            {
                                recvVBlocking(
                                    makePrepareGen(qSetHash, A3, &A3, 2, 2));
                                REQUIRE(pogcvm.mEnvs.size() == 7);
                                verifyConfirm(pogcvm.mEnvs[6], v0SecretKey,
                                              qSetHash0, 0, 3, A3, 2, 2);
                                REQUIRE(!pogcvm.hasBallotTimer());
                            }
                            SECTION("v-blocking prepared A3+B3")
                            {
                                recvVBlocking(makePrepareGen(qSetHash, A3, &A3,
                                                             2, 2, &B3));
                                REQUIRE(pogcvm.mEnvs.size() == 7);
                                verifyConfirm(pogcvm.mEnvs[6], v0SecretKey,
                                              qSetHash0, 0, 3, A3, 2, 2);
                                REQUIRE(!pogcvm.hasBallotTimer());
                            }
                            SECTION("v-blocking confirm A3")
                            {
                                recvVBlocking(
                                    makeConfirmGen(qSetHash, 3, A3, 2, 2));
                                REQUIRE(pogcvm.mEnvs.size() == 7);
                                verifyConfirm(pogcvm.mEnvs[6], v0SecretKey,
                                              qSetHash0, 0, 3, A3, 2, 2);
                                REQUIRE(!pogcvm.hasBallotTimer());
                            }
                            SECTION("Hang - does not switch to B in CONFIRM")
                            {
                                SECTION("Network EXTERNALIZE")
                                {
                                    // externalize messages have a counter at
                                    // infinite
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, B2, 3));
                                    REQUIRE(pogcvm.mEnvs.size() == 7);
                                    verifyConfirm(pogcvm.mEnvs[6], v0SecretKey,
                                                  qSetHash0, 0, 2, AInf, 2, 2);
                                    REQUIRE(!pogcvm.hasBallotTimer());

                                    // stuck
                                    recvQuorumChecks(
                                        makeExternalizeGen(qSetHash, B2, 3),
                                        false, false);
                                    REQUIRE(pogcvm.mEnvs.size() == 7);
                                    REQUIRE(pogcvm.mExternalizedValues.size() ==
                                            0);
                                    // timer scheduled as there is a quorum
                                    // with (inf, *)
                                    REQUIRE(pogcvm.hasBallotTimerUpcoming());
                                }
                                SECTION("Network CONFIRMS other ballot")
                                {
                                    SECTION("at same counter")
                                    {
                                        // nothing should happen here, in
                                        // particular, node should not attempt
                                        // to switch 'p'
                                        recvQuorumChecks(
                                            makeConfirmGen(qSetHash, 3, B2, 2,
                                                           3),
                                            false, false);
                                        REQUIRE(pogcvm.mEnvs.size() == 6);
                                        REQUIRE(
                                            pogcvm.mExternalizedValues.size() ==
                                            0);
                                        REQUIRE(!pogcvm.hasBallotTimerUpcoming());
                                    }
                                    SECTION("at a different counter")
                                    {
                                        recvVBlocking(makeConfirmGen(
                                            qSetHash, 3, B3, 3, 3));
                                        REQUIRE(pogcvm.mEnvs.size() == 7);
                                        verifyConfirm(pogcvm.mEnvs[6], v0SecretKey,
                                                      qSetHash0, 0, 2, A3, 2,
                                                      2);
                                        REQUIRE(!pogcvm.hasBallotTimer());

                                        recvQuorumChecks(
                                            makeConfirmGen(qSetHash, 3, B3, 3,
                                                           3),
                                            false, false);
                                        REQUIRE(pogcvm.mEnvs.size() == 7);
                                        REQUIRE(
                                            pogcvm.mExternalizedValues.size() ==
                                            0);
                                        // timer scheduled as there is a quorum
                                        // with (3, *)
                                        REQUIRE(pogcvm.hasBallotTimerUpcoming());
                                    }
                                }
                            }
                        }
                        SECTION("v-blocking")
                        {
                            SECTION("CONFIRM")
                            {
                                SECTION("CONFIRM A2")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 2, A2, 2, 2));
                                    REQUIRE(pogcvm.mEnvs.size() == 6);
                                    verifyConfirm(pogcvm.mEnvs[5], v0SecretKey,
                                                  qSetHash0, 0, 2, A2, 2, 2);
                                    REQUIRE(!pogcvm.hasBallotTimerUpcoming());
                                }
                                SECTION("CONFIRM A3..4")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 4, A4, 3, 4));
                                    REQUIRE(pogcvm.mEnvs.size() == 6);
                                    verifyConfirm(pogcvm.mEnvs[5], v0SecretKey,
                                                  qSetHash0, 0, 4, A4, 3, 4);
                                    REQUIRE(!pogcvm.hasBallotTimer());
                                }
                                SECTION("CONFIRM B2")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 2, B2, 2, 2));
                                    REQUIRE(pogcvm.mEnvs.size() == 6);
                                    verifyConfirm(pogcvm.mEnvs[5], v0SecretKey,
                                                  qSetHash0, 0, 2, B2, 2, 2);
                                    REQUIRE(!pogcvm.hasBallotTimerUpcoming());
                                }
                            }
                            SECTION("EXTERNALIZE")
                            {
                                SECTION("EXTERNALIZE A2")
                                {
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, A2, 2));
                                    REQUIRE(pogcvm.mEnvs.size() == 6);
                                    verifyConfirm(pogcvm.mEnvs[5], v0SecretKey,
                                                  qSetHash0, 0, UINT32_MAX,
                                                  AInf, 2, UINT32_MAX);
                                    REQUIRE(!pogcvm.hasBallotTimer());
                                }
                                SECTION("EXTERNALIZE B2")
                                {
                                    // can switch to B2 with externalize (higher
                                    // counter)
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, B2, 2));
                                    REQUIRE(pogcvm.mEnvs.size() == 6);
                                    verifyConfirm(pogcvm.mEnvs[5], v0SecretKey,
                                                  qSetHash0, 0, UINT32_MAX,
                                                  BInf, 2, UINT32_MAX);
                                    REQUIRE(!pogcvm.hasBallotTimer());
                                }
                            }
                        }
                    }
                    SECTION("get conflicting prepared B")
                    {
                        SECTION("same counter")
                        {
                            // messages are ignored as B2 < A2
                            recvQuorumChecks(makePrepareGen(qSetHash, B2, &B2),
                                             false, false);
                            REQUIRE(pogcvm.mEnvs.size() == 5);
                            REQUIRE(!pogcvm.hasBallotTimerUpcoming());
                        }
                        SECTION("higher counter")
                        {
                            recvVBlocking(
                                makePrepareGen(qSetHash, B3, &B2, 2, 2));
                            REQUIRE(pogcvm.mEnvs.size() == 6);
                            // A2 > B2 -> p = A2, p'=B2
                            verifyPrepare(pogcvm.mEnvs[5], v0SecretKey, qSetHash0,
                                          0, A3, &A2, 2, 2, &B2);
                            REQUIRE(!pogcvm.hasBallotTimer());

                            // node is trying to commit A2=<2,y> but rest
                            // of its quorum is trying to commit B2
                            // we end up with a delayed quorum
                            recvQuorumChecksEx(
                                makePrepareGen(qSetHash, B3, &B2, 2, 2), true,
                                true, true);
                            REQUIRE(pogcvm.mEnvs.size() == 7);
                            verifyConfirm(pogcvm.mEnvs[6], v0SecretKey, qSetHash0,
                                          0, 3, B3, 2, 2);
                        }
                        SECTION("higher counter mixed")
                        {
                            recvVBlocking(
                                makePrepareGen(qSetHash, A3, &B3, 0, 2, &A2));
                            REQUIRE(pogcvm.mEnvs.size() == 6);
                            // h still A2
                            // v-blocking
                            //     prepared B3 -> p = B3, p'=A2 (1)
                            //     counter 3, b = A3 (9) (same value than h)
                            // c = 0 (1)
                            verifyPrepare(pogcvm.mEnvs[5], v0SecretKey, qSetHash0,
                                          0, A3, &B3, 0, 2, &A2);
                            recvQuorumEx(
                                makePrepareGen(qSetHash, A3, &B3, 0, 2, &A2),
                                true);
                            // p=A3, p'=B3 (1)
                            // computed_h = B3 (2) z = B - cannot update b
                            REQUIRE(pogcvm.mEnvs.size() == 7);
                            verifyPrepare(pogcvm.mEnvs[6], v0SecretKey, qSetHash0,
                                          0, A3, &A3, 0, 2, &B3);
                            // timeout, bump to B4
                            REQUIRE(pogcvm.hasBallotTimerUpcoming());
                            auto cb = pogcvm.getBallotProtocolTimer().mCallback;
                            cb();
                            // computed_h = B3
                            // h = B3 (2)
                            // c = 0
                            REQUIRE(pogcvm.mEnvs.size() == 8);
                            verifyPrepare(pogcvm.mEnvs[7], v0SecretKey, qSetHash0,
                                          0, B4, &A3, 0, 3, &B3);
                        }
                    }
                }
                SECTION("Confirm prepared mixed")
                {
                    // a few nodes prepared B2
                    recvVBlocking(makePrepareGen(qSetHash, A2, &A2, 0, 0, &B2));
                    REQUIRE(pogcvm.mEnvs.size() == 5);
                    verifyPrepare(pogcvm.mEnvs[4], v0SecretKey, qSetHash0, 0, A2,
                                  &A2, 0, 0, &B2);
                    REQUIRE(!pogcvm.hasBallotTimerUpcoming());

                    SECTION("mixed A2")
                    {
                        // causes h=A2, c=A2
                        pogcvm.bumpTimerOffset();
                        pogcvm.receiveEnvelope(
                            makePrepare(v3SecretKey, qSetHash, 0, A2, &A2));

                        REQUIRE(pogcvm.mEnvs.size() == 6);
                        verifyPrepare(pogcvm.mEnvs[5], v0SecretKey, qSetHash0, 0,
                                      A2, &A2, 2, 2, &B2);
                        REQUIRE(!pogcvm.hasBallotTimerUpcoming());

                        pogcvm.bumpTimerOffset();
                        pogcvm.receiveEnvelope(
                            makePrepare(v4SecretKey, qSetHash, 0, A2, &A2));

                        REQUIRE(pogcvm.mEnvs.size() == 6);
                        REQUIRE(!pogcvm.hasBallotTimerUpcoming());
                    }
                    SECTION("mixed B2")
                    {
                        // causes computed_h=B2 ~ not set as h ~!= b
                        // -> noop
                        pogcvm.bumpTimerOffset();
                        pogcvm.receiveEnvelope(
                            makePrepare(v3SecretKey, qSetHash, 0, A2, &B2));

                        REQUIRE(pogcvm.mEnvs.size() == 5);
                        REQUIRE(!pogcvm.hasBallotTimerUpcoming());

                        pogcvm.bumpTimerOffset();
                        pogcvm.receiveEnvelope(
                            makePrepare(v4SecretKey, qSetHash, 0, B2, &B2));

                        REQUIRE(pogcvm.mEnvs.size() == 5);
                        REQUIRE(!pogcvm.hasBallotTimerUpcoming());
                    }
                }
            }
            SECTION("switch prepared B1 from A1")
            {
                // can't switch to B1
                recvQuorumChecks(makePrepareGen(qSetHash, B1, &B1), false,
                                 false);
                REQUIRE(pogcvm.mEnvs.size() == 2);
                REQUIRE(!pogcvm.hasBallotTimerUpcoming());
            }
            SECTION("switch prepare B1")
            {
                // doesn't switch as B1 < A1
                recvQuorumChecks(makePrepareGen(qSetHash, B1), false, false);
                REQUIRE(pogcvm.mEnvs.size() == 2);
                REQUIRE(!pogcvm.hasBallotTimerUpcoming());
            }
            SECTION("prepare higher counter (v-blocking)")
            {
                recvVBlocking(makePrepareGen(qSetHash, B2));
                REQUIRE(pogcvm.mEnvs.size() == 3);
                verifyPrepare(pogcvm.mEnvs[2], v0SecretKey, qSetHash0, 0, A2, &A1);
                REQUIRE(!pogcvm.hasBallotTimer());

                // more timeout from vBlocking set
                recvVBlocking(makePrepareGen(qSetHash, B3));
                REQUIRE(pogcvm.mEnvs.size() == 4);
                verifyPrepare(pogcvm.mEnvs[3], v0SecretKey, qSetHash0, 0, A3, &A1);
                REQUIRE(!pogcvm.hasBallotTimer());
            }
        }
        SECTION("prepared B (v-blocking)")
        {
            recvVBlocking(makePrepareGen(qSetHash, B1, &B1));
            REQUIRE(pogcvm.mEnvs.size() == 2);
            verifyPrepare(pogcvm.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &B1);
            REQUIRE(!pogcvm.hasBallotTimer());
        }
        SECTION("prepare B (quorum)")
        {
            recvQuorumChecksEx(makePrepareGen(qSetHash, B1), true, true, true);
            REQUIRE(pogcvm.mEnvs.size() == 2);
            verifyPrepare(pogcvm.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &B1);
        }
        SECTION("confirm (v-blocking)")
        {
            SECTION("via CONFIRM")
            {
                pogcvm.bumpTimerOffset();
                pogcvm.receiveEnvelope(
                    makeConfirm(v1SecretKey, qSetHash, 0, 3, A3, 3, 3));
                pogcvm.receiveEnvelope(
                    makeConfirm(v2SecretKey, qSetHash, 0, 4, A4, 2, 4));
                REQUIRE(pogcvm.mEnvs.size() == 2);
                verifyConfirm(pogcvm.mEnvs[1], v0SecretKey, qSetHash0, 0, 3, A3, 3,
                              3);
                REQUIRE(!pogcvm.hasBallotTimer());
            }
            SECTION("via EXTERNALIZE")
            {
                pogcvm.receiveEnvelope(
                    makeExternalize(v1SecretKey, qSetHash, 0, A2, 4));
                pogcvm.receiveEnvelope(
                    makeExternalize(v2SecretKey, qSetHash, 0, A3, 5));
                REQUIRE(pogcvm.mEnvs.size() == 2);
                verifyConfirm(pogcvm.mEnvs[1], v0SecretKey, qSetHash0, 0,
                              UINT32_MAX, AInf, 3, UINT32_MAX);
                REQUIRE(!pogcvm.hasBallotTimer());
            }
        }
    }

    // this is the same test suite than "start <1,x>" but only keeping
    // the transitions that are observable when starting from empty
    SECTION("start from pristine")
    {
        Value const& aValue = xValue;
        Value const& bValue = zValue;

        pogcvmBallot A1(1, aValue);
        pogcvmBallot B1(1, bValue);

        pogcvmBallot A2 = A1;
        A2.counter++;

        pogcvmBallot A3 = A2;
        A3.counter++;

        pogcvmBallot A4 = A3;
        A4.counter++;

        pogcvmBallot A5 = A4;
        A5.counter++;

        pogcvmBallot AInf(UINT32_MAX, aValue), BInf(UINT32_MAX, bValue);

        pogcvmBallot B2 = B1;
        B2.counter++;

        pogcvmBallot B3 = B2;
        B3.counter++;

        REQUIRE(pogcvm.mEnvs.size() == 0);

        SECTION("prepared A1")
        {
            recvQuorumChecks(makePrepareGen(qSetHash, A1), false, false);
            REQUIRE(pogcvm.mEnvs.size() == 0);

            SECTION("bump prepared A2")
            {
                SECTION("Confirm prepared A2")
                {
                    recvVBlockingChecks(makePrepareGen(qSetHash, A2, &A2),
                                        false);
                    REQUIRE(pogcvm.mEnvs.size() == 0);

                    SECTION("Quorum A2")
                    {
                        recvVBlockingChecks(makePrepareGen(qSetHash, A2, &A2),
                                            false);
                        REQUIRE(pogcvm.mEnvs.size() == 0);
                        recvQuorum(makePrepareGen(qSetHash, A2, &A2));
                        REQUIRE(pogcvm.mEnvs.size() == 1);
                        verifyPrepare(pogcvm.mEnvs[0], v0SecretKey, qSetHash0, 0,
                                      A2, &A2, 1, 2);
                    }
                    SECTION("Quorum B2")
                    {
                        recvVBlockingChecks(makePrepareGen(qSetHash, B2, &B2),
                                            false);
                        REQUIRE(pogcvm.mEnvs.size() == 0);
                        recvQuorum(makePrepareGen(qSetHash, B2, &B2));
                        REQUIRE(pogcvm.mEnvs.size() == 1);
                        verifyPrepare(pogcvm.mEnvs[0], v0SecretKey, qSetHash0, 0,
                                      B2, &B2, 2, 2, &A2);
                    }
                    SECTION("Accept commit")
                    {
                        SECTION("Quorum A2")
                        {
                            recvQuorum(makePrepareGen(qSetHash, A2, &A2, 2, 2));
                            REQUIRE(pogcvm.mEnvs.size() == 1);
                            verifyConfirm(pogcvm.mEnvs[0], v0SecretKey, qSetHash0,
                                          0, 2, A2, 2, 2);
                        }
                        SECTION("Quorum B2")
                        {
                            recvQuorum(makePrepareGen(qSetHash, B2, &B2, 2, 2));
                            REQUIRE(pogcvm.mEnvs.size() == 1);
                            verifyConfirm(pogcvm.mEnvs[0], v0SecretKey, qSetHash0,
                                          0, 2, B2, 2, 2);
                        }
                        SECTION("v-blocking")
                        {
                            SECTION("CONFIRM")
                            {
                                SECTION("CONFIRM A2")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 2, A2, 2, 2));
                                    REQUIRE(pogcvm.mEnvs.size() == 1);
                                    verifyConfirm(pogcvm.mEnvs[0], v0SecretKey,
                                                  qSetHash0, 0, 2, A2, 2, 2);
                                }
                                SECTION("CONFIRM A3..4")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 4, A4, 3, 4));
                                    REQUIRE(pogcvm.mEnvs.size() == 1);
                                    verifyConfirm(pogcvm.mEnvs[0], v0SecretKey,
                                                  qSetHash0, 0, 4, A4, 3, 4);
                                }
                                SECTION("CONFIRM B2")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 2, B2, 2, 2));
                                    REQUIRE(pogcvm.mEnvs.size() == 1);
                                    verifyConfirm(pogcvm.mEnvs[0], v0SecretKey,
                                                  qSetHash0, 0, 2, B2, 2, 2);
                                }
                            }
                            SECTION("EXTERNALIZE")
                            {
                                SECTION("EXTERNALIZE A2")
                                {
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, A2, 2));
                                    REQUIRE(pogcvm.mEnvs.size() == 1);
                                    verifyConfirm(pogcvm.mEnvs[0], v0SecretKey,
                                                  qSetHash0, 0, UINT32_MAX,
                                                  AInf, 2, UINT32_MAX);
                                }
                                SECTION("EXTERNALIZE B2")
                                {
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, B2, 2));
                                    REQUIRE(pogcvm.mEnvs.size() == 1);
                                    verifyConfirm(pogcvm.mEnvs[0], v0SecretKey,
                                                  qSetHash0, 0, UINT32_MAX,
                                                  BInf, 2, UINT32_MAX);
                                }
                            }
                        }
                    }
                }
                SECTION("Confirm prepared mixed")
                {
                    // a few nodes prepared A2
                    // causes p=A2
                    recvVBlockingChecks(makePrepareGen(qSetHash, A2, &A2),
                                        false);
                    REQUIRE(pogcvm.mEnvs.size() == 0);

                    // a few nodes prepared B2
                    // causes p=B2, p'=A2
                    recvVBlockingChecks(
                        makePrepareGen(qSetHash, A2, &B2, 0, 0, &A2), false);
                    REQUIRE(pogcvm.mEnvs.size() == 0);

                    SECTION("mixed A2")
                    {
                        // causes h=A2
                        // but c = 0, as p >!~ h
                        pogcvm.receiveEnvelope(
                            makePrepare(v3SecretKey, qSetHash, 0, A2, &A2));

                        REQUIRE(pogcvm.mEnvs.size() == 1);
                        verifyPrepare(pogcvm.mEnvs[0], v0SecretKey, qSetHash0, 0,
                                      A2, &B2, 0, 2, &A2);

                        pogcvm.receiveEnvelope(
                            makePrepare(v4SecretKey, qSetHash, 0, A2, &A2));

                        REQUIRE(pogcvm.mEnvs.size() == 1);
                    }
                    SECTION("mixed B2")
                    {
                        // causes h=B2, c=B2
                        pogcvm.receiveEnvelope(
                            makePrepare(v3SecretKey, qSetHash, 0, B2, &B2));

                        REQUIRE(pogcvm.mEnvs.size() == 1);
                        verifyPrepare(pogcvm.mEnvs[0], v0SecretKey, qSetHash0, 0,
                                      B2, &B2, 2, 2, &A2);

                        pogcvm.receiveEnvelope(
                            makePrepare(v4SecretKey, qSetHash, 0, B2, &B2));

                        REQUIRE(pogcvm.mEnvs.size() == 1);
                    }
                }
            }
            SECTION("switch prepared B1")
            {
                recvVBlockingChecks(makePrepareGen(qSetHash, B1, &B1), false);
                REQUIRE(pogcvm.mEnvs.size() == 0);
            }
        }
        SECTION("prepared B (v-blocking)")
        {
            recvVBlockingChecks(makePrepareGen(qSetHash, B1, &B1), false);
            REQUIRE(pogcvm.mEnvs.size() == 0);
        }
        SECTION("confirm (v-blocking)")
        {
            SECTION("via CONFIRM")
            {
                pogcvm.receiveEnvelope(
                    makeConfirm(v1SecretKey, qSetHash, 0, 3, A3, 3, 3));
                pogcvm.receiveEnvelope(
                    makeConfirm(v2SecretKey, qSetHash, 0, 4, A4, 2, 4));
                REQUIRE(pogcvm.mEnvs.size() == 1);
                verifyConfirm(pogcvm.mEnvs[0], v0SecretKey, qSetHash0, 0, 3, A3, 3,
                              3);
            }
            SECTION("via EXTERNALIZE")
            {
                pogcvm.receiveEnvelope(
                    makeExternalize(v1SecretKey, qSetHash, 0, A2, 4));
                pogcvm.receiveEnvelope(
                    makeExternalize(v2SecretKey, qSetHash, 0, A3, 5));
                REQUIRE(pogcvm.mEnvs.size() == 1);
                verifyConfirm(pogcvm.mEnvs[0], v0SecretKey, qSetHash0, 0,
                              UINT32_MAX, AInf, 3, UINT32_MAX);
            }
        }
    }

    SECTION("normal round (1,x)")
    {
        nodesAllPledgeToCommit();
        REQUIRE(pogcvm.mEnvs.size() == 3);

        pogcvmBallot b(1, xValue);

        // bunch of prepare messages with "commit b"
        pogcvmEnvelope preparedC1 =
            makePrepare(v1SecretKey, qSetHash, 0, b, &b, b.counter, b.counter);
        pogcvmEnvelope preparedC2 =
            makePrepare(v2SecretKey, qSetHash, 0, b, &b, b.counter, b.counter);
        pogcvmEnvelope preparedC3 =
            makePrepare(v3SecretKey, qSetHash, 0, b, &b, b.counter, b.counter);
        pogcvmEnvelope preparedC4 =
            makePrepare(v4SecretKey, qSetHash, 0, b, &b, b.counter, b.counter);

        // those should not trigger anything just yet
        pogcvm.receiveEnvelope(preparedC1);
        pogcvm.receiveEnvelope(preparedC2);
        REQUIRE(pogcvm.mEnvs.size() == 3);

        // this should cause the node to accept 'commit b' (quorum)
        // and therefore send a "CONFIRM" message
        pogcvm.receiveEnvelope(preparedC3);
        REQUIRE(pogcvm.mEnvs.size() == 4);

        verifyConfirm(pogcvm.mEnvs[3], v0SecretKey, qSetHash0, 0, 1, b, b.counter,
                      b.counter);

        // bunch of confirm messages
        pogcvmEnvelope confirm1 = makeConfirm(v1SecretKey, qSetHash, 0, b.counter,
                                           b, b.counter, b.counter);
        pogcvmEnvelope confirm2 = makeConfirm(v2SecretKey, qSetHash, 0, b.counter,
                                           b, b.counter, b.counter);
        pogcvmEnvelope confirm3 = makeConfirm(v3SecretKey, qSetHash, 0, b.counter,
                                           b, b.counter, b.counter);
        pogcvmEnvelope confirm4 = makeConfirm(v4SecretKey, qSetHash, 0, b.counter,
                                           b, b.counter, b.counter);

        // those should not trigger anything just yet
        pogcvm.receiveEnvelope(confirm1);
        pogcvm.receiveEnvelope(confirm2);
        REQUIRE(pogcvm.mEnvs.size() == 4);

        pogcvm.receiveEnvelope(confirm3);
        // this causes our node to
        // externalize (confirm commit c)
        REQUIRE(pogcvm.mEnvs.size() == 5);

        // The slot should have externalized the value
        REQUIRE(pogcvm.mExternalizedValues.size() == 1);
        REQUIRE(pogcvm.mExternalizedValues[0] == xValue);

        verifyExternalize(pogcvm.mEnvs[4], v0SecretKey, qSetHash0, 0, b,
                          b.counter);

        // extra vote should not do anything
        pogcvm.receiveEnvelope(confirm4);
        REQUIRE(pogcvm.mEnvs.size() == 5);
        REQUIRE(pogcvm.mExternalizedValues.size() == 1);

        // duplicate should just no-op
        pogcvm.receiveEnvelope(confirm2);
        REQUIRE(pogcvm.mEnvs.size() == 5);
        REQUIRE(pogcvm.mExternalizedValues.size() == 1);

        SECTION("bumpToBallot prevented once committed")
        {
            pogcvmBallot b2;
            SECTION("bumpToBallot prevented once committed (by value)")
            {
                b2 = pogcvmBallot(1, zValue);
            }
            SECTION("bumpToBallot prevented once committed (by counter)")
            {
                b2 = pogcvmBallot(2, xValue);
            }
            SECTION(
                "bumpToBallot prevented once committed (by value and counter)")
            {
                b2 = pogcvmBallot(2, zValue);
            }

            pogcvmEnvelope confirm1b2, confirm2b2, confirm3b2, confirm4b2;
            confirm1b2 = makeConfirm(v1SecretKey, qSetHash, 0, b2.counter, b2,
                                     b2.counter, b2.counter);
            confirm2b2 = makeConfirm(v2SecretKey, qSetHash, 0, b2.counter, b2,
                                     b2.counter, b2.counter);
            confirm3b2 = makeConfirm(v3SecretKey, qSetHash, 0, b2.counter, b2,
                                     b2.counter, b2.counter);
            confirm4b2 = makeConfirm(v4SecretKey, qSetHash, 0, b2.counter, b2,
                                     b2.counter, b2.counter);

            pogcvm.receiveEnvelope(confirm1b2);
            pogcvm.receiveEnvelope(confirm2b2);
            pogcvm.receiveEnvelope(confirm3b2);
            pogcvm.receiveEnvelope(confirm4b2);
            REQUIRE(pogcvm.mEnvs.size() == 5);
            REQUIRE(pogcvm.mExternalizedValues.size() == 1);
        }
    }

    SECTION("range check")
    {
        nodesAllPledgeToCommit();
        REQUIRE(pogcvm.mEnvs.size() == 3);

        pogcvmBallot b(1, xValue);

        // bunch of prepare messages with "commit b"
        pogcvmEnvelope preparedC1 =
            makePrepare(v1SecretKey, qSetHash, 0, b, &b, b.counter, b.counter);
        pogcvmEnvelope preparedC2 =
            makePrepare(v2SecretKey, qSetHash, 0, b, &b, b.counter, b.counter);
        pogcvmEnvelope preparedC3 =
            makePrepare(v3SecretKey, qSetHash, 0, b, &b, b.counter, b.counter);
        pogcvmEnvelope preparedC4 =
            makePrepare(v4SecretKey, qSetHash, 0, b, &b, b.counter, b.counter);

        // those should not trigger anything just yet
        pogcvm.receiveEnvelope(preparedC1);
        pogcvm.receiveEnvelope(preparedC2);
        REQUIRE(pogcvm.mEnvs.size() == 3);

        // this should cause the node to accept 'commit b' (quorum)
        // and therefore send a "CONFIRM" message
        pogcvm.receiveEnvelope(preparedC3);
        REQUIRE(pogcvm.mEnvs.size() == 4);

        verifyConfirm(pogcvm.mEnvs[3], v0SecretKey, qSetHash0, 0, 1, b, b.counter,
                      b.counter);

        // bunch of confirm messages with different ranges
        pogcvmBallot b5(5, xValue);
        pogcvmEnvelope confirm1 = makeConfirm(v1SecretKey, qSetHash, 0, 4,
                                           pogcvmBallot(4, xValue), 2, 4);
        pogcvmEnvelope confirm2 = makeConfirm(v2SecretKey, qSetHash, 0, 6,
                                           pogcvmBallot(6, xValue), 2, 6);
        pogcvmEnvelope confirm3 = makeConfirm(v3SecretKey, qSetHash, 0, 5,
                                           pogcvmBallot(5, xValue), 3, 5);
        pogcvmEnvelope confirm4 = makeConfirm(v4SecretKey, qSetHash, 0, 6,
                                           pogcvmBallot(6, xValue), 3, 6);

        // this should not trigger anything just yet
        pogcvm.receiveEnvelope(confirm1);

        // v-blocking
        //   * b gets bumped to (4,x)
        //   * p gets bumped to (4,x)
        //   * (c,h) gets bumped to (2,4)
        pogcvm.receiveEnvelope(confirm2);
        REQUIRE(pogcvm.mEnvs.size() == 5);
        verifyConfirm(pogcvm.mEnvs[4], v0SecretKey, qSetHash0, 0, 4,
                      pogcvmBallot(4, xValue), 2, 4);

        // this causes to externalize
        // range is [3,4]
        pogcvm.receiveEnvelope(confirm4);
        REQUIRE(pogcvm.mEnvs.size() == 6);

        // The slot should have externalized the value
        REQUIRE(pogcvm.mExternalizedValues.size() == 1);
        REQUIRE(pogcvm.mExternalizedValues[0] == xValue);

        verifyExternalize(pogcvm.mEnvs[5], v0SecretKey, qSetHash0, 0,
                          pogcvmBallot(3, xValue), 4);
    }

    SECTION("timeout when h is set -> stay locked on h")
    {
        pogcvmBallot bx(1, xValue);
        REQUIRE(pogcvm.bumpState(0, xValue));
        REQUIRE(pogcvm.mEnvs.size() == 1);

        // v-blocking -> prepared
        // quorum -> confirm prepared
        recvQuorum(makePrepareGen(qSetHash, bx, &bx));
        REQUIRE(pogcvm.mEnvs.size() == 3);
        verifyPrepare(pogcvm.mEnvs[2], v0SecretKey, qSetHash0, 0, bx, &bx,
                      bx.counter, bx.counter);

        // now, see if we can timeout and move to a different value
        REQUIRE(pogcvm.bumpState(0, yValue));
        REQUIRE(pogcvm.mEnvs.size() == 4);
        pogcvmBallot newbx(2, xValue);
        verifyPrepare(pogcvm.mEnvs[3], v0SecretKey, qSetHash0, 0, newbx, &bx,
                      bx.counter, bx.counter);
    }
    SECTION("timeout when h exists but can't be set -> vote for h")
    {
        // start with (1,y)
        pogcvmBallot by(1, yValue);
        REQUIRE(pogcvm.bumpState(0, yValue));
        REQUIRE(pogcvm.mEnvs.size() == 1);

        pogcvmBallot bx(1, xValue);
        // but quorum goes with (1,x)
        // v-blocking -> prepared
        recvVBlocking(makePrepareGen(qSetHash, bx, &bx));
        REQUIRE(pogcvm.mEnvs.size() == 2);
        verifyPrepare(pogcvm.mEnvs[1], v0SecretKey, qSetHash0, 0, by, &bx);
        // quorum -> confirm prepared (no-op as b > h)
        recvQuorumChecks(makePrepareGen(qSetHash, bx, &bx), false, false);
        REQUIRE(pogcvm.mEnvs.size() == 2);

        REQUIRE(pogcvm.bumpState(0, yValue));
        REQUIRE(pogcvm.mEnvs.size() == 3);
        pogcvmBallot newbx(2, xValue);
        // on timeout:
        // * we should move to the quorum's h value
        // * c can't be set yet as b > h
        verifyPrepare(pogcvm.mEnvs[2], v0SecretKey, qSetHash0, 0, newbx, &bx, 0,
                      bx.counter);
    }

    SECTION("timeout from multiple nodes")
    {
        REQUIRE(pogcvm.bumpState(0, xValue));

        pogcvmBallot x1(1, xValue);

        REQUIRE(pogcvm.mEnvs.size() == 1);
        verifyPrepare(pogcvm.mEnvs[0], v0SecretKey, qSetHash0, 0, x1);

        recvQuorum(makePrepareGen(qSetHash, x1));
        // quorum -> prepared (1,x)
        REQUIRE(pogcvm.mEnvs.size() == 2);
        verifyPrepare(pogcvm.mEnvs[1], v0SecretKey, qSetHash0, 0, x1, &x1);

        pogcvmBallot x2(2, xValue);
        // timeout from local node
        REQUIRE(pogcvm.bumpState(0, xValue));
        // prepares (2,x)
        REQUIRE(pogcvm.mEnvs.size() == 3);
        verifyPrepare(pogcvm.mEnvs[2], v0SecretKey, qSetHash0, 0, x2, &x1);

        recvQuorum(makePrepareGen(qSetHash, x1, &x1));
        // quorum -> set nH=1
        REQUIRE(pogcvm.mEnvs.size() == 4);
        verifyPrepare(pogcvm.mEnvs[3], v0SecretKey, qSetHash0, 0, x2, &x1, 0, 1);
        REQUIRE(pogcvm.mEnvs.size() == 4);

        recvVBlocking(makePrepareGen(qSetHash, x2, &x2, 1, 1));
        // v-blocking prepared (2,x) -> prepared (2,x)
        REQUIRE(pogcvm.mEnvs.size() == 5);
        verifyPrepare(pogcvm.mEnvs[4], v0SecretKey, qSetHash0, 0, x2, &x2, 0, 1);

        recvQuorum(makePrepareGen(qSetHash, x2, &x2, 1, 1));
        // quorum (including us) confirms (2,x) prepared -> set h=c=x2
        // we also get extra message: a quorum not including us confirms (1,x)
        // prepared
        //  -> we confirm c=h=x1
        REQUIRE(pogcvm.mEnvs.size() == 7);
        verifyPrepare(pogcvm.mEnvs[5], v0SecretKey, qSetHash0, 0, x2, &x2, 2, 2);
        verifyConfirm(pogcvm.mEnvs[6], v0SecretKey, qSetHash0, 0, 2, x2, 1, 1);
    }

    SECTION("timeout after prepare, receive old messages to prepare")
    {
        REQUIRE(pogcvm.bumpState(0, xValue));

        pogcvmBallot x1(1, xValue);

        REQUIRE(pogcvm.mEnvs.size() == 1);
        verifyPrepare(pogcvm.mEnvs[0], v0SecretKey, qSetHash0, 0, x1);

        pogcvm.receiveEnvelope(makePrepare(v1SecretKey, qSetHash, 0, x1));
        pogcvm.receiveEnvelope(makePrepare(v2SecretKey, qSetHash, 0, x1));
        pogcvm.receiveEnvelope(makePrepare(v3SecretKey, qSetHash, 0, x1));

        // quorum -> prepared (1,x)
        REQUIRE(pogcvm.mEnvs.size() == 2);
        verifyPrepare(pogcvm.mEnvs[1], v0SecretKey, qSetHash0, 0, x1, &x1);

        pogcvmBallot x2(2, xValue);
        // timeout from local node
        REQUIRE(pogcvm.bumpState(0, xValue));
        // prepares (2,x)
        REQUIRE(pogcvm.mEnvs.size() == 3);
        verifyPrepare(pogcvm.mEnvs[2], v0SecretKey, qSetHash0, 0, x2, &x1);

        pogcvmBallot x3(3, xValue);
        // timeout again
        REQUIRE(pogcvm.bumpState(0, xValue));
        // prepares (3,x)
        REQUIRE(pogcvm.mEnvs.size() == 4);
        verifyPrepare(pogcvm.mEnvs[3], v0SecretKey, qSetHash0, 0, x3, &x1);

        // other nodes moved on with x2
        pogcvm.receiveEnvelope(
            makePrepare(v1SecretKey, qSetHash, 0, x2, &x2, 1, 2));
        pogcvm.receiveEnvelope(
            makePrepare(v2SecretKey, qSetHash, 0, x2, &x2, 1, 2));
        // v-blocking -> prepared x2
        REQUIRE(pogcvm.mEnvs.size() == 5);
        verifyPrepare(pogcvm.mEnvs[4], v0SecretKey, qSetHash0, 0, x3, &x2);

        pogcvm.receiveEnvelope(
            makePrepare(v3SecretKey, qSetHash, 0, x2, &x2, 1, 2));
        // quorum -> set nH=2
        REQUIRE(pogcvm.mEnvs.size() == 6);
        verifyPrepare(pogcvm.mEnvs[5], v0SecretKey, qSetHash0, 0, x3, &x2, 0, 2);
    }

    SECTION("non validator watching the network")
    {
        SIMULATION_CREATE_NODE(NV);
        Testpogcvm pogcvmNV(vNVSecretKey.getPublicKey(), qSet, false);
        pogcvmNV.storeQuorumSet(std::make_shared<pogcvmQuorumSet>(qSet));
        uint256 qSetHashNV = pogcvmNV.mpogcvm.getLocalNode()->getQuorumSetHash();

        pogcvmBallot b(1, xValue);
        REQUIRE(pogcvmNV.bumpState(0, xValue));
        REQUIRE(pogcvmNV.mEnvs.size() == 0);
        verifyPrepare(pogcvmNV.getCurrentEnvelope(0, vNVNodeID), vNVSecretKey,
                      qSetHashNV, 0, b);
        auto ext1 = makeExternalize(v1SecretKey, qSetHash, 0, b, 1);
        auto ext2 = makeExternalize(v2SecretKey, qSetHash, 0, b, 1);
        auto ext3 = makeExternalize(v3SecretKey, qSetHash, 0, b, 1);
        auto ext4 = makeExternalize(v4SecretKey, qSetHash, 0, b, 1);
        pogcvmNV.receiveEnvelope(ext1);
        pogcvmNV.receiveEnvelope(ext2);
        pogcvmNV.receiveEnvelope(ext3);
        REQUIRE(pogcvmNV.mEnvs.size() == 0);
        verifyConfirm(pogcvmNV.getCurrentEnvelope(0, vNVNodeID), vNVSecretKey,
                      qSetHashNV, 0, UINT32_MAX, pogcvmBallot(UINT32_MAX, xValue),
                      1, UINT32_MAX);
        pogcvmNV.receiveEnvelope(ext4);
        REQUIRE(pogcvmNV.mEnvs.size() == 0);
        verifyExternalize(pogcvmNV.getCurrentEnvelope(0, vNVNodeID), vNVSecretKey,
                          qSetHashNV, 0, b, UINT32_MAX);
        REQUIRE(pogcvmNV.mExternalizedValues[0] == xValue);
    }

    SECTION("restore ballot protocol")
    {
        Testpogcvm pogcvm2(v0SecretKey.getPublicKey(), qSet);
        pogcvm2.storeQuorumSet(std::make_shared<pogcvmQuorumSet>(qSet));
        pogcvmBallot b(2, xValue);
        SECTION("prepare")
        {
            pogcvm2.mpogcvm.setStateFromEnvelope(
                0,
                pogcvm2.wrapEnvelope(makePrepare(v0SecretKey, qSetHash0, 0, b)));
        }
        SECTION("confirm")
        {
            pogcvm2.mpogcvm.setStateFromEnvelope(
                0, pogcvm2.wrapEnvelope(
                       makeConfirm(v0SecretKey, qSetHash0, 0, 2, b, 1, 2)));
        }
        SECTION("externalize")
        {
            pogcvm2.mpogcvm.setStateFromEnvelope(
                0, pogcvm2.wrapEnvelope(
                       makeExternalize(v0SecretKey, qSetHash0, 0, b, 2)));
        }
    }
}

TEST_CASE("ballot protocol 3", "[pogcvm][ballotprotocol]")
{
    setupValues();
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);

    // 3 has an edge case where v-blocking and quorum can be the same
    // v-blocking set size: 2
    // threshold: 2 = 1 + self or 2 others
    pogcvmQuorumSet qSet;
    qSet.threshold = 2;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);

    uint256 qSetHash = sha256(xdr::xdr_to_opaque(qSet));

    Testpogcvm pogcvm(v0SecretKey.getPublicKey(), qSet);

    pogcvm.storeQuorumSet(std::make_shared<pogcvmQuorumSet>(qSet));
    uint256 qSetHash0 = pogcvm.mpogcvm.getLocalNode()->getQuorumSetHash();

    REQUIRE(xValue < yValue);
    REQUIRE(yValue < zValue);

    auto recvQuorumChecksEx2 = [&](genEnvelope gen, bool withChecks,
                                   bool delayedQuorum, bool checkUpcoming,
                                   bool minQuorum) {
        pogcvmEnvelope e1 = gen(v1SecretKey);
        pogcvmEnvelope e2 = gen(v2SecretKey);

        pogcvm.bumpTimerOffset();

        size_t i = pogcvm.mEnvs.size() + 1;
        pogcvm.receiveEnvelope(e1);
        if (withChecks && !delayedQuorum)
        {
            REQUIRE(pogcvm.mEnvs.size() == i);
        }
        if (checkUpcoming)
        {
            REQUIRE(pogcvm.hasBallotTimerUpcoming());
        }
        if (!minQuorum)
        {
            // nothing happens with an extra vote (unless we're in
            // delayedQuorum)
            pogcvm.receiveEnvelope(e2);
            if (withChecks)
            {
                REQUIRE(pogcvm.mEnvs.size() == i);
            }
        }
    };
    auto recvQuorumChecksEx =
        std::bind(recvQuorumChecksEx2, _1, _2, _3, _4, false);
    auto recvQuorumChecks = std::bind(recvQuorumChecksEx, _1, _2, _3, false);

    // no timer is set
    REQUIRE(!pogcvm.hasBallotTimer());

    Value const& aValue = zValue;
    Value const& bValue = xValue;

    pogcvmBallot A1(1, aValue);
    pogcvmBallot B1(1, bValue);

    pogcvmBallot A2 = A1;
    A2.counter++;

    pogcvmBallot A3 = A2;
    A3.counter++;

    pogcvmBallot A4 = A3;
    A4.counter++;

    pogcvmBallot A5 = A4;
    A5.counter++;

    pogcvmBallot AInf(UINT32_MAX, aValue), BInf(UINT32_MAX, bValue);

    pogcvmBallot B2 = B1;
    B2.counter++;

    pogcvmBallot B3 = B2;
    B3.counter++;

    SECTION("prepared B1 (quorum votes B1) local aValue")
    {
        REQUIRE(pogcvm.bumpState(0, aValue));
        REQUIRE(pogcvm.mEnvs.size() == 1);
        REQUIRE(!pogcvm.hasBallotTimer());

        pogcvm.bumpTimerOffset();
        recvQuorumChecks(makePrepareGen(qSetHash, B1), true, true);
        REQUIRE(pogcvm.mEnvs.size() == 2);
        verifyPrepare(pogcvm.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &B1);
        REQUIRE(pogcvm.hasBallotTimerUpcoming());
        SECTION("quorum prepared B1")
        {
            pogcvm.bumpTimerOffset();
            recvQuorumChecks(makePrepareGen(qSetHash, B1, &B1), false, false);
            REQUIRE(pogcvm.mEnvs.size() == 2);
            // nothing happens:
            // computed_h = B1 (2)
            //    does not actually update h as b > computed_h
            //    also skips (3)
            REQUIRE(!pogcvm.hasBallotTimerUpcoming());
            SECTION("quorum bumps to A1")
            {
                pogcvm.bumpTimerOffset();
                recvQuorumChecksEx2(makePrepareGen(qSetHash, A1, &B1), false,
                                    false, false, true);

                REQUIRE(pogcvm.mEnvs.size() == 3);
                // still does not set h as b > computed_h
                verifyPrepare(pogcvm.mEnvs[2], v0SecretKey, qSetHash0, 0, A1, &A1,
                              0, 0, &B1);
                REQUIRE(!pogcvm.hasBallotTimerUpcoming());

                pogcvm.bumpTimerOffset();
                // quorum commits A1
                recvQuorumChecksEx2(
                    makePrepareGen(qSetHash, A2, &A1, 1, 1, &B1), false, false,
                    false, true);
                REQUIRE(pogcvm.mEnvs.size() == 4);
                verifyConfirm(pogcvm.mEnvs[3], v0SecretKey, qSetHash0, 0, 2, A1, 1,
                              1);
                REQUIRE(!pogcvm.hasBallotTimerUpcoming());
            }
        }
    }
    SECTION("prepared A1 with timeout")
    {
        // starts with bValue (smallest)
        REQUIRE(pogcvm.bumpState(0, bValue));
        REQUIRE(pogcvm.mEnvs.size() == 1);

        // setup
        recvQuorumChecks(makePrepareGen(qSetHash, A1, &A1, 0, 1), false, false);
        REQUIRE(pogcvm.mEnvs.size() == 2);
        verifyPrepare(pogcvm.mEnvs[1], v0SecretKey, qSetHash0, 0, A1, &A1, 1, 1);

        // now, receive bumped votes
        recvQuorumChecks(makePrepareGen(qSetHash, A2, &B2, 0, 1, &A1), true,
                         true);
        REQUIRE(pogcvm.mEnvs.size() == 3);
        // p=B2, p'=A1 (1)
        // computed_h = B2 (2)
        //   does not update h as b < computed_h
        // v-blocking ahead -> b = computed_h = B2 (9)
        // h = B2 (2) (now possible)
        // c = 0 (1)
        verifyPrepare(pogcvm.mEnvs[2], v0SecretKey, qSetHash0, 0, B2, &A2, 0, 2,
                      &B2);
    }
    SECTION("node without self - quorum timeout")
    {
        SIMULATION_CREATE_NODE(NodeNS);
        Testpogcvm pogcvmNNS(vNodeNSSecretKey.getPublicKey(), qSet);
        pogcvmNNS.storeQuorumSet(std::make_shared<pogcvmQuorumSet>(qSet));
        uint256 qSetHashNodeNS = pogcvmNNS.mpogcvm.getLocalNode()->getQuorumSetHash();

        pogcvmNNS.receiveEnvelope(
            makePrepare(v1SecretKey, qSetHash, 0, A2, &B2, 0, 1, &A1));
        pogcvmNNS.receiveEnvelope(
            makePrepare(v2SecretKey, qSetHash, 0, A1, &A1, 1, 1));

        REQUIRE(pogcvmNNS.mEnvs.size() == 1);
        verifyPrepare(pogcvmNNS.mEnvs[0], vNodeNSSecretKey, qSetHashNodeNS, 0, A1,
                      &A1, 1, 1);

        pogcvmNNS.receiveEnvelope(
            makePrepare(v0SecretKey, qSetHash, 0, A2, &B2, 0, 1, &A1));

        REQUIRE(pogcvmNNS.mEnvs.size() == 2);
        verifyPrepare(pogcvmNNS.mEnvs[1], vNodeNSSecretKey, qSetHashNodeNS, 0, B2,
                      &A2, 0, 2, &B2);
    }
}

TEST_CASE("nomination tests 5", "[pogcvm][nominationprotocol]")
{
    setupValues();
    SIMULATION_CREATE_NODE(0);
    SIMULATION_CREATE_NODE(1);
    SIMULATION_CREATE_NODE(2);
    SIMULATION_CREATE_NODE(3);
    SIMULATION_CREATE_NODE(4);

    // we need 5 nodes to avoid sharing various thresholds:
    // v-blocking set size: 2
    // threshold: 4 = 3 + self or 4 others
    pogcvmQuorumSet qSet;
    qSet.threshold = 4;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);
    qSet.validators.push_back(v3NodeID);
    qSet.validators.push_back(v4NodeID);

    uint256 qSetHash = sha256(xdr::xdr_to_opaque(qSet));

    REQUIRE(xValue < yValue);
    REQUIRE(yValue < zValue);

    auto checkLeaders = [&](Testpogcvm& pogcvm, std::set<NodeID> expectedLeaders) {
        auto l = pogcvm.getNominationLeaders(0);
        REQUIRE(std::equal(l.begin(), l.end(), expectedLeaders.begin(),
                           expectedLeaders.end()));
    };

    SECTION("nomination - v0 is top")
    {
        Testpogcvm pogcvm(v0SecretKey.getPublicKey(), qSet);
        uint256 qSetHash0 = pogcvm.mpogcvm.getLocalNode()->getQuorumSetHash();
        pogcvm.storeQuorumSet(std::make_shared<pogcvmQuorumSet>(qSet));

        SECTION("v0 starts to nominates xValue")
        {
            REQUIRE(pogcvm.nominate(0, xValue, false));

            checkLeaders(pogcvm, {v0SecretKey.getPublicKey()});

            SECTION("others nominate what v0 says (x) -> prepare x")
            {
                std::vector<Value> votes, accepted;
                votes.emplace_back(xValue);

                REQUIRE(pogcvm.mEnvs.size() == 1);
                verifyNominate(pogcvm.mEnvs[0], v0SecretKey, qSetHash0, 0, votes,
                               accepted);

                pogcvmEnvelope nom1 =
                    makeNominate(v1SecretKey, qSetHash, 0, votes, accepted);
                pogcvmEnvelope nom2 =
                    makeNominate(v2SecretKey, qSetHash, 0, votes, accepted);
                pogcvmEnvelope nom3 =
                    makeNominate(v3SecretKey, qSetHash, 0, votes, accepted);
                pogcvmEnvelope nom4 =
                    makeNominate(v4SecretKey, qSetHash, 0, votes, accepted);

                // nothing happens yet
                pogcvm.receiveEnvelope(nom1);
                pogcvm.receiveEnvelope(nom2);
                REQUIRE(pogcvm.mEnvs.size() == 1);

                // this causes 'x' to be accepted (quorum)
                pogcvm.receiveEnvelope(nom3);
                REQUIRE(pogcvm.mEnvs.size() == 2);

                pogcvm.mExpectedCandidates.emplace(xValue);
                pogcvm.mCompositeValue = xValue;

                accepted.emplace_back(xValue);
                verifyNominate(pogcvm.mEnvs[1], v0SecretKey, qSetHash0, 0, votes,
                               accepted);

                // extra message doesn't do anything
                pogcvm.receiveEnvelope(nom4);
                REQUIRE(pogcvm.mEnvs.size() == 2);

                pogcvmEnvelope acc1 =
                    makeNominate(v1SecretKey, qSetHash, 0, votes, accepted);
                pogcvmEnvelope acc2 =
                    makeNominate(v2SecretKey, qSetHash, 0, votes, accepted);
                pogcvmEnvelope acc3 =
                    makeNominate(v3SecretKey, qSetHash, 0, votes, accepted);
                pogcvmEnvelope acc4 =
                    makeNominate(v4SecretKey, qSetHash, 0, votes, accepted);

                // nothing happens yet
                pogcvm.receiveEnvelope(acc1);
                pogcvm.receiveEnvelope(acc2);
                REQUIRE(pogcvm.mEnvs.size() == 2);

                pogcvm.mCompositeValue = xValue;
                // this causes the node to send a prepare message (quorum)
                pogcvm.receiveEnvelope(acc3);
                REQUIRE(pogcvm.mEnvs.size() == 3);

                verifyPrepare(pogcvm.mEnvs[2], v0SecretKey, qSetHash0, 0,
                              pogcvmBallot(1, xValue));

                pogcvm.receiveEnvelope(acc4);
                REQUIRE(pogcvm.mEnvs.size() == 3);

                std::vector<Value> votes2 = votes;
                votes2.emplace_back(yValue);

                SECTION(
                    "nominate x -> accept x -> prepare (x) ; others accepted y "
                    "-> update latest to (z=x+y)")
                {
                    pogcvmEnvelope acc1_2 =
                        makeNominate(v1SecretKey, qSetHash, 0, votes2, votes2);
                    pogcvmEnvelope acc2_2 =
                        makeNominate(v2SecretKey, qSetHash, 0, votes2, votes2);
                    pogcvmEnvelope acc3_2 =
                        makeNominate(v3SecretKey, qSetHash, 0, votes2, votes2);
                    pogcvmEnvelope acc4_2 =
                        makeNominate(v4SecretKey, qSetHash, 0, votes2, votes2);

                    pogcvm.receiveEnvelope(acc1_2);
                    REQUIRE(pogcvm.mEnvs.size() == 3);

                    // v-blocking
                    pogcvm.receiveEnvelope(acc2_2);
                    REQUIRE(pogcvm.mEnvs.size() == 4);
                    verifyNominate(pogcvm.mEnvs[3], v0SecretKey, qSetHash0, 0,
                                   votes2, votes2);

                    pogcvm.mExpectedCandidates.insert(yValue);
                    pogcvm.mCompositeValue = kValue;
                    // this updates the composite value to use next time
                    // but does not prepare it
                    pogcvm.receiveEnvelope(acc3_2);
                    REQUIRE(pogcvm.mEnvs.size() == 4);

                    REQUIRE(pogcvm.getLatestCompositeCandidate(0) == kValue);

                    pogcvm.receiveEnvelope(acc4_2);
                    REQUIRE(pogcvm.mEnvs.size() == 4);
                }
                SECTION("nomination - restored state")
                {
                    Testpogcvm pogcvm2(v0SecretKey.getPublicKey(), qSet);
                    pogcvm2.storeQuorumSet(std::make_shared<pogcvmQuorumSet>(qSet));

                    // at this point
                    // votes = { x }
                    // accepted = { x }

                    // tests if nomination proceeds like normal
                    // nominates x
                    auto nominationRestore = [&]() {
                        // restores from the previous state
                        pogcvm2.mpogcvm.setStateFromEnvelope(
                            0,
                            pogcvm2.wrapEnvelope(makeNominate(
                                v0SecretKey, qSetHash0, 0, votes, accepted)));
                        // tries to start nomination with yValue
                        REQUIRE(pogcvm2.nominate(0, yValue, false));

                        checkLeaders(pogcvm2, {v0SecretKey.getPublicKey()});

                        REQUIRE(pogcvm2.mEnvs.size() == 1);
                        verifyNominate(pogcvm2.mEnvs[0], v0SecretKey, qSetHash0, 0,
                                       votes2, accepted);

                        // other nodes vote for 'x'
                        pogcvm2.receiveEnvelope(nom1);
                        pogcvm2.receiveEnvelope(nom2);
                        REQUIRE(pogcvm2.mEnvs.size() == 1);
                        // 'x' is accepted (quorum)
                        // but because the restored state already included
                        // 'x' in the accepted set, no new message is emitted
                        pogcvm2.receiveEnvelope(nom3);

                        pogcvm2.mExpectedCandidates.emplace(xValue);
                        pogcvm2.mCompositeValue = xValue;

                        // other nodes not emit 'x' as accepted
                        pogcvm2.receiveEnvelope(acc1);
                        pogcvm2.receiveEnvelope(acc2);
                        REQUIRE(pogcvm2.mEnvs.size() == 1);

                        pogcvm2.mCompositeValue = xValue;
                        // this causes the node to update its composite value to
                        // x
                        pogcvm2.receiveEnvelope(acc3);
                    };

                    SECTION("ballot protocol not started")
                    {
                        nominationRestore();
                        // nomination ended up starting the ballot protocol
                        REQUIRE(pogcvm2.mEnvs.size() == 2);

                        verifyPrepare(pogcvm2.mEnvs[1], v0SecretKey, qSetHash0, 0,
                                      pogcvmBallot(1, xValue));
                    }
                    SECTION("ballot protocol started (on value k)")
                    {
                        pogcvm2.mpogcvm.setStateFromEnvelope(
                            0, pogcvm2.wrapEnvelope(
                                   makePrepare(v0SecretKey, qSetHash0, 0,
                                               pogcvmBallot(1, kValue))));
                        nominationRestore();
                        // nomination didn't do anything (already working on k)
                        REQUIRE(pogcvm2.mEnvs.size() == 1);
                    }
                }
            }
            SECTION(
                "receive more messages, then v0 switches to a different leader")
            {
                pogcvmEnvelope nom1 =
                    makeNominate(v1SecretKey, qSetHash, 0, {kValue}, {});
                pogcvmEnvelope nom2 =
                    makeNominate(v2SecretKey, qSetHash, 0, {yValue}, {});

                // nothing more happens
                pogcvm.receiveEnvelope(nom1);
                pogcvm.receiveEnvelope(nom2);
                REQUIRE(pogcvm.mEnvs.size() == 1);

                // switch leader to v1
                pogcvm.mPriorityLookup = [&](NodeID const& n) {
                    return (n == v1NodeID) ? 1000 : 1;
                };
                REQUIRE(pogcvm.nominate(0, xValue, true));
                REQUIRE(pogcvm.mEnvs.size() == 2);

                std::vector<Value> votesXK;
                votesXK.emplace_back(xValue);
                votesXK.emplace_back(kValue);
                std::sort(votesXK.begin(), votesXK.end());

                verifyNominate(pogcvm.mEnvs[1], v0SecretKey, qSetHash0, 0, votesXK,
                               {});
            }
        }
        SECTION("self nominates 'x', others nominate y -> prepare y")
        {
            std::vector<Value> myVotes, accepted;
            myVotes.emplace_back(xValue);

            pogcvm.mExpectedCandidates.emplace(xValue);
            pogcvm.mCompositeValue = xValue;
            REQUIRE(pogcvm.nominate(0, xValue, false));

            REQUIRE(pogcvm.mEnvs.size() == 1);
            verifyNominate(pogcvm.mEnvs[0], v0SecretKey, qSetHash0, 0, myVotes,
                           accepted);

            std::vector<Value> votes;
            votes.emplace_back(yValue);

            std::vector<Value> acceptedY = accepted;

            acceptedY.emplace_back(yValue);

            SECTION("others only vote for y")
            {
                pogcvmEnvelope nom1 =
                    makeNominate(v1SecretKey, qSetHash, 0, votes, accepted);
                pogcvmEnvelope nom2 =
                    makeNominate(v2SecretKey, qSetHash, 0, votes, accepted);
                pogcvmEnvelope nom3 =
                    makeNominate(v3SecretKey, qSetHash, 0, votes, accepted);
                pogcvmEnvelope nom4 =
                    makeNominate(v4SecretKey, qSetHash, 0, votes, accepted);

                // nothing happens yet
                pogcvm.receiveEnvelope(nom1);
                pogcvm.receiveEnvelope(nom2);
                pogcvm.receiveEnvelope(nom3);
                REQUIRE(pogcvm.mEnvs.size() == 1);

                // 'y' is accepted (quorum)
                pogcvm.receiveEnvelope(nom4);
                REQUIRE(pogcvm.mEnvs.size() == 2);
                myVotes.emplace_back(yValue);
                verifyNominate(pogcvm.mEnvs[1], v0SecretKey, qSetHash0, 0, myVotes,
                               acceptedY);
            }
            SECTION("others accepted y")
            {
                pogcvmEnvelope acc1 =
                    makeNominate(v1SecretKey, qSetHash, 0, votes, acceptedY);
                pogcvmEnvelope acc2 =
                    makeNominate(v2SecretKey, qSetHash, 0, votes, acceptedY);
                pogcvmEnvelope acc3 =
                    makeNominate(v3SecretKey, qSetHash, 0, votes, acceptedY);
                pogcvmEnvelope acc4 =
                    makeNominate(v4SecretKey, qSetHash, 0, votes, acceptedY);

                pogcvm.receiveEnvelope(acc1);
                REQUIRE(pogcvm.mEnvs.size() == 1);

                // this causes 'y' to be accepted (v-blocking)
                pogcvm.receiveEnvelope(acc2);
                REQUIRE(pogcvm.mEnvs.size() == 2);

                myVotes.emplace_back(yValue);
                verifyNominate(pogcvm.mEnvs[1], v0SecretKey, qSetHash0, 0, myVotes,
                               acceptedY);

                pogcvm.mExpectedCandidates.clear();
                pogcvm.mExpectedCandidates.insert(yValue);
                pogcvm.mCompositeValue = yValue;
                // this causes the node to send a prepare message (quorum)
                pogcvm.receiveEnvelope(acc3);
                REQUIRE(pogcvm.mEnvs.size() == 3);

                verifyPrepare(pogcvm.mEnvs[2], v0SecretKey, qSetHash0, 0,
                              pogcvmBallot(1, yValue));

                pogcvm.receiveEnvelope(acc4);
                REQUIRE(pogcvm.mEnvs.size() == 3);
            }
        }
    }
    SECTION("v1 is top node")
    {
        Testpogcvm pogcvm(v0SecretKey.getPublicKey(), qSet);
        uint256 qSetHash0 = pogcvm.mpogcvm.getLocalNode()->getQuorumSetHash();
        pogcvm.storeQuorumSet(std::make_shared<pogcvmQuorumSet>(qSet));

        pogcvm.mPriorityLookup = [&](NodeID const& n) {
            return (n == v1NodeID) ? 1000 : 1;
        };

        std::vector<Value> votesX, votesY, votesK, votesXY, votesYK, votesXK,
            emptyV;
        votesX.emplace_back(xValue);
        votesY.emplace_back(yValue);
        votesK.emplace_back(kValue);

        votesXY.emplace_back(xValue);
        votesXY.emplace_back(yValue);

        votesYK.emplace_back(yValue);
        votesYK.emplace_back(kValue);
        std::sort(votesYK.begin(), votesYK.end());

        votesXK.emplace_back(xValue);
        votesXK.emplace_back(kValue);
        std::sort(votesXK.begin(), votesXK.end());

        std::vector<Value> valuesHash;
        valuesHash.emplace_back(xValue);
        valuesHash.emplace_back(yValue);
        valuesHash.emplace_back(kValue);
        std::sort(valuesHash.begin(), valuesHash.end());

        pogcvm.mHashValueCalculator = [&](Value const& v) {
            auto pos = std::find(valuesHash.begin(), valuesHash.end(), v);
            if (pos == valuesHash.end())
            {
                abort();
            }
            return 1 + std::distance(valuesHash.begin(), pos);
        };

        pogcvmEnvelope nom1 =
            makeNominate(v1SecretKey, qSetHash, 0, votesXY, emptyV);
        pogcvmEnvelope nom2 =
            makeNominate(v2SecretKey, qSetHash, 0, votesXK, emptyV);

        SECTION("nomination waits for v1")
        {
            REQUIRE(!pogcvm.nominate(0, xValue, false));

            checkLeaders(pogcvm, {v1SecretKey.getPublicKey()});

            REQUIRE(pogcvm.mEnvs.size() == 0);

            pogcvmEnvelope nom4 =
                makeNominate(v4SecretKey, qSetHash, 0, votesXK, emptyV);

            // nothing happens with non top nodes
            pogcvm.receiveEnvelope(nom2);
            // (note: don't receive anything from node3 - we want to pick
            // another dead node)
            REQUIRE(pogcvm.mEnvs.size() == 0);

            // v1 is leader -> nominate the first value from its message
            // that's "y"
            pogcvm.receiveEnvelope(nom1);
            REQUIRE(pogcvm.mEnvs.size() == 1);
            verifyNominate(pogcvm.mEnvs[0], v0SecretKey, qSetHash0, 0, votesY,
                           emptyV);

            pogcvm.receiveEnvelope(nom4);
            REQUIRE(pogcvm.mEnvs.size() == 1);

            // "timeout -> pick another value from v1"
            pogcvm.mExpectedCandidates.emplace(xValue);
            pogcvm.mCompositeValue = xValue;

            // allows to pick another leader,
            // pick another dead node v3 as to force picking up
            // a new value from v1
            pogcvm.mPriorityLookup = [&](NodeID const& n) {
                return (n == v3NodeID) ? 1000 : 1;
            };

            // note: value passed in here should be ignored
            REQUIRE(pogcvm.nominate(0, kValue, true));
            // picks up 'x' from v1 (as we already have 'y')
            // which also happens to causes 'x' to be accepted
            REQUIRE(pogcvm.mEnvs.size() == 2);
            verifyNominate(pogcvm.mEnvs[1], v0SecretKey, qSetHash0, 0, votesXY,
                           votesX);
        }
        SECTION("v1 dead, timeout")
        {
            REQUIRE(!pogcvm.nominate(0, xValue, false));

            REQUIRE(pogcvm.mEnvs.size() == 0);

            pogcvm.receiveEnvelope(nom2);
            REQUIRE(pogcvm.mEnvs.size() == 0);

            checkLeaders(pogcvm, {v1SecretKey.getPublicKey()});

            SECTION("v0 is new top node")
            {
                pogcvm.mPriorityLookup = [&](NodeID const& n) {
                    return (n == v0NodeID) ? 1000 : 1;
                };

                REQUIRE(pogcvm.nominate(0, xValue, true));
                checkLeaders(pogcvm, {v0SecretKey.getPublicKey(),
                                   v1SecretKey.getPublicKey()});

                REQUIRE(pogcvm.mEnvs.size() == 1);
                verifyNominate(pogcvm.mEnvs[0], v0SecretKey, qSetHash0, 0, votesX,
                               emptyV);
            }
            SECTION("v2 is new top node")
            {
                pogcvm.mPriorityLookup = [&](NodeID const& n) {
                    return (n == v2NodeID) ? 1000 : 1;
                };

                REQUIRE(pogcvm.nominate(0, xValue, true));
                checkLeaders(pogcvm, {v1SecretKey.getPublicKey(),
                                   v2SecretKey.getPublicKey()});

                REQUIRE(pogcvm.mEnvs.size() == 1);
                // v2 votes for XK, but nomination only picks the highest value
                std::vector<Value> v2Top;
                v2Top.emplace_back(std::max(xValue, kValue));
                verifyNominate(pogcvm.mEnvs[0], v0SecretKey, qSetHash0, 0, v2Top,
                               emptyV);
            }
            SECTION("v3 is new top node")
            {
                pogcvm.mPriorityLookup = [&](NodeID const& n) {
                    return (n == v3NodeID) ? 1000 : 1;
                };
                // nothing happens, we don't have any message for v3
                REQUIRE(!pogcvm.nominate(0, xValue, true));
                checkLeaders(pogcvm, {v1SecretKey.getPublicKey(),
                                   v3SecretKey.getPublicKey()});

                REQUIRE(pogcvm.mEnvs.size() == 0);
            }
        }
    }
}
}
