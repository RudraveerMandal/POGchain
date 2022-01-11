// Copyright 2014 POGchain Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "pogcvm/pogcvm.h"
#include "crypto/Hex.h"
#include "pogcvm/LocalNode.h"
#include "pogcvm/Slot.h"
#include "util/GlobalChecks.h"
#include "util/Logging.h"
#include "util/XDROperators.h"
#include "xdrpp/marshal.h"

#include <algorithm>
#include <lib/json/json.h>
#include <sstream>

namespace POGchain
{

pogcvm::pogcvm(pogcvmDriver& driver, NodeID const& nodeID, bool isValidator,
         pogcvmQuorumSet const& qSetLocal)
    : mDriver(driver)
{
    mLocalNode =
        std::make_shared<LocalNode>(nodeID, isValidator, qSetLocal, driver);
}

pogcvm::EnvelopeState
pogcvm::receiveEnvelope(pogcvmEnvelopeWrapperPtr envelope)
{
    uint64 slotIndex = envelope->getStatement().slotIndex;
    return getSlot(slotIndex, true)->processEnvelope(envelope, false);
}

bool
pogcvm::nominate(uint64 slotIndex, ValueWrapperPtr value,
              Value const& previousValue)
{
    dbgAssert(isValidator());
    return getSlot(slotIndex, true)->nominate(value, previousValue, false);
}

void
pogcvm::stopNomination(uint64 slotIndex)
{
    auto s = getSlot(slotIndex, false);
    if (s)
    {
        s->stopNomination();
    }
}

void
pogcvm::updateLocalQuorumSet(pogcvmQuorumSet const& qSet)
{
    mLocalNode->updateQuorumSet(qSet);
}

pogcvmQuorumSet const&
pogcvm::getLocalQuorumSet()
{
    return mLocalNode->getQuorumSet();
}

NodeID const&
pogcvm::getLocalNodeID()
{
    return mLocalNode->getNodeID();
}

void
pogcvm::purgeSlots(uint64 maxSlotIndex)
{
    auto it = mKnownSlots.begin();
    while (it != mKnownSlots.end() && it->first < maxSlotIndex)
    {
        it = mKnownSlots.erase(it);
    }
}

std::shared_ptr<LocalNode>
pogcvm::getLocalNode()
{
    return mLocalNode;
}

std::shared_ptr<Slot>
pogcvm::getSlot(uint64 slotIndex, bool create)
{
    std::shared_ptr<Slot> res;
    auto it = mKnownSlots.find(slotIndex);
    if (it == mKnownSlots.end())
    {
        if (create)
        {
            res = std::make_shared<Slot>(slotIndex, *this);
            mKnownSlots[slotIndex] = res;
        }
    }
    else
    {
        res = it->second;
    }
    return res;
}

Json::Value
pogcvm::getJsonInfo(size_t limit, bool fullKeys)
{
    Json::Value ret;
    auto it = mKnownSlots.rbegin();
    while (it != mKnownSlots.rend() && limit-- != 0)
    {
        auto& slot = *(it->second);
        ret[std::to_string(slot.getSlotIndex())] = slot.getJsonInfo(fullKeys);
        it++;
    }

    return ret;
}

Json::Value
pogcvm::getJsonQuorumInfo(NodeID const& id, bool summary, bool fullKeys,
                       uint64 index)
{
    Json::Value ret;
    if (index == 0)
    {
        for (auto& item : mKnownSlots)
        {
            auto& slot = *item.second;
            ret = slot.getJsonQuorumInfo(id, summary, fullKeys);
            ret["ledger"] = static_cast<Json::UInt64>(slot.getSlotIndex());
        }
    }
    else
    {
        auto s = getSlot(index, false);
        if (s)
        {
            ret = s->getJsonQuorumInfo(id, summary, fullKeys);
            ret["ledger"] = static_cast<Json::UInt64>(index);
        }
    }
    return ret;
}

bool
pogcvm::isValidator()
{
    return mLocalNode->isValidator();
}

bool
pogcvm::isSlotFullyValidated(uint64 slotIndex)
{
    auto slot = getSlot(slotIndex, false);
    if (slot)
    {
        return slot->isFullyValidated();
    }
    else
    {
        return false;
    }
}

bool
pogcvm::gotVBlocking(uint64 slotIndex)
{
    auto slot = getSlot(slotIndex, false);
    if (slot)
    {
        return slot->gotVBlocking();
    }
    else
    {
        return false;
    }
}

size_t
pogcvm::getKnownSlotsCount() const
{
    return mKnownSlots.size();
}

size_t
pogcvm::getCumulativeStatemtCount() const
{
    size_t c = 0;
    for (auto const& s : mKnownSlots)
    {
        c += s.second->getStatementCount();
    }
    return c;
}

std::vector<pogcvmEnvelope>
pogcvm::getLatestMessagesSend(uint64 slotIndex)
{
    auto slot = getSlot(slotIndex, false);
    if (slot)
    {
        return slot->getLatestMessagesSend();
    }
    else
    {
        return std::vector<pogcvmEnvelope>();
    }
}

void
pogcvm::setStateFromEnvelope(uint64 slotIndex, pogcvmEnvelopeWrapperPtr e)
{
    auto slot = getSlot(slotIndex, true);
    slot->setStateFromEnvelope(e);
}

bool
pogcvm::empty() const
{
    return mKnownSlots.empty();
}

void
pogcvm::processCurrentState(uint64 slotIndex,
                         std::function<bool(pogcvmEnvelope const&)> const& f,
                         bool forceSelf)
{
    auto slot = getSlot(slotIndex, false);
    if (slot)
    {
        slot->processCurrentState(f, forceSelf);
    }
}

void
pogcvm::processSlotsAscendingFrom(uint64 startingSlot,
                               std::function<bool(uint64)> const& f)
{
    for (auto iter = mKnownSlots.lower_bound(startingSlot);
         iter != mKnownSlots.end(); ++iter)
    {
        if (!f(iter->first))
        {
            break;
        }
    }
}

void
pogcvm::processSlotsDescendingFrom(uint64 startingSlot,
                                std::function<bool(uint64)> const& f)
{
    auto iter = mKnownSlots.upper_bound(startingSlot);
    while (iter != mKnownSlots.begin())
    {
        --iter;
        if (!f(iter->first))
        {
            break;
        }
    }
}

pogcvmEnvelope const*
pogcvm::getLatestMessage(NodeID const& id)
{
    for (auto it = mKnownSlots.rbegin(); it != mKnownSlots.rend(); it++)
    {
        auto slot = it->second;
        auto res = slot->getLatestMessage(id);
        if (res != nullptr)
        {
            return res;
        }
    }
    return nullptr;
}

std::vector<pogcvmEnvelope>
pogcvm::getExternalizingState(uint64 slotIndex)
{
    auto slot = getSlot(slotIndex, false);
    if (slot)
    {
        return slot->getExternalizingState();
    }
    else
    {
        return std::vector<pogcvmEnvelope>();
    }
}

std::string
pogcvm::getValueString(Value const& v) const
{
    return mDriver.getValueString(v);
}

std::string
pogcvm::ballotToStr(pogcvmBallot const& ballot) const
{
    std::ostringstream oss;

    oss << "(" << ballot.counter << "," << getValueString(ballot.value) << ")";
    return oss.str();
}

std::string
pogcvm::ballotToStr(std::unique_ptr<pogcvmBallot> const& ballot) const
{
    std::string res;
    if (ballot)
    {
        res = ballotToStr(*ballot);
    }
    else
    {
        res = "(<null_ballot>)";
    }
    return res;
}

std::string
pogcvm::envToStr(pogcvmEnvelope const& envelope, bool fullKeys) const
{
    return envToStr(envelope.statement, fullKeys);
}

std::string
pogcvm::envToStr(pogcvmStatement const& st, bool fullKeys) const
{
    std::ostringstream oss;

    Hash const& qSetHash = Slot::getCompanionQuorumSetHashFromStatement(st);

    std::string nodeId = mDriver.toStrKey(st.nodeID, fullKeys);

    oss << "{ENV@" << nodeId << " | "
        << " i: " << st.slotIndex;
    switch (st.pledges.type())
    {
    case pogcvmStatementType::pogcvm_ST_PREPARE:
    {
        auto const& p = st.pledges.prepare();
        oss << " | PREPARE"
            << " | D: " << hexAbbrev(qSetHash)
            << " | b: " << ballotToStr(p.ballot)
            << " | p: " << ballotToStr(p.prepared)
            << " | p': " << ballotToStr(p.preparedPrime) << " | c.n: " << p.nC
            << " | h.n: " << p.nH;
    }
    break;
    case pogcvmStatementType::pogcvm_ST_CONFIRM:
    {
        auto const& c = st.pledges.confirm();
        oss << " | CONFIRM"
            << " | D: " << hexAbbrev(qSetHash)
            << " | b: " << ballotToStr(c.ballot) << " | p.n: " << c.nPrepared
            << " | c.n: " << c.nCommit << " | h.n: " << c.nH;
    }
    break;
    case pogcvmStatementType::pogcvm_ST_EXTERNALIZE:
    {
        auto const& ex = st.pledges.externalize();
        oss << " | EXTERNALIZE"
            << " | c: " << ballotToStr(ex.commit) << " | h.n: " << ex.nH
            << " | (lastD): " << hexAbbrev(qSetHash);
    }
    break;
    case pogcvmStatementType::pogcvm_ST_NOMINATE:
    {
        auto const& nom = st.pledges.nominate();
        oss << " | NOMINATE"
            << " | D: " << hexAbbrev(qSetHash) << " | X: {";
        bool first = true;
        for (auto const& v : nom.votes)
        {
            if (!first)
            {
                oss << " ,";
            }
            oss << "'" << getValueString(v) << "'";
            first = false;
        }
        oss << "}"
            << " | Y: {";
        first = true;
        for (auto const& a : nom.accepted)
        {
            if (!first)
            {
                oss << " ,";
            }
            oss << "'" << getValueString(a) << "'";
            first = false;
        }
        oss << "}";
    }
    break;
    }

    oss << " }";
    return oss.str();
}
}
