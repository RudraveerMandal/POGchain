// Copyright 2014 POGchain Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "pogcvmDriver.h"

#include <algorithm>

#include "crypto/Hex.h"
#include "crypto/KeyUtils.h"
#include "crypto/SecretKey.h"
#include "util/GlobalChecks.h"
#include "xdrpp/marshal.h"

namespace POGchain
{

bool
WrappedValuePtrComparator::operator()(ValueWrapperPtr const& l,
                                      ValueWrapperPtr const& r) const
{
    releaseAssert(l && r);
    return l->getValue() < r->getValue();
}

pogcvmEnvelopeWrapper::pogcvmEnvelopeWrapper(pogcvmEnvelope const& e) : mEnvelope(e)
{
}

pogcvmEnvelopeWrapper::~pogcvmEnvelopeWrapper()
{
}

ValueWrapper::ValueWrapper(Value const& value) : mValue(value)
{
}

ValueWrapper::~ValueWrapper()
{
}

pogcvmEnvelopeWrapperPtr
pogcvmDriver::wrapEnvelope(pogcvmEnvelope const& envelope)
{
    auto res = std::make_shared<pogcvmEnvelopeWrapper>(envelope);
    return res;
}

ValueWrapperPtr
pogcvmDriver::wrapValue(Value const& value)
{
    auto res = std::make_shared<ValueWrapper>(value);
    return res;
}

std::string
pogcvmDriver::getValueString(Value const& v) const
{
    Hash valueHash = getHashOf({xdr::xdr_to_opaque(v)});

    return hexAbbrev(valueHash);
}

std::string
pogcvmDriver::toStrKey(NodeID const& pk, bool fullKey) const
{
    return fullKey ? KeyUtils::toStrKey(pk) : toShortString(pk);
}

std::string
pogcvmDriver::toShortString(NodeID const& pk) const
{
    return KeyUtils::toShortString(pk);
}

// values used to switch hash function between priority and neighborhood checks
static const uint32 hash_N = 1;
static const uint32 hash_P = 2;
static const uint32 hash_K = 3;

uint64
pogcvmDriver::hashHelper(
    uint64 slotIndex, Value const& prev,
    std::function<void(std::vector<xdr::opaque_vec<>>&)> extra)
{
    std::vector<xdr::opaque_vec<>> vals;
    vals.emplace_back(xdr::xdr_to_opaque(slotIndex));
    vals.emplace_back(xdr::xdr_to_opaque(prev));
    extra(vals);
    Hash t = getHashOf(vals);
    uint64 res = 0;
    for (size_t i = 0; i < sizeof(res); i++)
    {
        res = (res << 8) | t[i];
    }
    return res;
}

uint64
pogcvmDriver::computeHashNode(uint64 slotIndex, Value const& prev, bool isPriority,
                           int32_t roundNumber, NodeID const& nodeID)
{
    return hashHelper(
        slotIndex, prev, [&](std::vector<xdr::opaque_vec<>>& vals) {
            vals.emplace_back(xdr::xdr_to_opaque(isPriority ? hash_P : hash_N));
            vals.emplace_back(xdr::xdr_to_opaque(roundNumber));
            vals.emplace_back(xdr::xdr_to_opaque(nodeID));
        });
}

uint64
pogcvmDriver::computeValueHash(uint64 slotIndex, Value const& prev,
                            int32_t roundNumber, Value const& value)
{
    return hashHelper(slotIndex, prev,
                      [&](std::vector<xdr::opaque_vec<>>& vals) {
                          vals.emplace_back(xdr::xdr_to_opaque(hash_K));
                          vals.emplace_back(xdr::xdr_to_opaque(roundNumber));
                          vals.emplace_back(xdr::xdr_to_opaque(value));
                      });
}

static const int MAX_TIMEOUT_SECONDS = (30 * 60);

std::chrono::milliseconds
pogcvmDriver::computeTimeout(uint32 roundNumber)
{
    // straight linear timeout
    // starting at 1 second and capping at MAX_TIMEOUT_SECONDS

    int timeoutInSeconds;
    if (roundNumber > MAX_TIMEOUT_SECONDS)
    {
        timeoutInSeconds = MAX_TIMEOUT_SECONDS;
    }
    else
    {
        timeoutInSeconds = (int)roundNumber;
    }
    return std::chrono::seconds(timeoutInSeconds);
}
}
