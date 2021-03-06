// Copyright 2014 POGchain Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "herder/HerderUtils.h"
#include "pogcvm/Slot.h"
#include "xdr/POGchain-ledger.h"
#include <algorithm>
#include <xdrpp/marshal.h>

namespace POGchain
{

std::vector<Hash>
getTxSetHashes(pogcvmEnvelope const& envelope)
{
    auto values = getPOGchainValues(envelope.statement);
    auto result = std::vector<Hash>{};
    result.resize(values.size());

    std::transform(std::begin(values), std::end(values), std::begin(result),
                   [](POGchainValue const& sv) { return sv.txSetHash; });

    return result;
}

std::vector<POGchainValue>
getPOGchainValues(pogcvmStatement const& statement)
{
    auto values = Slot::getStatementValues(statement);
    auto result = std::vector<POGchainValue>{};
    result.resize(values.size());

    std::transform(std::begin(values), std::end(values), std::begin(result),
                   [](Value const& v) {
                       auto wb = POGchainValue{};
                       xdr::xdr_from_opaque(v, wb);
                       return wb;
                   });

    return result;
}
}
