#pragma once

// Copyright 2017 POGchain Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "xdr/POGchain-types.h"
#include <vector>

namespace POGchain
{

struct pogcvmEnvelope;
struct pogcvmStatement;
struct POGchainValue;

std::vector<Hash> getTxSetHashes(pogcvmEnvelope const& envelope);
std::vector<POGchainValue> getPOGchainValues(pogcvmStatement const& envelope);
}
