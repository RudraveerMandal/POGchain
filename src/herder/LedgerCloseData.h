#pragma once

// Copyright 2014 POGchain Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "TxSetFrame.h"
#include "main/Config.h"
#include "overlay/POGchainXDR.h"
#include <optional>
#include <string>

namespace POGchain
{

/**
 * Helper class that describes a single ledger-to-close -- a set of transactions
 * and auxiliary values -- as decided by the Herder (and ultimately: pogcvm). This
 * does not include the effects of _performing_ any transactions, merely the
 * values that the network has agreed _to apply_ to the current ledger,
 * atomically, in order to produce the next ledger.
 */
class LedgerCloseData
{
  public:
    LedgerCloseData(
        uint32_t ledgerSeq, std::shared_ptr<AbstractTxSetFrameForApply> txSet,
        POGchainValue const& v,
        std::optional<Hash> const& expectedLedgerHash = std::nullopt);

    uint32_t
    getLedgerSeq() const
    {
        return mLedgerSeq;
    }
    std::shared_ptr<AbstractTxSetFrameForApply>
    getTxSet() const
    {
        return mTxSet;
    }
    POGchainValue const&
    getValue() const
    {
        return mValue;
    }
    std::optional<Hash> const&
    getExpectedHash() const
    {
        return mExpectedLedgerHash;
    }

  private:
    uint32_t mLedgerSeq;
    std::shared_ptr<AbstractTxSetFrameForApply> mTxSet;
    POGchainValue mValue;
    std::optional<Hash> mExpectedLedgerHash;
};

std::string POGchainValueToString(Config const& c, POGchainValue const& sv);

#define emptyUpgradeSteps (xdr::xvector<UpgradeType, 6>(0))
}
