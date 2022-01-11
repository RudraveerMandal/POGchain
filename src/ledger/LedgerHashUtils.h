#pragma once

// Copyright 2018 POGchain Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "crypto/ShortHash.h"
#include "ledger/InternalLedgerEntry.h"
#include "xdr/POGchain-ledger.h"
#include <functional>

namespace POGchain
{

static PoolID const&
getLiquidityPoolID(Asset const& asset)
{
    throw std::runtime_error("cannot get PoolID from Asset");
}

static PoolID const&
getLiquidityPoolID(TrustLineAsset const& tlAsset)
{
    return tlAsset.liquidityPoolID();
}

static inline void
hashMix(size_t& h, size_t v)
{
    // from https://github.com/ztanml/fast-hash (MIT license)
    v ^= v >> 23;
    v *= 0x2127599bf4325c37ULL;
    v ^= v >> 47;
    h ^= v;
    h *= 0x880355f21e6d1965ULL;
}

template <typename T>
static size_t
getAssetHash(T const& asset)
{
    size_t res = asset.type();

    switch (asset.type())
    {
    case POGchain::ASSET_TYPE_NATIVE:
        break;
    case POGchain::ASSET_TYPE_CREDIT_ALPHANUM4:
    {
        auto& a4 = asset.alphaNum4();
        hashMix(res, POGchain::shortHash::computeHash(
                         POGchain::ByteSlice(a4.issuer.ed25519().data(), 8)));
        hashMix(res, POGchain::shortHash::computeHash(POGchain::ByteSlice(
                         a4.assetCode.data(), a4.assetCode.size())));
        break;
    }
    case POGchain::ASSET_TYPE_CREDIT_ALPHANUM12:
    {
        auto& a12 = asset.alphaNum12();
        hashMix(res, POGchain::shortHash::computeHash(
                         POGchain::ByteSlice(a12.issuer.ed25519().data(), 8)));
        hashMix(res, POGchain::shortHash::computeHash(POGchain::ByteSlice(
                         a12.assetCode.data(), a12.assetCode.size())));
        break;
    }
    case POGchain::ASSET_TYPE_POOL_SHARE:
    {
        hashMix(res, POGchain::shortHash::computeHash(POGchain::ByteSlice(
                         getLiquidityPoolID(asset).data(), 8)));
        break;
    }
    default:
        throw std::runtime_error("unknown Asset type");
    }
    return res;
}

}

// implements a default hasher for "LedgerKey"
namespace std
{
template <> class hash<POGchain::Asset>
{
  public:
    size_t
    operator()(POGchain::Asset const& asset) const
    {
        return POGchain::getAssetHash<POGchain::Asset>(asset);
    }
};

template <> class hash<POGchain::TrustLineAsset>
{
  public:
    size_t
    operator()(POGchain::TrustLineAsset const& asset) const
    {
        return POGchain::getAssetHash<POGchain::TrustLineAsset>(asset);
    }
};

template <> class hash<POGchain::LedgerKey>
{
  public:
    size_t
    operator()(POGchain::LedgerKey const& lk) const
    {
        size_t res = lk.type();
        switch (lk.type())
        {
        case POGchain::ACCOUNT:
            POGchain::hashMix(res,
                             POGchain::shortHash::computeHash(POGchain::ByteSlice(
                                 lk.account().accountID.ed25519().data(), 8)));
            break;
        case POGchain::TRUSTLINE:
        {
            auto& tl = lk.trustLine();
            POGchain::hashMix(
                res, POGchain::shortHash::computeHash(
                         POGchain::ByteSlice(tl.accountID.ed25519().data(), 8)));
            POGchain::hashMix(res, hash<POGchain::TrustLineAsset>()(tl.asset));
            break;
        }
        case POGchain::DATA:
            POGchain::hashMix(res,
                             POGchain::shortHash::computeHash(POGchain::ByteSlice(
                                 lk.data().accountID.ed25519().data(), 8)));
            POGchain::hashMix(
                res,
                POGchain::shortHash::computeHash(POGchain::ByteSlice(
                    lk.data().dataName.data(), lk.data().dataName.size())));
            break;
        case POGchain::OFFER:
            POGchain::hashMix(
                res, POGchain::shortHash::computeHash(POGchain::ByteSlice(
                         &lk.offer().offerID, sizeof(lk.offer().offerID))));
            break;
        case POGchain::CLAIMABLE_BALANCE:
            POGchain::hashMix(
                res, POGchain::shortHash::computeHash(POGchain::ByteSlice(
                         lk.claimableBalance().balanceID.v0().data(), 8)));
            break;
        case POGchain::LIQUIDITY_POOL:
            POGchain::hashMix(
                res, POGchain::shortHash::computeHash(POGchain::ByteSlice(
                         lk.liquidityPool().liquidityPoolID.data(), 8)));
            break;
        default:
            abort();
        }
        return res;
    }
};

template <> class hash<POGchain::InternalLedgerKey>
{
  public:
    size_t
    operator()(POGchain::InternalLedgerKey const& glk) const
    {
        return glk.hash();
    }
};
}
