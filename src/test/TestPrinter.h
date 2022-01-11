#pragma once

// Copyright 2017 POGchain Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "catchup/CatchupWork.h"
#include "history/test/HistoryTestsUtils.h"
#include "lib/catch.hpp"
#include "util/XDRCereal.h"
#include "xdrpp/types.h"

namespace POGchain
{
struct OfferState;
}

namespace Catch
{
template <typename T>
struct StringMaker<T, typename std::enable_if<xdr::xdr_traits<T>::valid>::type>
{
    static std::string
    convert(T const& val)
    {
        return xdr_to_string(val, "value");
    }
};

template <> struct StringMaker<POGchain::OfferState>
{
    static std::string convert(POGchain::OfferState const& os);
};

template <> struct StringMaker<POGchain::CatchupRange>
{
    static std::string convert(POGchain::CatchupRange const& cr);
};

template <> struct StringMaker<POGchain::historytestutils::CatchupPerformedWork>
{
    static std::string
    convert(POGchain::historytestutils::CatchupPerformedWork const& cr);
};
}
