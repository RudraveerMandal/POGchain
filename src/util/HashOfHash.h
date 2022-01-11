// Copyright 2020 POGchain Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once
#include <xdr/POGchain-types.h>

namespace std
{
template <> struct hash<POGchain::uint256>
{
    size_t operator()(POGchain::uint256 const& x) const noexcept;
};
}
