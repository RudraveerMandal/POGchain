// Copyright 2015 POGchain Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

%#include "xdr/POGchain-types.h"

namespace POGchain
{

typedef opaque Value<>;

struct pogcvmBallot
{
    uint32 counter; // n
    Value value;    // x
};

enum pogcvmStatementType
{
    pogcvm_ST_PREPARE = 0,
    pogcvm_ST_CONFIRM = 1,
    pogcvm_ST_EXTERNALIZE = 2,
    pogcvm_ST_NOMINATE = 3
};

struct pogcvmNomination
{
    Hash quorumSetHash; // D
    Value votes<>;      // X
    Value accepted<>;   // Y
};

struct pogcvmStatement
{
    NodeID nodeID;    // v
    uint64 slotIndex; // i

    union switch (pogcvmStatementType type)
    {
    case pogcvm_ST_PREPARE:
        struct
        {
            Hash quorumSetHash;       // D
            pogcvmBallot ballot;         // b
            pogcvmBallot* prepared;      // p
            pogcvmBallot* preparedPrime; // p'
            uint32 nC;                // c.n
            uint32 nH;                // h.n
        } prepare;
    case pogcvm_ST_CONFIRM:
        struct
        {
            pogcvmBallot ballot;   // b
            uint32 nPrepared;   // p.n
            uint32 nCommit;     // c.n
            uint32 nH;          // h.n
            Hash quorumSetHash; // D
        } confirm;
    case pogcvm_ST_EXTERNALIZE:
        struct
        {
            pogcvmBallot commit;         // c
            uint32 nH;                // h.n
            Hash commitQuorumSetHash; // D used before EXTERNALIZE
        } externalize;
    case pogcvm_ST_NOMINATE:
        pogcvmNomination nominate;
    }
    pledges;
};

struct pogcvmEnvelope
{
    pogcvmStatement statement;
    Signature signature;
};

// supports things like: A,B,C,(D,E,F),(G,H,(I,J,K,L))
// only allows 2 levels of nesting
struct pogcvmQuorumSet
{
    uint32 threshold;
    NodeID validators<>;
    pogcvmQuorumSet innerSets<>;
};
}
