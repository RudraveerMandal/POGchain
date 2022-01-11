#pragma once

// Copyright 2014 POGchain Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include <memory>
#include <set>
#include <vector>

#include "lib/json/json-forwards.h"
#include "pogcvm/pogcvmDriver.h"
#include "util/HashOfHash.h"

namespace POGchain
{
/**
 * This is one Node in the POGchain network
 */
class LocalNode
{
  protected:
    const NodeID mNodeID;
    const bool mIsValidator;
    pogcvmQuorumSet mQSet;
    Hash mQSetHash;

    // alternative qset used during externalize {{mNodeID}}
    Hash gSingleQSetHash;                      // hash of the singleton qset
    std::shared_ptr<pogcvmQuorumSet> mSingleQSet; // {{mNodeID}}

    pogcvmDriver& mDriver;

  public:
    LocalNode(NodeID const& nodeID, bool isValidator, pogcvmQuorumSet const& qSet,
              pogcvmDriver& driver);

    NodeID const& getNodeID();

    void updateQuorumSet(pogcvmQuorumSet const& qSet);

    pogcvmQuorumSet const& getQuorumSet();
    Hash const& getQuorumSetHash();
    bool isValidator();

    // returns the quorum set {{X}}
    static pogcvmQuorumSetPtr getSingletonQSet(NodeID const& nodeID);

    // runs proc over all nodes contained in qset, but fast fails if proc fails
    static bool forAllNodes(pogcvmQuorumSet const& qset,
                            std::function<bool(NodeID const&)> proc);

    // returns the weight of the node within the qset
    // normalized between 0-UINT64_MAX
    static uint64 getNodeWeight(NodeID const& nodeID, pogcvmQuorumSet const& qset);

    // Tests this node against nodeSet for the specified qSethash.
    static bool isQuorumSlice(pogcvmQuorumSet const& qSet,
                              std::vector<NodeID> const& nodeSet);
    static bool isVBlocking(pogcvmQuorumSet const& qSet,
                            std::vector<NodeID> const& nodeSet);

    // Tests this node against a map of nodeID -> T for the specified qSetHash.

    // `isVBlocking` tests if the filtered nodes V are a v-blocking set for
    // this node.
    static bool isVBlocking(
        pogcvmQuorumSet const& qSet,
        std::map<NodeID, pogcvmEnvelopeWrapperPtr> const& map,
        std::function<bool(pogcvmStatement const&)> const& filter =
            [](pogcvmStatement const&) { return true; });

    // `isQuorum` tests if the filtered nodes V form a quorum
    // (meaning for each v \in V there is q \in Q(v)
    // included in V and we have quorum on V for qSetHash). `qfun` extracts the
    // pogcvmQuorumSetPtr from the pogcvmStatement for its associated node in map
    // (required for transitivity)
    static bool isQuorum(
        pogcvmQuorumSet const& qSet,
        std::map<NodeID, pogcvmEnvelopeWrapperPtr> const& map,
        std::function<pogcvmQuorumSetPtr(pogcvmStatement const&)> const& qfun,
        std::function<bool(pogcvmStatement const&)> const& filter =
            [](pogcvmStatement const&) { return true; });

    // computes the distance to the set of v-blocking sets given
    // a set of nodes that agree (but can fail)
    // excluded, if set will be skipped altogether
    static std::vector<NodeID>
    findClosestVBlocking(pogcvmQuorumSet const& qset,
                         std::set<NodeID> const& nodes, NodeID const* excluded);

    static std::vector<NodeID> findClosestVBlocking(
        pogcvmQuorumSet const& qset,
        std::map<NodeID, pogcvmEnvelopeWrapperPtr> const& map,
        std::function<bool(pogcvmStatement const&)> const& filter =
            [](pogcvmStatement const&) { return true; },
        NodeID const* excluded = nullptr);

    static Json::Value toJson(pogcvmQuorumSet const& qSet,
                              std::function<std::string(NodeID const&)> r);

    Json::Value toJson(pogcvmQuorumSet const& qSet, bool fullKeys) const;
    std::string to_string(pogcvmQuorumSet const& qSet) const;

    static uint64 computeWeight(uint64 m, uint64 total, uint64 threshold);

  protected:
    // returns a quorum set {{ nodeID }}
    static pogcvmQuorumSet buildSingletonQSet(NodeID const& nodeID);

    // called recursively
    static bool isQuorumSliceInternal(pogcvmQuorumSet const& qset,
                                      std::vector<NodeID> const& nodeSet);
    static bool isVBlockingInternal(pogcvmQuorumSet const& qset,
                                    std::vector<NodeID> const& nodeSet);
};
}
