#pragma once

// Copyright 2019 POGchain Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

// This structure just exists to cache frequently-accessed, overlay-wide
// (non-peer-specific) metrics.

namespace medida
{
class Timer;
class Meter;
class Counter;
}

namespace POGchain
{

class Application;

struct OverlayMetrics
{
    OverlayMetrics(Application& app);
    medida::Meter& mMessageRead;
    medida::Meter& mMessageWrite;
    medida::Meter& mMessageDrop;
    medida::Meter& mAsyncRead;
    medida::Meter& mAsyncWrite;
    medida::Meter& mByteRead;
    medida::Meter& mByteWrite;
    medida::Meter& mErrorRead;
    medida::Meter& mErrorWrite;
    medida::Meter& mTimeoutIdle;
    medida::Meter& mTimeoutStraggler;
    medida::Timer& mConnectionLatencyTimer;

    medida::Meter& mItemFetcherNextPeer;

    medida::Timer& mRecvErrorTimer;
    medida::Timer& mRecvHelloTimer;
    medida::Timer& mRecvAuthTimer;
    medida::Timer& mRecvDontHaveTimer;
    medida::Timer& mRecvGetPeersTimer;
    medida::Timer& mRecvPeersTimer;
    medida::Timer& mRecvGetTxSetTimer;
    medida::Timer& mRecvTxSetTimer;
    medida::Timer& mRecvTransactionTimer;
    medida::Timer& mRecvGetpogcvmQuorumSetTimer;
    medida::Timer& mRecvpogcvmQuorumSetTimer;
    medida::Timer& mRecvpogcvmMessageTimer;
    medida::Timer& mRecvGetpogcvmStateTimer;

    medida::Timer& mRecvpogcvmPrepareTimer;
    medida::Timer& mRecvpogcvmConfirmTimer;
    medida::Timer& mRecvpogcvmNominateTimer;
    medida::Timer& mRecvpogcvmExternalizeTimer;

    medida::Timer& mRecvSurveyRequestTimer;
    medida::Timer& mRecvSurveyResponseTimer;

    medida::Timer& mMessageDelayInWriteQueueTimer;
    medida::Timer& mMessageDelayInAsyncWriteTimer;

    medida::Meter& mSendErrorMeter;
    medida::Meter& mSendHelloMeter;
    medida::Meter& mSendAuthMeter;
    medida::Meter& mSendDontHaveMeter;
    medida::Meter& mSendGetPeersMeter;
    medida::Meter& mSendPeersMeter;
    medida::Meter& mSendGetTxSetMeter;
    medida::Meter& mSendTransactionMeter;
    medida::Meter& mSendTxSetMeter;
    medida::Meter& mSendGetpogcvmQuorumSetMeter;
    medida::Meter& mSendpogcvmQuorumSetMeter;
    medida::Meter& mSendpogcvmMessageSetMeter;
    medida::Meter& mSendGetpogcvmStateMeter;

    medida::Meter& mSendSurveyRequestMeter;
    medida::Meter& mSendSurveyResponseMeter;

    medida::Meter& mMessagesBroadcast;
    medida::Counter& mPendingPeersSize;
    medida::Counter& mAuthenticatedPeersSize;

    medida::Meter& mUniqueFloodBytesRecv;
    medida::Meter& mDuplicateFloodBytesRecv;
    medida::Meter& mUniqueFetchBytesRecv;
    medida::Meter& mDuplicateFetchBytesRecv;
};
}
