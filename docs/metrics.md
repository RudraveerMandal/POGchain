---
title: List of metrics exposed by POGchain
---

POGchain uses libmedida for computing metrics, a detailed description can
be found at http://dln.github.io/medida/

### Counters (`NewCounter`)
Tracks a value in absolute terms of a base unit.

### Histograms (`NewHistogram`)
Tracks aggregates (count, min, max, mean, percentiles, etc) for samples
expressed in arbitrary base unit.

### Timers (`NewTimer`)
Tracks aggregates (count, min, max, mean, percentiles, etc) of samples expressed in units of time.

### Meters (`NewMeter`)
Tracks aggregates (count, min, max, mean, etc),  rate (1m, 5m, 15m) for samples
expressed in base unit.

### Buckets (`NewBuckets`)
Tracks multiple timers organized into disjoint buckets.

Metric name                              | Type      | Description
---------------------------------------  | --------  | --------------------
app.post-on-background-thread.delay      | timer     | time to start task posted to background thread
app.post-on-main-thread.delay            | timer     | time to start task posted to current crank of main thread
bucket.batch.addtime                     | timer     | time to add a batch
bucket.batch.objectsadded                | meter     | number of objects added per batch
bucket.memory.shared                     | counter   | number of buckets referenced (excluding publish queue)
bucket.merge-time.level-<X>              | timer     | time to merge two buckets on level <X>
bucket.snap.merge                        | timer     | time to merge two buckets
herder.pending-txs.age0                  | counter   | number of gen0 pending transactions
herder.pending-txs.age1                  | counter   | number of gen1 pending transactions
herder.pending-txs.age2                  | counter   | number of gen2 pending transactions
herder.pending-txs.age3                  | counter   | number of gen3 pending transactions
herder.pending-txs.banned                | counter   | number of transactions that got banned
herder.pending-txs.delay                 | timer     | time for transactions to be included in a ledger
history.check.failure                    | meter     | history archive status checks failed
history.check.success                    | meter     | history archive status checks succeeded
history.publish.failure                  | meter     | published failed
history.publish.success                  | meter     | published completed successfully
history.publish.time                     | timer     | time to successfully publish history
ledger.age.closed                        | bucket    | time between ledgers
ledger.age.current-seconds               | counter   | gap between last close ledger time and current time
ledger.catchup.duration                  | timer     | time between entering LM_CATCHING_UP_STATE and entering LM_SYNCED_STATE
ledger.invariant.failure                 | counter   | number of times invariants failed
ledger.ledger.close                      | timer     | time to close a ledger (excluding validation)
ledger.memory.queued-ledgers             | counter   | number of ledgers queued in memory for replay
ledger.metastream.write                  | timer     | time spent writing data into meta-stream
ledger.operation.apply                   | timer     | time applying an operation
ledger.operation.count                   | histogram | number of operations per ledger
ledger.transaction.apply                 | timer     | time to apply one transaction
ledger.transaction.count                 | histogram | number of transactions per ledger
ledger.transaction.internal-error        | counter   | number of internal errors since start
loadgen.account.created                  | meter     | loadgenerator: account created
loadgen.payment.native                   | meter     | loadgenerator: native payment submitted
loadgen.pretend.submitted                | meter     | loadgenerator: pretend ops submitted
loadgen.run.complete                     | meter     | loadgenerator: run complete
loadgen.step.count                       | meter     | loadgenerator: generated some transactions
loadgen.step.submit                      | timer     | loadgenerator: time spent submiting transactions per step
loadgen.txn.attempted                    | meter     | loadgenerator: transaction submitted
loadgen.txn.bytes                        | meter     | loadgenerator: size of transactions submitted
loadgen.txn.rejected                     | meter     | loadgenerator: transaction rejected
overlay.byte.read                        | meter     | number of bytes received
overlay.byte.write                       | meter     | number of bytes sent
overlay.async.read                       | meter     | number of async read requests issued
overlay.async.write                      | meter     | number of async write requests issued
overlay.connection.authenticated         | counter   | number of authenticated peers
overlay.connection.latency               | timer     | estimated latency between peers
overlay.connection.pending               | counter   | number of pending connections
overlay.delay.async-write                | timer     | time between each message's async write issue and completion
overlay.delay.write-queue                | timer     | time between each message's entry and exit from peer write queue
overlay.error.read                       | meter     | error while receiving a message
overlay.error.write                      | meter     | error while sending a message
overlay.fetch.txset                      | timer     | time to complete fetching of a txset
overlay.fetch.qset                       | timer     | time to complete fetching of a qset
overlay.flood.broadcast                  | meter     | message sent as broadcast per peer
overlay.flood.duplicate_recv             | meter     | number of bytes of flooded messages that have already been received
overlay.flood.unique_recv                | meter     | number of bytes of flooded messages that have not yet been received
overlay.inbound.attempt                  | meter     | inbound connection attempted (accepted on socket)
overlay.inbound.drop                     | meter     | inbound connection dropped
overlay.inbound.establish                | meter     | inbound connection established (added to pending)
overlay.inbound.reject                   | meter     | inbound connection rejected
overlay.item-fetcher.next-peer           | meter     | ask for item past the first one
overlay.memory.flood-known               | counter   | number of known flooded entries
overlay.message.broadcast                | meter     | message broadcasted
overlay.message.read                     | meter     | message received
overlay.message.write                    | meter     | message sent
overlay.message.drop                     | meter     | message dropped due to load-shedding
overlay.outbound.attempt                 | meter     | outbound connection attempted (socket opened)
overlay.outbound.cancel                  | meter     | outbound connection cancelled
overlay.outbound.drop                    | meter     | outbound connection dropped
overlay.outbound.establish               | meter     | outbound connection established (added to pending)
overlay.recv.<X>                         | timer     | received message <X>
overlay.send.<X>                         | meter     | sent message <X>
overlay.timeout.idle                     | meter     | idle peer timeout
overlay.recv.survey-request              | timer     | time spent in processing survey request
overlay.recv.survey-response             | timer     | time spent in processing survey response
overlay.send.survey-request              | meter     | sent survey request
overlay.send.survey-response             | meter     | sent survey response
process.action.queue                     | counter   | number of items waiting in internal action-queue
process.action.overloaded                | counter   | 0-or-1 value indicating action-queue overloading
pogcvm.envelope.emit                        | meter     | pogcvm message sent
pogcvm.envelope.invalidsig                  | meter     | envelope failed signature verification
pogcvm.envelope.receive                     | meter     | pogcvm message received
pogcvm.envelope.sign                        | meter     | envelope signed
pogcvm.envelope.validsig                    | meter     | envelope signature verified
pogcvm.fetch.envelope                       | timer     | time to complete fetching of an envelope
pogcvm.memory.cumulative-statements         | counter   | number of known pogcvm statements known
pogcvm.nomination.combinecandidates         | meter     | number of candidates per call
pogcvm.pending.discarded                    | counter   | number of discarded envelopes
pogcvm.pending.fetching                     | counter   | number of incomplete envelopes
pogcvm.pending.processed                    | counter   | number of already processed envelopes
pogcvm.pending.ready                        | counter   | number of envelopes ready to process
pogcvm.sync.lost                            | meter     | validator lost sync
pogcvm.timeout.nominate                     | meter     | timeouts in nomination
pogcvm.timeout.prepare                      | meter     | timeouts in ballot protocol
pogcvm.timing.nominated                     | timer     | time spent in nomination
pogcvm.timing.externalized                  | timer     | time spent in ballot protocol
pogcvm.timing.first-to-self-externalize-lag | timer     | delay between first externalize message and local node externalizing
pogcvm.timing.self-to-others-externalize-lag| timer     | delay between local node externalizing and later externalize messages from other nodes
pogcvm.value.invalid                        | meter     | pogcvm value is invalid
pogcvm.value.valid                          | meter     | pogcvm value is valid

