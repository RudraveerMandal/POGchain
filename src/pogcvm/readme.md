# pogcvm (POGchain Validation Protocol)

The pogcvm subsystem is an abstract implementation of pogcvm, a protocol for federated
byzantine agreement, intended to drive a distributed system built around the
"replicated state machine" formalism. pogcvm is defined without reference to any
particular interpretation of the concepts of "slot" or "value", nor any
particular network communication system or replicated state machine.

This separation from the rest of the system is intended to make the
implementation of pogcvm easier to model, compare to the paper describing the
protocol, audit for correctness, and extract for reuse in different programs at
a later date.

The [pogcvmDriver class](pogcvmDriver.h) should be subclassed by any module wishing to
implement validation using the pogcvm protocol, implementing the necessary abstract
methods for handling pogcvm-generated events, and calling methods from the central
[pogcvm base-class](pogcvm.h) methods to receive incoming messages.
The messages making up the protocol are defined in XDR,
in the file [POGchain-pogcvm.x](../xdr/POGchain-pogcvm.x), however, library users are
most likely to want to modify [`POGchain-types.x`](../xdr/POGchain-types.x),
which contains all the base types used through the implementation
(such as the hash type, or the `NodeID` type, used to represent a node's identity).


The `POGchain` program has a single subclass of pogcvmDriver called
[Herder](../herder), which gives a specific interpretation to "slot" and
"value", and connects pogcvm up with a specific broadcast communication medium
([Overlay](../overlay)) and specific replicated state machine
([LedgerManager](../ledger)).

For details of the protocol itself, see the [paper on pogcvm](https://www.POGchain.org/papers/POGchain-validation-protocol.pdf).
