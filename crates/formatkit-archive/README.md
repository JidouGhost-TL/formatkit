# formatkit-archive

Browse existing Formatkit indexed namespaces, select members by index or exact
name, copy stored bytes or validated content to caller-owned writers, and walk
children incrementally through an injected resolver. This crate supplies no
format grammars, recognizers, operation registry, or filesystem policy.

Resolvers keep mounted children alive while calling a continuation with the
same work ledger. This permits both owned mounts and mounts borrowing a resident
reservation, including use of `ResidentReservation::with_budget`. Context is
scoped through the canonical namespace traversal context. The resolver chooses
operations and authenticates contextual inputs; a missing operation or missing
input is distinct from an ordinary recognition miss.

The resolver continuation accepts optional borrowed catalog identification.
Selected candidates, evidence, readiness and ambiguity contenders reach typed
identification and resolution events without a second probe or another identity
model. Already-mounted namespaces may omit this metadata. The walker retains
the original typed continuation failure even if a resolver swallows or replaces
its opaque stop error.

Recovery requires both the caller's `continue_on_malformed` policy and an owner's
explicit `InvalidContent` outcome. Arbitrary resolver errors always terminate:
source access and verification errors cannot be classified by inspecting their
error variant. Owners must distinguish those failures from grammar corruption
before selecting a recoverable outcome.

Traversal callbacks receive borrowed events synchronously. `Skip` on a member
filters descent, and `Stop` releases traversal state immediately. No event queue
or collection is allocated. The caller supplies a finite namespace depth cap;
the existing work budget also bounds aggregate nodes, members, reads, output,
materialization, residency and depth. Owners remain responsible for accounting
mount allocations and retaining permits with content sources. Stable ancestor
keys are optional and must identify the validated logical view and operation;
without a key, depth and work limits still bound descent.

Extraction uses a caller-owned transfer buffer and writer. Successful writes
are charged exactly, including progress before a sink failure. Errors may leave
partial output. Staging, collision handling, flushing and publication belong to
the caller. Stored extraction never implicitly opens transformed or semantic
content.
