use formatkit_catalog::Resolution as CatalogResolution;
use formatkit_core::{
    Error, IndexedNamespace, MountedMember, MountedMembers, NamespaceTraversalContext, Result,
    WorkBudget, WorkResource,
};

/// Scoped continuation used by an injected resolver. Identification metadata
/// may be omitted for already-mounted namespaces.
pub type ResolutionVisitor<'a> = dyn FnMut(Resolution<'_>, Option<&CatalogResolution<'_>>, &mut WorkBudget) -> Result<WalkControl>
    + 'a;

/// Backpressure for synchronous event delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkControl {
    Continue,
    /// On a member, identification or resolution event, omit member descent.
    Skip,
    Stop,
}

/// The result of resolving one member. No catalog or owner is implicit.
pub enum Resolution<'a> {
    Miss,
    Unsupported,
    RecognitionOnly,
    RequiresInputs,
    Ambiguous,
    /// An owner explicitly classified a grammar/content failure after excluding
    /// source access, integrity, cancellation and resource failures. Arbitrary
    /// resolver errors are terminal, even when malformed-content recovery is on.
    InvalidContent {
        error: Error,
    },
    Mounted {
        namespace: &'a dyn IndexedNamespace,
        /// Optional authenticated logical-view AND operation identity. Do not
        /// use a display name or offset alone. Matching ancestors stop descent.
        ancestor_key: Option<&'a str>,
    },
}

/// Inject operation selection and contextual authentication without transferring
/// lifetime-bearing mounts into a traversal queue.
///
/// Invoke `visit` exactly once on success, with the original ledger (or a bridge
/// to it) while the mounted namespace and all residency reservations remain
/// live. Supply optional canonical catalog identification alongside the outcome;
/// selected candidates, evidence and ambiguity remain borrowed without reprobes.
/// Propagate the continuation's result unchanged. On failure the continuation
/// returns an opaque stop error while the walker retains the original typed
/// cause; replacing or swallowing that stop error cannot hide the cause.
/// Owned, borrowed, and runner-scoped mounts use this same contract.
/// Resolution errors must preserve
/// their typed cause; do not retry cancellation, source changes or resource
/// failures through another recognizer. The resolver is shared immutably so
/// nested resolution can use the same catalog without holding a mutable borrow.
pub trait Resolver {
    fn resolve(
        &self,
        member: MountedMember<'_>,
        context: Option<&NamespaceTraversalContext>,
        budget: &mut WorkBudget,
        visit: &mut ResolutionVisitor<'_>,
    ) -> Result<WalkControl>;
}

/// Borrowed events are delivered immediately; no names, members or mounts are
/// cloned. Depth counts namespace boundaries, with the root at one.
pub enum WalkEvent<'a> {
    Namespace {
        namespace: &'a dyn IndexedNamespace,
        depth: usize,
    },
    Member {
        member: MountedMember<'a>,
        depth: usize,
    },
    Identification {
        member: MountedMember<'a>,
        identification: &'a CatalogResolution<'a>,
        depth: usize,
    },
    Resolution {
        member: MountedMember<'a>,
        resolution: &'a Resolution<'a>,
        identification: Option<&'a CatalogResolution<'a>>,
        depth: usize,
    },
    Cycle {
        member: MountedMember<'a>,
        depth: usize,
    },
    Limit {
        /// `None` when admission failed at a namespace boundary.
        member: Option<MountedMember<'a>>,
        error: &'a Error,
        depth: usize,
    },
    Failure {
        member: MountedMember<'a>,
        error: &'a Error,
        depth: usize,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct WalkOptions {
    /// Namespace depth, root included. Must be in 1..=128 to bound the native
    /// recursion stack even when aggregate ledger limits are unlimited.
    pub max_depth: usize,
    /// Opt in to reporting and skipping explicit `InvalidContent` outcomes.
    /// Arbitrary resolver errors always terminate, including `Malformed` errors
    /// from source I/O or verification. The owner must classify corruption before
    /// using this outcome. Typed source, cancellation and resource failures
    /// still terminate if incorrectly submitted as invalid content.
    /// Ordinary misses and unsupported outcomes are successful events instead.
    pub continue_on_malformed: bool,
}

impl Default for WalkOptions {
    fn default() -> Self {
        Self {
            max_depth: 32,
            continue_on_malformed: false,
        }
    }
}

struct Ancestor<'a> {
    key: Option<&'a str>,
    parent: Option<&'a Ancestor<'a>>,
}

impl Ancestor<'_> {
    fn contains(&self, key: &str) -> bool {
        let mut next = Some(self);
        while let Some(ancestor) = next {
            if ancestor.key == Some(key) {
                return true;
            }
            next = ancestor.parent;
        }
        false
    }
}

/// Walk depth first with incremental events and a shared work ledger.
///
/// Members are charged when visited and namespaces when entered, in addition to
/// any owner mount work. `Skip` on a namespace omits its members. A depth limit
/// terminates before entering another namespace, and callback `Stop` releases
/// child scopes immediately. Context is inherited through `traversal_context`;
/// the resolver must authenticate any capabilities it uses. No semantic view is
/// implicitly substituted for stored/content bytes.
pub fn walk(
    namespace: &dyn IndexedNamespace,
    resolver: &impl Resolver,
    inherited: Option<&NamespaceTraversalContext>,
    budget: &mut WorkBudget,
    options: WalkOptions,
    mut event: impl FnMut(WalkEvent<'_>) -> WalkControl,
) -> Result<WalkControl> {
    if !(1..=128).contains(&options.max_depth) {
        return Err(Error::InvalidField {
            what: "walk maximum depth (1..=128)",
            value: options.max_depth as u64,
        });
    }
    Walker {
        resolver,
        options,
        event: &mut event,
    }
    .namespace(
        namespace,
        inherited,
        budget,
        1,
        &Ancestor {
            key: None,
            parent: None,
        },
    )
}

struct Walker<'a, R, F> {
    resolver: &'a R,
    options: WalkOptions,
    event: &'a mut F,
}

impl<R: Resolver, F: FnMut(WalkEvent<'_>) -> WalkControl> Walker<'_, R, F> {
    fn namespace(
        &mut self,
        namespace: &dyn IndexedNamespace,
        inherited: Option<&NamespaceTraversalContext>,
        budget: &mut WorkBudget,
        depth: usize,
        ancestors: &Ancestor<'_>,
    ) -> Result<WalkControl> {
        budget.check_cancelled()?;
        let mut scope = budget.enter_depth().inspect_err(|error| {
            self.limit(error, None, depth);
        })?;
        let budget = &mut *scope;
        budget.charge(WorkResource::Nodes, 1).inspect_err(|error| {
            self.limit(error, None, depth);
        })?;
        match (self.event)(WalkEvent::Namespace { namespace, depth }) {
            WalkControl::Stop => return Ok(WalkControl::Stop),
            WalkControl::Skip => return Ok(WalkControl::Continue),
            WalkControl::Continue => {}
        }
        let context = namespace.traversal_context(inherited);
        for member in MountedMembers::new(namespace) {
            budget.check_cancelled()?;
            budget
                .charge(WorkResource::Members, 1)
                .inspect_err(|error| {
                    self.limit(error, Some(member), depth);
                })?;
            match (self.event)(WalkEvent::Member { member, depth }) {
                WalkControl::Stop => return Ok(WalkControl::Stop),
                WalkControl::Skip => continue,
                WalkControl::Continue => {}
            }
            let resolver = self.resolver;
            let mut called = false;
            let mut continuation_error = None;
            let mut delivered = WalkControl::Continue;
            // A zero-byte canonical permit authenticates the ledger supplied
            // to the continuation without reserving payload memory.
            let mut continuity = budget.retain_resident(0)?;
            let result = resolver.resolve(
                member,
                context.as_ref(),
                budget,
                &mut |resolution, identification, budget| {
                    if called {
                        continuation_error.get_or_insert_with(|| {
                            Error::Malformed("resolver invoked continuation twice".into())
                        });
                        return Err(Error::Unsupported("walk continuation failed".into()));
                    }
                    called = true;
                    let result = continuity.resize(budget, 0).and_then(|()| {
                        self.resolved(
                            member,
                            (resolution, identification),
                            context.as_ref(),
                            budget,
                            depth,
                            ancestors,
                        )
                    });
                    match result {
                        Ok(control) => {
                            delivered = control;
                            Ok(control)
                        }
                        Err(error) => {
                            continuation_error = Some(error);
                            Err(Error::Unsupported("walk continuation failed".into()))
                        }
                    }
                },
            );
            if let Some(error) = continuation_error {
                return Err(error);
            }
            match result {
                Ok(control) if !called || control != delivered => {
                    return Err(Error::Malformed(
                        "resolver did not preserve continuation result".into(),
                    ));
                }
                Ok(WalkControl::Stop) => return Ok(WalkControl::Stop),
                Ok(_) => {}
                Err(error) => {
                    if matches!(error.leaf(), Error::ResourceLimit { .. }) {
                        (self.event)(WalkEvent::Limit {
                            member: Some(member),
                            error: &error,
                            depth,
                        });
                    } else {
                        (self.event)(WalkEvent::Failure {
                            member,
                            error: &error,
                            depth,
                        });
                    }
                    return Err(error);
                }
            }
        }
        budget.check_cancelled()?;
        Ok(WalkControl::Continue)
    }

    fn resolved(
        &mut self,
        member: MountedMember<'_>,
        resolved: (Resolution<'_>, Option<&CatalogResolution<'_>>),
        context: Option<&NamespaceTraversalContext>,
        budget: &mut WorkBudget,
        depth: usize,
        ancestors: &Ancestor<'_>,
    ) -> Result<WalkControl> {
        let (resolution, identification) = resolved;
        budget.check_cancelled()?;
        let invalid = matches!(resolution, Resolution::InvalidContent { .. });
        let mut requested_control = WalkControl::Continue;
        if let Some(identification) = identification {
            match (self.event)(WalkEvent::Identification {
                member,
                identification,
                depth,
            }) {
                control @ (WalkControl::Stop | WalkControl::Skip) if invalid => {
                    requested_control = control
                }
                WalkControl::Stop => return Ok(WalkControl::Stop),
                WalkControl::Skip => return Ok(WalkControl::Continue),
                WalkControl::Continue => {}
            }
        }
        match (self.event)(WalkEvent::Resolution {
            member,
            resolution: &resolution,
            identification,
            depth,
        }) {
            control @ (WalkControl::Stop | WalkControl::Skip) if invalid => {
                if requested_control != WalkControl::Stop {
                    requested_control = control;
                }
            }
            WalkControl::Stop => return Ok(WalkControl::Stop),
            WalkControl::Skip => return Ok(WalkControl::Continue),
            WalkControl::Continue => {}
        }
        if let Resolution::InvalidContent { error } = resolution {
            let fatal = matches!(
                error.leaf(),
                Error::Cancelled
                    | Error::ResourceLimit { .. }
                    | Error::SourceIdentityChanged { .. }
                    | Error::SourceRangeOutside { .. }
                    | Error::Unsupported(_)
                    | Error::UnsupportedDialect { .. }
            );
            let control = if matches!(error.leaf(), Error::ResourceLimit { .. }) {
                (self.event)(WalkEvent::Limit {
                    member: Some(member),
                    error: &error,
                    depth,
                })
            } else {
                (self.event)(WalkEvent::Failure {
                    member,
                    error: &error,
                    depth,
                })
            };
            if fatal || !self.options.continue_on_malformed {
                return Err(error);
            }
            return Ok(
                if control == WalkControl::Stop || requested_control == WalkControl::Stop {
                    WalkControl::Stop
                } else {
                    WalkControl::Continue
                },
            );
        }
        if let Resolution::Mounted {
            namespace,
            ancestor_key,
        } = resolution
        {
            if ancestor_key.is_some_and(|key| ancestors.contains(key)) {
                return Ok(match (self.event)(WalkEvent::Cycle { member, depth }) {
                    WalkControl::Stop => WalkControl::Stop,
                    _ => WalkControl::Continue,
                });
            }
            if depth >= self.options.max_depth {
                let error = Error::ResourceLimit {
                    resource: "walk namespace depth",
                    requested: depth as u64 + 1,
                    limit: self.options.max_depth as u64,
                };
                (self.event)(WalkEvent::Limit {
                    member: Some(member),
                    error: &error,
                    depth,
                });
                return Err(error);
            }
            self.namespace(
                namespace,
                context,
                budget,
                depth + 1,
                &Ancestor {
                    key: ancestor_key,
                    parent: Some(ancestors),
                },
            )
        } else {
            Ok(WalkControl::Continue)
        }
    }

    fn limit(&mut self, error: &Error, member: Option<MountedMember<'_>>, depth: usize) {
        if matches!(error.leaf(), Error::ResourceLimit { .. }) {
            (self.event)(WalkEvent::Limit {
                member,
                error,
                depth,
            });
        }
    }
}
