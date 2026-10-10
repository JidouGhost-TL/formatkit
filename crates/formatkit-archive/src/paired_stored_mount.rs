//! Shared mounting sequence for paired indexes whose members are stored ranges.
//!
//! Directory grammars and range policies remain in the owner callback. This
//! module owns only role resolution, source verification, bounded index I/O,
//! and construction of the content-backed namespace.

use formatkit_core::NamespaceEntry as Entry;
use formatkit_core::{Error, IndexedNamespace, ReadBudget, Result, StoredRangeNamespaceLimits};

type ParseIndex = fn(&[u8], u64) -> Result<(Vec<Entry>, Vec<Vec<u8>>)>;
type ParseSelectedIndex = fn(&[u8], &str, u64) -> Result<(Vec<Entry>, Vec<Vec<u8>>)>;

#[derive(Clone, Copy)]
pub struct PairedStoredMount {
    directory_role: &'static str,
    content_role: &'static str,
    max_directory_bytes: u64,
    directory_resource: &'static str,
    parse_index: ParseIndex,
    limits: StoredRangeNamespaceLimits,
}

impl PairedStoredMount {
    pub const fn new(
        directory_role: &'static str,
        content_role: &'static str,
        max_directory_bytes: u64,
        directory_resource: &'static str,
        parse_index: ParseIndex,
        limits: StoredRangeNamespaceLimits,
    ) -> Self {
        Self {
            directory_role,
            content_role,
            max_directory_bytes,
            directory_resource,
            parse_index,
            limits,
        }
    }

    pub fn mount(
        self,
        sources: formatkit_catalog::catalog::PairedNamespaceSources,
        budget: &mut ReadBudget,
    ) -> Result<Box<dyn IndexedNamespace>> {
        let (directory, content) = sources.into_roles(self.directory_role, self.content_role)?;
        mount_sources(
            directory,
            content,
            self.max_directory_bytes,
            self.directory_resource,
            self.parse_index,
            self.limits,
            budget,
        )
    }
}

/// Selected pairs use the same I/O sequence; selector interpretation and all
/// filtering/range policy remain in the owner callback.
pub fn mount_selected(
    sources: formatkit_catalog::catalog::PairedNamespaceSources,
    roles: (&'static str, &'static str, &'static str),
    max_directory_bytes: u64,
    directory_resource: &'static str,
    parse_index: ParseSelectedIndex,
    limits: StoredRangeNamespaceLimits,
    budget: &mut ReadBudget,
) -> Result<Box<dyn IndexedNamespace>> {
    let (directory, content, selector) = sources.into_selected_roles(roles.0, roles.1, roles.2)?;
    mount_sources(
        directory,
        content,
        max_directory_bytes,
        directory_resource,
        |bytes, size| parse_index(bytes, &selector, size),
        limits,
        budget,
    )
}

fn mount_sources(
    directory: std::sync::Arc<dyn formatkit_core::RangeSource>,
    content: std::sync::Arc<dyn formatkit_core::RangeSource>,
    max_directory_bytes: u64,
    directory_resource: &'static str,
    parse_index: impl FnOnce(&[u8], u64) -> Result<(Vec<Entry>, Vec<Vec<u8>>)>,
    limits: StoredRangeNamespaceLimits,
    budget: &mut ReadBudget,
) -> Result<Box<dyn IndexedNamespace>> {
    directory.verify_unchanged()?;
    content.verify_unchanged()?;
    if directory.size() > max_directory_bytes {
        return Err(Error::ResourceLimit {
            resource: directory_resource,
            requested: directory.size(),
            limit: max_directory_bytes,
        });
    }
    let directory_bytes = directory.read_at(0, directory.size(), budget)?;
    let (entries, raw_names) = parse_index(&directory_bytes, content.size())?;
    directory.verify_unchanged()?;
    content.verify_unchanged()?;
    Ok(Box::new(formatkit_core::StoredRangeNamespace::new(
        content,
        entries,
        raw_names.into_iter().map(Some).collect(),
        limits,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use formatkit_core::{MemoryRangeSource, RangeSource, SharedBytes};
    use std::sync::{Arc, Mutex};

    struct EventSource {
        inner: MemoryRangeSource,
        role: &'static str,
        events: Arc<Mutex<Vec<String>>>,
    }

    impl RangeSource for EventSource {
        fn size(&self) -> u64 {
            self.inner.size()
        }

        fn read_at(&self, offset: u64, length: u64, budget: &mut ReadBudget) -> Result<Vec<u8>> {
            self.events
                .lock()
                .unwrap()
                .push(format!("{} read", self.role));
            self.inner.read_at(offset, length, budget)
        }

        fn read_shared_at(
            &self,
            offset: u64,
            length: u64,
            budget: &mut ReadBudget,
        ) -> Result<SharedBytes> {
            self.inner.read_shared_at(offset, length, budget)
        }

        fn describe_coordinate_space(&self) -> formatkit_core::CoordinateSpaceDescription {
            self.inner.describe_coordinate_space()
        }

        fn verify_unchanged(&self) -> Result<()> {
            self.events
                .lock()
                .unwrap()
                .push(format!("{} verify", self.role));
            Ok(())
        }
    }

    fn parse(bytes: &[u8], content_size: u64) -> Result<(Vec<Entry>, Vec<Vec<u8>>)> {
        assert_eq!(bytes, b"D");
        Ok((
            vec![Entry {
                name: Some("x".into()),
                offset: 0,
                size: content_size,
            }],
            vec![b"x".to_vec()],
        ))
    }

    const MOUNT: PairedStoredMount = PairedStoredMount::new(
        "directory",
        "content",
        1,
        "test directory bytes",
        parse,
        StoredRangeNamespaceLimits {
            max_entries: 1,
            max_name_bytes: 1,
            max_total_name_bytes: 2,
        },
    );

    #[test]
    fn sequence_is_role_verify_read_parse_verify_wrap() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let source = |bytes, role| -> Arc<dyn RangeSource> {
            Arc::new(EventSource {
                inner: MemoryRangeSource::new(bytes, role),
                role,
                events: events.clone(),
            })
        };
        let sources = formatkit_catalog::catalog::PairedNamespaceSources::for_input(
            formatkit_catalog::catalog::NamespaceMountInput::PairedSources {
                directory_role: "directory",
                content_role: "content",
            },
            source(b"D".to_vec(), "directory"),
            source(b"BODY".to_vec(), "content"),
        )
        .unwrap();
        let mut budget = ReadBudget::limited(1);
        let mounted = MOUNT.mount(sources, &mut budget).unwrap();
        assert_eq!(budget.spent(), 1);
        assert_eq!(mounted.entries()[0].offset, 0);
        assert_eq!(mounted.entries()[0].size, 4);
        assert_eq!(mounted.raw_name_bytes(0), Some(b"x".as_slice()));
        assert_eq!(
            *events.lock().unwrap(),
            [
                "directory verify",
                "content verify",
                "directory read",
                "directory verify",
                "content verify",
                "content verify"
            ]
        );
    }

    #[test]
    fn cap_fails_after_initial_verification_and_before_read_or_parse() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let source = |bytes, role| -> Arc<dyn RangeSource> {
            Arc::new(EventSource {
                inner: MemoryRangeSource::new(bytes, role),
                role,
                events: events.clone(),
            })
        };
        let sources = formatkit_catalog::catalog::PairedNamespaceSources::for_input(
            formatkit_catalog::catalog::NamespaceMountInput::PairedSources {
                directory_role: "directory",
                content_role: "content",
            },
            source(b"XX".to_vec(), "directory"),
            source(b"BODY".to_vec(), "content"),
        )
        .unwrap();
        let error = MOUNT
            .mount(sources, &mut ReadBudget::unlimited())
            .err()
            .unwrap();
        assert_eq!(
            error,
            Error::ResourceLimit {
                resource: "test directory bytes",
                requested: 2,
                limit: 1,
            }
        );
        assert_eq!(
            *events.lock().unwrap(),
            ["directory verify", "content verify"]
        );
    }

    #[test]
    fn selected_roles_preserve_sequence_selector_and_failure_precedence() {
        for (roles, bytes, budget_limit, parse_failure) in [
            (
                ("directory", "content", "selection"),
                b"D".as_slice(),
                1,
                false,
            ),
            (
                ("content", "directory", "selection"),
                b"D".as_slice(),
                1,
                false,
            ),
            (("directory", "content", "wrong"), b"D".as_slice(), 1, false),
            (
                ("directory", "content", "selection"),
                b"XX".as_slice(),
                2,
                false,
            ),
            (
                ("directory", "content", "selection"),
                b"D".as_slice(),
                0,
                false,
            ),
            (
                ("directory", "content", "selection"),
                b"D".as_slice(),
                1,
                true,
            ),
        ] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let source = |bytes: Vec<u8>, role| -> Arc<dyn RangeSource> {
                Arc::new(EventSource {
                    inner: MemoryRangeSource::new(bytes, role),
                    role,
                    events: events.clone(),
                })
            };
            let sources = formatkit_catalog::catalog::PairedNamespaceSources::for_selected_input(
                formatkit_catalog::catalog::NamespaceMountInput::SelectedPairedSources {
                    directory_role: "directory",
                    content_role: "content",
                    selector_role: "selection",
                },
                source(bytes.to_vec(), "directory"),
                source(b"BODY".to_vec(), "content"),
                "EXACT.PAK",
            )
            .unwrap();
            let mut budget = ReadBudget::limited(budget_limit);
            let result = mount_selected(
                sources,
                roles,
                1,
                "test directory bytes",
                if parse_failure {
                    |_, selector, _| {
                        assert_eq!(selector, "EXACT.PAK");
                        Err(Error::Malformed("owner parse failure".into()))
                    }
                } else {
                    |bytes, selector, size| {
                        assert_eq!(selector, "EXACT.PAK");
                        parse(bytes, size)
                    }
                },
                MOUNT.limits,
                &mut budget,
            );
            let expected = if roles != ("directory", "content", "selection") {
                assert_eq!(result.err().unwrap(), Error::Unsupported(format!(
                    "selected paired namespace roles (\"directory\", \"content\") and selector Some((\"selection\", \"EXACT.PAK\")) do not match required roles ({:?}, {:?}, {:?})",
                    roles.0, roles.1, roles.2,
                )));
                assert_eq!(budget.spent(), 0);
                vec![]
            } else if bytes.len() > 1 {
                assert_eq!(
                    result.err().unwrap(),
                    Error::ResourceLimit {
                        resource: "test directory bytes",
                        requested: 2,
                        limit: 1,
                    }
                );
                assert_eq!(budget.spent(), 0);
                vec!["directory verify", "content verify"]
            } else if budget_limit == 0 || parse_failure {
                if parse_failure {
                    assert_eq!(
                        result.err().unwrap(),
                        Error::Malformed("owner parse failure".into())
                    );
                    assert_eq!(budget.spent(), 1);
                } else {
                    assert!(result.is_err());
                    assert_eq!(budget.spent(), 0);
                }
                vec!["directory verify", "content verify", "directory read"]
            } else {
                let mounted = result.unwrap();
                assert_eq!(mounted.entries()[0].offset, 0);
                assert_eq!(mounted.entries()[0].size, 4);
                assert_eq!(mounted.raw_name_bytes(0), Some(b"x".as_slice()));
                assert_eq!(budget.spent(), 1);
                vec![
                    "directory verify",
                    "content verify",
                    "directory read",
                    "directory verify",
                    "content verify",
                    "content verify",
                ]
            };
            assert_eq!(*events.lock().unwrap(), expected);
        }
    }
}
