use crate::prelude::*;

use super::{f, GltfBuilder, ImageRecord, IDENTITY_MATRIX};
use crate::glb::write_glb;
use crate::json::Json;

/// Result of serializing a glTF 2.0 scene as a `.gltf` JSON document plus
/// external `.bin` buffer and texture image files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GltfSplitOutput {
    /// Compact `.gltf` JSON document.
    pub gltf_json: String,
    /// Binary `.bin` buffer bytes.
    pub bin: Vec<u8>,
    /// External image files `(uri, bytes)` extracted from embedded images.
    pub textures: Vec<(String, Vec<u8>)>,
}

impl GltfBuilder {
    fn build_nodes_json(&self) -> Vec<Json> {
        self.nodes
            .iter()
            .map(|n| {
                let mut fields = Vec::new();
                if let Some(name) = &n.name {
                    fields.push(("name", Json::Str(name.clone())));
                }
                if let Some(m) = n.matrix {
                    if m != IDENTITY_MATRIX {
                        fields.push(("matrix", Json::Arr(m.iter().map(|&x| f(x)).collect())));
                    }
                }
                if let Some(t) = n.translation {
                    fields.push(("translation", Json::Arr(t.iter().map(|&x| f(x)).collect())));
                }
                if let Some(r) = n.rotation {
                    fields.push(("rotation", Json::Arr(r.iter().map(|&x| f(x)).collect())));
                }
                if let Some(s) = n.scale {
                    fields.push(("scale", Json::Arr(s.iter().map(|&x| f(x)).collect())));
                }
                if let Some(mesh) = n.mesh {
                    fields.push(("mesh", Json::UInt(mesh as u64)));
                }
                if let Some(skin) = n.skin {
                    fields.push(("skin", Json::UInt(skin as u64)));
                }
                if !n.children.is_empty() {
                    fields.push((
                        "children",
                        Json::Arr(n.children.iter().map(|&c| Json::UInt(c as u64)).collect()),
                    ));
                }
                Json::Obj(fields)
            })
            .collect()
    }

    fn build_document_json(
        &mut self,
        scene_roots: Vec<usize>,
        images: Vec<Json>,
        bin_uri: Option<&str>,
    ) -> String {
        let nodes_json = self.build_nodes_json();
        let buffer_len = self.buffer.len();
        let generator = self
            .generator
            .take()
            .unwrap_or_else(|| "formatkit-gltf".to_string());
        let mut root = vec![
            (
                "asset",
                Json::Obj(vec![
                    ("version", Json::Str("2.0".to_string())),
                    ("generator", Json::Str(generator)),
                ]),
            ),
            ("scene", Json::UInt(0)),
            (
                "scenes",
                Json::Arr(vec![Json::Obj(vec![(
                    "nodes",
                    Json::Arr(scene_roots.iter().map(|&n| Json::UInt(n as u64)).collect()),
                )])]),
            ),
            ("nodes", Json::Arr(nodes_json)),
        ];
        if self.uses_unlit {
            root.push((
                "extensionsUsed",
                Json::Arr(vec![Json::Str("KHR_materials_unlit".to_string())]),
            ));
        }
        if !self.meshes.is_empty() {
            root.push(("meshes", Json::Arr(core::mem::take(&mut self.meshes))));
        }
        if !self.materials.is_empty() {
            root.push(("materials", Json::Arr(core::mem::take(&mut self.materials))));
        }
        if !self.textures.is_empty() {
            root.push(("textures", Json::Arr(core::mem::take(&mut self.textures))));
        }
        if !images.is_empty() {
            root.push(("images", Json::Arr(images)));
        }
        if !self.samplers.is_empty() {
            root.push(("samplers", Json::Arr(core::mem::take(&mut self.samplers))));
        }
        if !self.animations.is_empty() {
            root.push((
                "animations",
                Json::Arr(core::mem::take(&mut self.animations)),
            ));
        }
        if !self.skins.is_empty() {
            root.push(("skins", Json::Arr(core::mem::take(&mut self.skins))));
        }
        if !self.accessors.is_empty() {
            root.push(("accessors", Json::Arr(core::mem::take(&mut self.accessors))));
        }
        if !self.buffer_views.is_empty() {
            root.push((
                "bufferViews",
                Json::Arr(core::mem::take(&mut self.buffer_views)),
            ));
        }
        let mut buffer_fields = Vec::new();
        if let Some(uri) = bin_uri {
            buffer_fields.push(("uri", Json::Str(uri.to_string())));
        }
        buffer_fields.push(("byteLength", Json::UInt(buffer_len as u64)));
        root.push(("buffers", Json::Arr(vec![Json::Obj(buffer_fields)])));

        Json::Obj(root).to_json_string()
    }

    /// Fallible version of [`GltfBuilder::finish_glb`].
    ///
    /// Returns an error instead of panicking if the serialized GLB exceeds the
    /// 4 GiB `u32` container length limit.
    pub fn try_finish_glb(mut self, scene_roots: Vec<usize>) -> formatkit_core::Result<Vec<u8>> {
        let images = core::mem::take(&mut self.images);
        let json = self.build_document_json(scene_roots, images, None);
        write_glb(json.as_bytes(), Some(&self.buffer))
    }

    /// Serialize to a `.glb` byte vector with `scene_roots` as the default
    /// scene's root nodes.
    #[must_use]
    pub fn finish_glb(self, scene_roots: Vec<usize>) -> Vec<u8> {
        self.try_finish_glb(scene_roots)
            .expect("GLB size fits in u32")
    }

    /// Serialize to a split `.gltf` JSON string, external `.bin` buffer, and
    /// external texture image files.
    #[must_use]
    pub fn finish_split(
        mut self,
        scene_roots: Vec<usize>,
        bin_uri: &str,
        tex_prefix: &str,
    ) -> GltfSplitOutput {
        let sep = if tex_prefix.is_empty() || tex_prefix.ends_with(['_', '-', '/']) {
            ""
        } else {
            "_"
        };
        let mut textures = Vec::new();
        let mut external_images = Vec::with_capacity(self.image_records.len());
        let mut embedded_idx = 0usize;
        for record in &self.image_records {
            match record {
                ImageRecord::Embedded {
                    offset,
                    len,
                    mime_type,
                } => {
                    let ext = match mime_type.as_str() {
                        "image/jpeg" => "jpg",
                        _ => "png",
                    };
                    let uri = format!("{tex_prefix}{sep}{embedded_idx}.{ext}");
                    embedded_idx += 1;
                    let bytes = self.buffer[*offset..*offset + *len].to_vec();
                    textures.push((uri.clone(), bytes));
                    external_images.push(Json::Obj(vec![
                        ("uri", Json::Str(uri)),
                        ("mimeType", Json::Str(mime_type.clone())),
                    ]));
                }
                ImageRecord::External { uri, mime_type } => {
                    let mut fields = vec![("uri", Json::Str(uri.clone()))];
                    if let Some(mime) = mime_type {
                        fields.push(("mimeType", Json::Str(mime.clone())));
                    }
                    external_images.push(Json::Obj(fields));
                }
            }
        }
        self.images.clear();
        let gltf_json = self.build_document_json(scene_roots, external_images, Some(bin_uri));
        GltfSplitOutput {
            gltf_json,
            bin: self.buffer,
            textures,
        }
    }
}
