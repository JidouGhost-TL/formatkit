use super::{f, AlphaMode, GltfBuilder, GltfError, ImageRecord, MaterialKey, MaterialOptions};
use crate::json::Json;
#[cfg(feature = "png")]
use formatkit_codec::png::{encode_rgba_png, encode_rgba_png_with, PngEncodeOptions};
#[cfg(feature = "png")]
use formatkit_core::Image;

impl GltfBuilder {
    #[cfg(feature = "png")]
    fn ensure_sampler(&mut self) -> usize {
        if let Some(s) = self.sampler {
            return s;
        }
        let idx = self.add_sampler(Some(9728), Some(9728), 10497, 10497);
        self.sampler = Some(idx);
        idx
    }

    /// Add an explicit texture sampler with glTF/WebGL filter and wrap enums.
    pub fn add_sampler(
        &mut self,
        mag_filter: Option<u32>,
        min_filter: Option<u32>,
        wrap_s: u32,
        wrap_t: u32,
    ) -> usize {
        let mut fields = Vec::new();
        if let Some(mag) = mag_filter {
            fields.push(("magFilter", Json::UInt(u64::from(mag))));
        }
        if let Some(min) = min_filter {
            fields.push(("minFilter", Json::UInt(u64::from(min))));
        }
        fields.push(("wrapS", Json::UInt(u64::from(wrap_s))));
        fields.push(("wrapT", Json::UInt(u64::from(wrap_t))));
        self.samplers.push(Json::Obj(fields));
        self.samplers.len() - 1
    }

    /// Embed pre-encoded image bytes (such as PNG or JPEG) in the binary buffer
    /// and return its image index.
    pub fn add_encoded_image(&mut self, mime_type: &str, bytes: &[u8]) -> usize {
        let view = self.add_view(bytes, None);
        let offset = self.buffer.len() - bytes.len();
        self.image_records.push(ImageRecord::Embedded {
            offset,
            len: bytes.len(),
            mime_type: mime_type.to_string(),
        });
        self.images.push(Json::Obj(vec![
            ("mimeType", Json::Str(mime_type.to_string())),
            ("bufferView", Json::UInt(view as u64)),
        ]));
        self.images.len() - 1
    }

    /// Reference an external image by URI (without embedding bytes in the
    /// binary buffer) and return its image index.
    pub fn add_external_image(&mut self, uri: &str, mime_type: Option<&str>) -> usize {
        self.image_records.push(ImageRecord::External {
            uri: uri.to_string(),
            mime_type: mime_type.map(ToString::to_string),
        });
        let mut fields = vec![("uri", Json::Str(uri.to_string()))];
        if let Some(mime) = mime_type {
            fields.push(("mimeType", Json::Str(mime.to_string())));
        }
        self.images.push(Json::Obj(fields));
        self.images.len() - 1
    }

    /// Encode an RGBA8 [`Image`] as PNG using [`encode_rgba_png`] and embed it
    /// in the binary buffer, returning its image index.
    #[cfg(feature = "png")]
    pub fn add_png_image(&mut self, image: &Image) -> Result<usize, GltfError> {
        let png = encode_rgba_png(image, usize::MAX)
            .map_err(|err| GltfError::ImageEncode(err.to_string()))?;
        Ok(self.add_encoded_image("image/png", &png))
    }

    /// Encode an RGBA8 [`Image`] as PNG using [`encode_rgba_png_with`] and
    /// embed it in the binary buffer, returning its image index.
    #[cfg(feature = "png")]
    pub fn add_png_image_with(
        &mut self,
        image: &Image,
        options: &PngEncodeOptions,
    ) -> Result<usize, GltfError> {
        let png = encode_rgba_png_with(image, usize::MAX, options)
            .map_err(|err| GltfError::ImageEncode(err.to_string()))?;
        Ok(self.add_encoded_image("image/png", &png))
    }

    /// Add a texture referencing `source` (image index) and optional `sampler`
    /// index, returning its texture index.
    pub fn add_texture(&mut self, source: usize, sampler: Option<usize>) -> usize {
        let mut fields = Vec::new();
        if let Some(s) = sampler {
            fields.push(("sampler", Json::UInt(s as u64)));
        }
        fields.push(("source", Json::UInt(source as u64)));
        self.textures.push(Json::Obj(fields));
        self.textures.len() - 1
    }

    /// Add a textured material referencing an existing `texture` index with
    /// explicit [`MaterialOptions`].
    pub fn add_textured_material(
        &mut self,
        name: &str,
        texture: usize,
        options: MaterialOptions,
    ) -> Result<usize, GltfError> {
        validate_material_options(options)?;
        if options.unlit {
            self.uses_unlit = true;
        }
        let mut fields = vec![
            ("name", Json::Str(name.to_string())),
            (
                "pbrMetallicRoughness",
                Json::Obj(vec![
                    (
                        "baseColorTexture",
                        Json::Obj(vec![("index", Json::UInt(texture as u64))]),
                    ),
                    ("metallicFactor", Json::Num(0.0)),
                    ("roughnessFactor", Json::Num(1.0)),
                ]),
            ),
        ];
        append_material_options(&mut fields, options);
        self.materials.push(Json::Obj(fields));
        Ok(self.materials.len() - 1)
    }

    /// The shared solid (vertex-coloured) material for untextured faces.
    pub fn solid_material(&mut self) -> usize {
        if let Some(i) = self.solid_material {
            return i;
        }
        let idx = self
            .solid_material_with(MaterialOptions {
                double_sided: true,
                ..MaterialOptions::default()
            })
            .expect("the built-in solid material is valid");
        self.solid_material = Some(idx);
        idx
    }

    /// Add or reuse an untextured material with explicit culling, alpha, and
    /// unlit behavior. Unlike [`GltfBuilder::solid_material`], this uses
    /// exactly the supplied render state instead of forcing double-sided.
    pub fn solid_material_with(&mut self, options: MaterialOptions) -> Result<usize, GltfError> {
        validate_material_options(options)?;
        let key = MaterialKey::from(options);
        if let Some(&idx) = self.configured_solid_material.get(&key) {
            return Ok(idx);
        }
        if options.unlit {
            self.uses_unlit = true;
        }
        let mut fields = vec![
            ("name", Json::Str("solid".to_string())),
            (
                "pbrMetallicRoughness",
                Json::Obj(vec![
                    (
                        "baseColorFactor",
                        Json::Arr(vec![f(1.0), f(1.0), f(1.0), f(1.0)]),
                    ),
                    ("metallicFactor", Json::Num(0.0)),
                    ("roughnessFactor", Json::Num(1.0)),
                ]),
            ),
        ];
        append_material_options(&mut fields, options);
        self.materials.push(Json::Obj(fields));
        let idx = self.materials.len() - 1;
        self.configured_solid_material.insert(key, idx);
        Ok(idx)
    }

    /// Add an untextured material with a caller-supplied base colour.
    pub fn color_material(&mut self, name: &str, color: [f32; 4]) -> usize {
        self.materials.push(Json::Obj(vec![
            ("name", Json::Str(name.to_string())),
            (
                "pbrMetallicRoughness",
                Json::Obj(vec![
                    (
                        "baseColorFactor",
                        Json::Arr(color.into_iter().map(f).collect()),
                    ),
                    ("metallicFactor", Json::Num(0.0)),
                    ("roughnessFactor", Json::Num(1.0)),
                ]),
            ),
            ("doubleSided", Json::Bool(true)),
        ]));
        self.materials.len() - 1
    }

    /// A cached textured material keyed by `(texture_id, palette_id)`; the
    /// image is encoded as PNG and embedded as a buffer view. Repeated keys
    /// return the cached material.
    #[cfg(feature = "png")]
    pub fn textured_material(&mut self, key: (u16, u16), image: &Image) -> usize {
        if let Some(&i) = self.texture_material.get(&key) {
            return i;
        }
        let idx = self
            .textured_material_with(
                key,
                image,
                MaterialOptions {
                    double_sided: true,
                    alpha_mode: AlphaMode::Mask,
                    alpha_cutoff: 0.5,
                    unlit: false,
                },
            )
            .expect("valid image and built-in textured material options");
        self.texture_material.insert(key, idx);
        idx
    }

    /// Add or reuse a textured material with explicit culling, alpha, and unlit
    /// behavior. The texture image is encoded via [`encode_rgba_png`] and
    /// embedded in the binary buffer.
    #[cfg(feature = "png")]
    pub fn textured_material_with(
        &mut self,
        key: (u16, u16),
        image: &Image,
        options: MaterialOptions,
    ) -> Result<usize, GltfError> {
        validate_material_options(options)?;
        let material_key = MaterialKey::from(options);
        if let Some(&idx) = self
            .configured_texture_material
            .get(&(key.0, key.1, material_key))
        {
            return Ok(idx);
        }
        let sampler = self.ensure_sampler();
        let image_idx = self.add_png_image(image)?;
        let tex_idx = self.add_texture(image_idx, Some(sampler));
        let mat_idx =
            self.add_textured_material(&format!("tex_{}_{}", key.0, key.1), tex_idx, options)?;
        self.configured_texture_material
            .insert((key.0, key.1, material_key), mat_idx);
        Ok(mat_idx)
    }
}

fn append_material_options(fields: &mut Vec<(&'static str, Json)>, options: MaterialOptions) {
    if options.alpha_mode != AlphaMode::Opaque {
        fields.push((
            "alphaMode",
            Json::Str(options.alpha_mode.as_str().to_string()),
        ));
    }
    if options.alpha_mode == AlphaMode::Mask {
        fields.push(("alphaCutoff", f(options.alpha_cutoff)));
    }
    if options.double_sided {
        fields.push(("doubleSided", Json::Bool(true)));
    }
    if options.unlit {
        fields.push((
            "extensions",
            Json::Obj(vec![("KHR_materials_unlit", Json::Obj(Vec::new()))]),
        ));
    }
}

fn validate_material_options(options: MaterialOptions) -> Result<(), GltfError> {
    if options.alpha_mode == AlphaMode::Mask && !options.alpha_cutoff.is_finite() {
        return Err(GltfError::NonFinite("material alpha cutoff"));
    }
    Ok(())
}
