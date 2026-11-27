use super::{
    AlphaMode, GltfBuilder, GltfError, MaterialOptions, MorphTarget, Prim, PrimExtras,
    IDENTITY_MATRIX,
};
use crate::glb::read_glb;
#[cfg(feature = "png")]
use formatkit_core::Image;

fn glb_json(glb: &[u8]) -> &str {
    let (json, _) = read_glb(glb).unwrap();
    core::str::from_utf8(json).unwrap()
}

fn glb_bin(glb: &[u8]) -> &[u8] {
    let (_, bin) = read_glb(glb).unwrap();
    bin.unwrap()
}

fn triangle(material: usize) -> Prim {
    Prim {
        material,
        positions: vec![[0.0, 0.0, 0.0], [1.0, 0.0, 0.0], [0.0, 1.0, 0.0]],
        normals: vec![[0.0, 0.0, 1.0]; 3],
        uvs: None,
        colors: None,
        joints: Some(vec![[0, 1, 2, 3]; 3]),
        weights: Some(vec![[0.4, 0.3, 0.2, 0.1]; 3]),
        indices: vec![0, 1, 2],
    }
}

#[test]
fn triangle_glb_round_trips_through_read_glb() {
    let mut builder = GltfBuilder::new();
    let mat = builder.solid_material();
    let mesh = builder.add_mesh(vec![triangle(mat)]);
    let node = builder.add_node(Some("tri".to_string()), None, Some(mesh));
    let glb = builder.finish_glb(vec![node]);

    let (json_bytes, bin_bytes) = read_glb(&glb).unwrap();
    let json = core::str::from_utf8(json_bytes).unwrap();
    assert!(json.contains("\"version\":\"2.0\""));
    assert!(json.contains("\"generator\":\"formatkit-gltf\""));
    assert!(json.contains("\"name\":\"tri\""));
    assert!(bin_bytes.is_some_and(|b| !b.is_empty()));
}

#[test]
fn push_animation_channel_builds_sampler_and_target() {
    use crate::json::Json;
    let (mut channels, mut samplers) = (Vec::new(), Vec::new());
    super::push_animation_channel(&mut channels, &mut samplers, 7, 3, "rotation", 8);
    assert_eq!(
        samplers,
        vec![Json::Obj(vec![
            ("input", Json::UInt(7)),
            ("output", Json::UInt(8)),
            ("interpolation", Json::Str("LINEAR".to_string())),
        ])]
    );
    assert_eq!(
        channels,
        vec![Json::Obj(vec![
            ("sampler", Json::UInt(0)),
            (
                "target",
                Json::Obj(vec![
                    ("node", Json::UInt(3)),
                    ("path", Json::Str("rotation".to_string())),
                ])
            ),
        ])]
    );
}

#[test]
fn skinning_and_animation_emit_valid_glb() {
    let mut builder = GltfBuilder::new();
    let joint = builder
        .try_add_node_trs(
            Some("root_joint".into()),
            [0.0; 3],
            [0.0, 0.0, 0.0, 1.0],
            [1.0; 3],
            None,
        )
        .unwrap();
    let mat = builder.color_material("skin_mat", [0.8, 0.2, 0.2, 1.0]);
    let mesh = builder.add_mesh(vec![triangle(mat)]);
    let mesh_node = builder.add_node(Some("skinned_mesh".into()), None, Some(mesh));
    let skin = builder.add_skin(&[joint], &[IDENTITY_MATRIX]);
    builder.set_node_skin(mesh_node, skin);
    builder.add_child(joint, mesh_node);

    let (mut channels, mut samplers) = (Vec::new(), Vec::new());
    let times = [0.0, 0.5, 1.0];
    builder
        .push_translation_channel(
            &mut channels,
            &mut samplers,
            joint,
            &times,
            &[[0.0; 3], [0.0, 1.0, 0.0], [0.0; 3]],
        )
        .unwrap();
    builder.add_animation("bounce", channels, samplers);

    let glb = builder.finish_glb(vec![joint]);
    let json = glb_json(&glb);
    assert!(json.contains("\"skins\""));
    assert!(json.contains("\"inverseBindMatrices\""));
    assert!(json.contains("\"animations\""));
    assert!(json.contains("\"name\":\"bounce\""));
}

#[test]
fn cubic_spline_rotation_channel_validates_triplets_and_node() {
    use crate::json::Json;
    let mut builder = GltfBuilder::new();
    let node = builder
        .try_add_node_trs(
            Some("joint".into()),
            [0.0; 3],
            [0.0, 0.0, 0.0, 1.0],
            [1.0; 3],
            None,
        )
        .unwrap();
    let times = [0.0, 1.0];
    let values = [
        [0.0; 4],
        [0.0, 0.0, 0.0, 1.0],
        [0.0, 0.0, 0.1, 0.0],
        [0.0, 0.0, 0.1, 0.0],
        [0.0, 0.0, 0.1, 0.9949874],
        [0.0; 4],
    ];
    let (mut channels, mut samplers) = (Vec::new(), Vec::new());
    builder
        .push_rotation_cubic_spline_channel(&mut channels, &mut samplers, node, &times, &values)
        .unwrap();
    assert_eq!(
        samplers,
        vec![Json::Obj(vec![
            ("input", Json::UInt(0)),
            ("output", Json::UInt(1)),
            ("interpolation", Json::Str("CUBICSPLINE".into())),
        ])]
    );

    assert!(builder
        .push_rotation_cubic_spline_channel(
            &mut Vec::new(),
            &mut Vec::new(),
            node,
            &times,
            &values[..5],
        )
        .is_err());
    let mut nonunit = values;
    nonunit[1] = [0.0; 4];
    assert!(builder
        .push_rotation_cubic_spline_channel(
            &mut Vec::new(),
            &mut Vec::new(),
            node,
            &times,
            &nonunit,
        )
        .is_err());
    let mut translated = IDENTITY_MATRIX;
    translated[12] = 1.0;
    let matrix_node = builder.add_node(Some("matrix".into()), Some(translated), None);
    assert!(builder
        .push_rotation_cubic_spline_channel(
            &mut Vec::new(),
            &mut Vec::new(),
            matrix_node,
            &times,
            &values,
        )
        .is_err());
}

#[test]
fn extended_primitive_emits_second_weights_and_morph_targets() {
    let mut builder = GltfBuilder::new();
    let material = builder
        .solid_material_with(MaterialOptions::default())
        .unwrap();
    let extras = PrimExtras {
        joints_1: Some(vec![[4, 5, 6, 0]; 3]),
        weights_1: Some(vec![[0.0, 0.0, 0.0, 0.0]; 3]),
        morph_targets: vec![MorphTarget {
            positions: Some(vec![[0.1, 0.0, 0.0]; 3]),
            normals: Some(vec![[0.0, 0.1, 0.0]; 3]),
        }],
    };
    let mesh = builder
        .add_mesh_with_extras(vec![(triangle(material), extras)])
        .unwrap();
    let node = builder.add_node(None, None, Some(mesh));
    let glb = builder.finish_glb(vec![node]);
    let json = glb_json(&glb);

    assert!(json.contains("\"JOINTS_1\""));
    assert!(json.contains("\"WEIGHTS_1\""));
    assert!(json.contains("\"targets\":[{\"POSITION\""));
    assert!(json.contains("\"NORMAL\""));
}

#[test]
fn extended_primitive_rejects_unpaired_or_mismatched_attributes() {
    let mut builder = GltfBuilder::new();
    let extras = PrimExtras {
        joints_1: Some(vec![[4, 5, 6, 7]; 3]),
        ..PrimExtras::default()
    };
    assert_eq!(
        builder.add_mesh_with_extras(vec![(triangle(0), extras)]),
        Err(GltfError::MissingPairedAttribute("JOINTS_1/WEIGHTS_1"))
    );

    let extras = PrimExtras {
        morph_targets: vec![MorphTarget {
            positions: Some(vec![[0.0; 3]; 2]),
            normals: None,
        }],
        ..PrimExtras::default()
    };
    assert_eq!(
        builder.add_mesh_with_extras(vec![(triangle(0), extras)]),
        Err(GltfError::AttributeLength {
            attribute: "morph POSITION",
            expected: 3,
            actual: 2,
        })
    );
}

#[test]
fn typed_trs_tracks_preserve_exact_times_and_all_paths() {
    let mut builder = GltfBuilder::new();
    let node = builder
        .try_add_node_trs(
            Some("joint".to_string()),
            [0.0, 0.0, 0.0],
            [0.0, 0.0, 0.0, 1.0],
            [1.0, 1.0, 1.0],
            None,
        )
        .unwrap();
    let times = [0.0, 0.123_456_79, 1.000_000_1];
    let mut channels = Vec::new();
    let mut samplers = Vec::new();
    builder
        .push_translation_channel(
            &mut channels,
            &mut samplers,
            node,
            &times,
            &[[0.0; 3], [1.0, 2.0, 3.0], [4.0, 5.0, 6.0]],
        )
        .unwrap();
    builder
        .push_rotation_channel(
            &mut channels,
            &mut samplers,
            node,
            &times,
            &[[0.0, 0.0, 0.0, 1.0]; 3],
        )
        .unwrap();
    builder
        .push_scale_channel(
            &mut channels,
            &mut samplers,
            node,
            &times,
            &[[1.0; 3], [2.0; 3], [3.0; 3]],
        )
        .unwrap();
    builder.add_animation("tracks", channels, samplers);
    let glb = builder.finish_glb(vec![node]);
    let json = glb_json(&glb);
    let bin = glb_bin(&glb);

    assert!(json.contains("\"path\":\"translation\""));
    assert!(json.contains("\"path\":\"rotation\""));
    assert!(json.contains("\"path\":\"scale\""));
    let exact_middle = times[1].to_le_bytes();
    assert!(bin.windows(4).any(|window| window == exact_middle));
}

#[test]
fn typed_animation_rejects_matrix_nodes_and_bad_times() {
    let mut builder = GltfBuilder::new();
    let mut matrix = IDENTITY_MATRIX;
    matrix[12] = 2.0;
    let matrix_node = builder.add_node(None, Some(matrix), None);
    let mut channels = Vec::new();
    let mut samplers = Vec::new();
    assert_eq!(
        builder.push_translation_channel(
            &mut channels,
            &mut samplers,
            matrix_node,
            &[0.0],
            &[[0.0; 3]],
        ),
        Err(GltfError::AnimatedNodeHasMatrix(matrix_node))
    );

    let trs_node = builder.add_node_trs(None, [0.0; 3], [0.0, 0.0, 0.0, 1.0], [1.0; 3], None);
    assert_eq!(
        builder.push_scale_channel(
            &mut channels,
            &mut samplers,
            trs_node,
            &[0.0, 0.0],
            &[[1.0; 3]; 2],
        ),
        Err(GltfError::NonIncreasingTimes)
    );
}

#[test]
fn unlit_and_external_image_material_options_serialize_cleanly() {
    let mut builder = GltfBuilder::new();
    let img = builder.add_external_image("albedo.png", Some("image/png"));
    let sampler = builder.add_sampler(Some(9729), Some(9729), 10497, 10497);
    let tex = builder.add_texture(img, Some(sampler));
    let _mat = builder
        .add_textured_material(
            "unlit_albedo",
            tex,
            MaterialOptions {
                double_sided: true,
                alpha_mode: AlphaMode::Blend,
                alpha_cutoff: 0.5,
                unlit: true,
            },
        )
        .unwrap();
    let node = builder.add_node(None, None, None);
    let glb = builder.finish_glb(vec![node]);
    let json = glb_json(&glb);

    assert!(json.contains("\"extensionsUsed\":[\"KHR_materials_unlit\"]"));
    assert!(json.contains("\"KHR_materials_unlit\":{}"));
    assert!(json.contains("\"uri\":\"albedo.png\""));
    assert!(json.contains("\"alphaMode\":\"BLEND\""));
    assert!(json.contains("\"doubleSided\":true"));
    assert!(!json.contains("\"alphaCutoff\""));
}

#[cfg(feature = "png")]
#[test]
fn embedded_png_texture_and_finish_split_round_trip() {
    let mut builder = GltfBuilder::new();
    let mat = builder.textured_material((0, 0), &Image::new(2, 2, vec![255; 16]));
    let mesh = builder.add_mesh(vec![triangle(mat)]);
    let node = builder.add_node(Some("mesh".to_string()), None, Some(mesh));

    let split = builder.finish_split(vec![node], "scene.bin", "scene_tex");
    assert!(split.gltf_json.contains("\"uri\":\"scene.bin\""));
    assert!(split.gltf_json.contains("\"uri\":\"scene_tex_0.png\""));
    assert!(split.gltf_json.contains("\"mimeType\":\"image/png\""));
    assert!(!split.bin.is_empty());
    assert_eq!(split.textures.len(), 1);
    assert_eq!(split.textures[0].0, "scene_tex_0.png");
    assert_eq!(&split.textures[0].1[..8], b"\x89PNG\r\n\x1a\n");
    let decoded = formatkit_codec::png::decode_png_rgba(&split.textures[0].1, 1024).unwrap();
    assert_eq!(decoded, Image::new(2, 2, vec![255; 16]));
}
