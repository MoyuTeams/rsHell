use std::sync::Arc;

use gtk::{
    cairo::{Context, Format, ImageSurface},
    pango,
};
use rshell_core::{
    CellAttributes, CellPosition, Color, CursorShape, RenderCell, RenderCursor, RenderFrame,
    RenderRow, SearchMatch, TerminalOverrides, TerminalSettingsV1, TerminalSize,
};
use rshell_ui::{
    FontMetricEnvironment, FontMetrics, FontMetricsService, MetricsChange, TerminalDecorations,
    TerminalRenderCache, TerminalRenderer,
};

#[test]
fn native_draw_contracts_run_serially_on_one_worker_thread() {
    offscreen_renderer_paints_deterministic_geometry_cursor_and_overlays();
    renderer_resolves_ansi_rgb_reverse_and_all_text_attributes();
    renderer_handles_every_cursor_shape_on_a_wide_cell();
    retained_renderer_relayouts_only_the_single_changed_row();
    retained_renderer_repaints_old_and_new_search_rows();
    retained_renderer_never_adopts_equal_generation_content();
    native_fallback_and_combining_glyphs_never_paint_outside_assigned_cells();
    measured_glyph_ink_fits_logical_cells_with_line_separation();
}

fn offscreen_renderer_paints_deterministic_geometry_cursor_and_overlays() {
    let metrics = FontMetrics::new(9.0, 18.0).unwrap();
    let profile = TerminalSettingsV1::default().resolve(&TerminalOverrides::default());
    let renderer = TerminalRenderer::new(&profile, metrics);
    let frame = fixture_frame();
    let decorations = TerminalDecorations::new(
        vec![SearchMatch {
            start: CellPosition {
                stable_row: 0,
                column: 2,
            },
            end: CellPosition {
                stable_row: 0,
                column: 3,
            },
        }],
        Some(0),
    );
    let surface = ImageSurface::create(Format::ARgb32, 36, 36).unwrap();
    let context = Context::new(&surface).unwrap();

    let stats = renderer
        .draw(&context, &frame, &decorations, 36, 36)
        .unwrap();
    assert_eq!(stats.rows, 2);
    assert_eq!(stats.text_runs, 4);
    assert_eq!(stats.wide_cells, 1);
    assert_eq!(stats.combining_cells, 1);
    assert_eq!(stats.selected_cells, 1);
    assert_eq!(stats.search_cells, 1);
    assert_eq!(stats.cursor_shape, Some(CursorShape::Underline));
    assert_eq!(stats.cursor_width, Some(18.0));

    let mut geometry_surface = ImageSurface::create(Format::ARgb32, 36, 36).unwrap();
    let geometry_context = Context::new(&geometry_surface).unwrap();
    renderer
        .draw(&geometry_context, &geometry_frame(), &decorations, 36, 36)
        .unwrap();
    drop(geometry_context);
    geometry_surface.flush();
    assert_eq!(
        stable_pixel_hash(geometry_surface.data().unwrap().as_ref()),
        9_452_195_836_048_871_113
    );
}

fn renderer_resolves_ansi_rgb_reverse_and_all_text_attributes() {
    let metrics = FontMetrics::new(9.0, 18.0).unwrap();
    let profile = TerminalSettingsV1::default().resolve(&TerminalOverrides::default());
    let renderer = TerminalRenderer::new(&profile, metrics);
    let mut surface = ImageSurface::create(Format::ARgb32, 36, 18).unwrap();
    let context = Context::new(&surface).unwrap();
    let frame = styled_frame();

    let stats = renderer
        .draw(&context, &frame, &TerminalDecorations::default(), 36, 18)
        .unwrap();
    drop(context);
    surface.flush();

    assert_eq!(stats.bold_cells, 1);
    assert_eq!(stats.italic_cells, 1);
    assert_eq!(stats.underlined_cells, 1);
    assert_eq!(stats.struck_cells, 1);
    assert_eq!(stats.reversed_cells, 1);
    let bytes = surface.data().unwrap();
    assert!(
        bytes
            .as_ref()
            .as_chunks::<4>()
            .0
            .iter()
            .any(|pixel| *pixel != [0, 0, 0, 0])
    );
}

fn renderer_handles_every_cursor_shape_on_a_wide_cell() {
    let metrics = FontMetrics::new(9.0, 18.0).unwrap();
    let profile = TerminalSettingsV1::default().resolve(&TerminalOverrides::default());
    let renderer = TerminalRenderer::new(&profile, metrics);

    for shape in [
        CursorShape::Block,
        CursorShape::Beam,
        CursorShape::Underline,
    ] {
        let mut frame = fixture_frame();
        Arc::make_mut(&mut frame).cursor.as_mut().unwrap().shape = shape;
        let surface = ImageSurface::create(Format::ARgb32, 36, 36).unwrap();
        let context = Context::new(&surface).unwrap();
        let stats = renderer
            .draw(&context, &frame, &TerminalDecorations::default(), 36, 36)
            .unwrap();
        assert_eq!(stats.cursor_shape, Some(shape));
        assert_eq!(stats.cursor_width, Some(18.0));
    }
}

fn retained_renderer_relayouts_only_the_single_changed_row() {
    let metrics = FontMetrics::new(9.0, 18.0).unwrap();
    let profile = TerminalSettingsV1::default().resolve(&TerminalOverrides::default());
    let renderer = TerminalRenderer::new(&profile, metrics);
    let mut cache = TerminalRenderCache::new();
    let first = fixture_frame();

    let initial = cache
        .update(
            &renderer,
            Arc::clone(&first),
            &TerminalDecorations::default(),
            36,
            36,
            1,
        )
        .unwrap();
    assert_eq!(initial.rows, 2);
    assert_eq!(initial.text_runs, 4);

    let mut next = first.as_ref().clone();
    next.generation = 2;
    next.rows = Arc::from([
        next.rows[0].clone(),
        RenderRow {
            stable_row: 1,
            wrapped: false,
            cells: Arc::from([cell("changed", 1, false)]),
        },
    ]);
    let incremental = cache
        .update(
            &renderer,
            Arc::new(next),
            &TerminalDecorations::default(),
            36,
            36,
            1,
        )
        .unwrap();

    assert_eq!(incremental.rows, 1);
    assert_eq!(incremental.text_runs, 1);

    let surface = ImageSurface::create(Format::ARgb32, 36, 36).unwrap();
    let context = Context::new(&surface).unwrap();
    cache.paint(&context).unwrap();
}

fn retained_renderer_repaints_old_and_new_search_rows() {
    let metrics = FontMetrics::new(9.0, 18.0).unwrap();
    let profile = TerminalSettingsV1::default().resolve(&TerminalOverrides::default());
    let renderer = TerminalRenderer::new(&profile, metrics);
    let mut cache = TerminalRenderCache::new();
    let frame = fixture_frame();
    let first = TerminalDecorations::new(vec![search_match(0)], Some(0));
    cache
        .update(&renderer, Arc::clone(&frame), &first, 36, 36, 1)
        .unwrap();

    let moved = TerminalDecorations::new(vec![search_match(1)], Some(0));
    let stats = cache.update(&renderer, frame, &moved, 36, 36, 1).unwrap();

    assert_eq!(stats.rows, 2);
}

fn retained_renderer_never_adopts_equal_generation_content() {
    let metrics = FontMetrics::new(9.0, 18.0).unwrap();
    let profile = TerminalSettingsV1::default().resolve(&TerminalOverrides::default());
    let renderer = TerminalRenderer::new(&profile, metrics);
    let mut cache = TerminalRenderCache::new();
    let first = fixture_frame();
    cache
        .update(
            &renderer,
            Arc::clone(&first),
            &TerminalDecorations::default(),
            36,
            36,
            1,
        )
        .unwrap();

    let mut equal = first.as_ref().clone();
    equal.rows = Arc::from([
        equal.rows[0].clone(),
        RenderRow {
            stable_row: 1,
            wrapped: false,
            cells: Arc::from([cell("must-not-be-adopted", 1, false)]),
        },
    ]);
    let ignored = cache
        .update(
            &renderer,
            Arc::new(equal),
            &TerminalDecorations::default(),
            36,
            36,
            1,
        )
        .unwrap();
    assert_eq!(ignored, Default::default());

    let mut next = first.as_ref().clone();
    next.generation = 2;
    let unchanged = cache
        .update(
            &renderer,
            Arc::new(next),
            &TerminalDecorations::default(),
            36,
            36,
            1,
        )
        .unwrap();
    assert_eq!(unchanged, Default::default());
}

fn native_fallback_and_combining_glyphs_never_paint_outside_assigned_cells() {
    let profile = TerminalSettingsV1::default().resolve(&TerminalOverrides::default());
    let font_map = pangocairo::FontMap::new();
    let pango_context = pango::Context::new();
    pango_context.set_font_map(Some(&font_map));
    let measured = match FontMetricsService::default()
        .measure(
            &pango_context,
            &profile,
            FontMetricEnvironment {
                effective_scale: 1.0,
                effective_dpi: 96.0,
                dpi_fallback_used: false,
            },
        )
        .unwrap()
    {
        MetricsChange::Changed(measured) | MetricsChange::Unchanged(measured) => measured,
    };
    let renderer = TerminalRenderer::new(&profile, measured.metrics);

    for (text, columns) in [("M", 1_u8), ("e\u{301}", 1), ("🙂", 1), ("界", 2)] {
        let painted = rendered_cell_bytes(&renderer, measured.metrics, text, columns);
        let baseline = rendered_cell_bytes(&renderer, measured.metrics, "", columns);
        let clip_x = (measured.metrics.cell_width * f64::from(columns)) as usize;
        let width = (measured.metrics.cell_width * 4.0) as usize;
        let stride = width * 4;
        let mut changed_inside = false;
        for (index, (actual, empty)) in painted.iter().zip(&baseline).enumerate() {
            let x = (index % stride) / 4;
            if actual != empty {
                if x >= clip_x {
                    panic!("{text:?} painted beyond its {columns}-cell clip at x={x}");
                }
                changed_inside = true;
            }
        }
        assert!(changed_inside, "{text:?} must produce visible in-cell ink");
    }
}

fn measured_glyph_ink_fits_logical_cells_with_line_separation() {
    for (effective_scale, scale_factor) in [(1.0, 1), (2.0, 2)] {
        assert_measured_glyph_matrix(effective_scale, scale_factor);
    }
}

fn assert_measured_glyph_matrix(effective_scale: f64, scale_factor: i32) {
    let profile = TerminalSettingsV1::default().resolve(&TerminalOverrides::default());
    let context = native_context();
    let measured = match FontMetricsService::default()
        .measure(
            &context,
            &profile,
            FontMetricEnvironment {
                effective_scale,
                effective_dpi: 96.0 * effective_scale,
                dpi_fallback_used: false,
            },
        )
        .unwrap()
    {
        MetricsChange::Changed(measured) | MetricsChange::Unchanged(measured) => measured,
    };
    let renderer = TerminalRenderer::from_measured(&profile, &measured);
    let mut failures = Vec::new();
    let printable = (' '..='~').map(|value| (value.to_string(), 1_u8));
    let representative = [
        ("e\u{301}".to_owned(), 1_u8),
        ("界".to_owned(), 2),
        ("🙂".to_owned(), 1),
        ("🙂".to_owned(), 2),
    ];
    for (bold, italic) in [(false, false), (true, false), (false, true), (true, true)] {
        for (text, columns) in printable.clone().chain(representative.clone()) {
            let diagnostic_surface = ImageSurface::create(Format::ARgb32, 128, 128).unwrap();
            diagnostic_surface.set_device_scale(effective_scale, effective_scale);
            let diagnostic_context = Context::new(&diagnostic_surface).unwrap();
            let diagnostic_layout = pangocairo::functions::create_layout(&diagnostic_context);
            diagnostic_layout.set_font_description(Some(&measured.font_description));
            diagnostic_layout.set_text(&text);
            let (ink, logical) = diagnostic_layout.pixel_extents();
            let mut cache = TerminalRenderCache::new();
            let stats = cache
                .update(
                    &renderer,
                    single_cell_frame(&text, columns, measured.metrics, bold, italic),
                    &TerminalDecorations::default(),
                    (measured.metrics.cell_width * 4.0) as i32,
                    (measured.metrics.cell_height * 2.0) as i32,
                    scale_factor,
                )
                .unwrap();

            if stats.glyph_clipped_cells != 0
                || !stats.minimum_line_separation.is_some_and(|gap| gap >= 1.0)
            {
                failures.push(format!(
                "{text:?}/{columns}/bold={bold}/italic={italic}: metrics={:?}, ink={ink:?}, logical={logical:?}, clipped={}, gap={:?}",
                measured.metrics, stats.glyph_clipped_cells, stats.minimum_line_separation,
            ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "scale-{effective_scale} terminal glyph contract failures: {}",
        failures.join("; ")
    );
}

fn fixture_frame() -> Arc<RenderFrame> {
    Arc::new(RenderFrame {
        generation: 1,
        size: size(4, 2),
        viewport_top: 0,
        rows: Arc::from([
            RenderRow {
                stable_row: 0,
                wrapped: false,
                cells: Arc::from([
                    cell("界", 2, false),
                    cell("e\u{301}", 1, false),
                    cell("x", 1, true),
                ]),
            },
            RenderRow {
                stable_row: 1,
                wrapped: false,
                cells: Arc::from([cell("z", 1, false)]),
            },
        ]),
        cursor: Some(RenderCursor {
            position: CellPosition {
                stable_row: 0,
                column: 0,
            },
            shape: CursorShape::Underline,
            visible: true,
        }),
        title: "draw fixture".into(),
        display_modes: Default::default(),
        alternate_screen: false,
        mouse_reporting: false,
    })
}

fn geometry_frame() -> Arc<RenderFrame> {
    let source = fixture_frame();
    Arc::new(RenderFrame {
        rows: Arc::from(
            source
                .rows
                .iter()
                .map(|row| RenderRow {
                    stable_row: row.stable_row,
                    wrapped: row.wrapped,
                    cells: Arc::from(
                        row.cells
                            .iter()
                            .map(|cell| RenderCell {
                                text: String::new(),
                                ..cell.clone()
                            })
                            .collect::<Vec<_>>(),
                    ),
                })
                .collect::<Vec<_>>(),
        ),
        ..source.as_ref().clone()
    })
}

fn styled_frame() -> Arc<RenderFrame> {
    Arc::new(RenderFrame {
        generation: 2,
        size: size(4, 1),
        viewport_top: 0,
        rows: Arc::from([RenderRow {
            stable_row: 0,
            wrapped: false,
            cells: Arc::from([
                RenderCell {
                    text: "S".into(),
                    width: 1,
                    foreground: Color::Ansi(1),
                    background: Color::Rgb(12, 34, 56),
                    attributes: CellAttributes {
                        bold: true,
                        italic: true,
                        underline: true,
                        strike: true,
                        reverse: true,
                        dim: false,
                    },
                    selected: false,
                },
                cell(" ", 1, false),
            ]),
        }]),
        cursor: None,
        title: "style fixture".into(),
        display_modes: Default::default(),
        alternate_screen: false,
        mouse_reporting: false,
    })
}

fn rendered_cell_bytes(
    renderer: &TerminalRenderer,
    metrics: FontMetrics,
    text: &str,
    columns: u8,
) -> Vec<u8> {
    let width = (metrics.cell_width * 4.0) as i32;
    let height = metrics.cell_height as i32;
    let mut surface = ImageSurface::create(Format::ARgb32, width, height).unwrap();
    let context = Context::new(&surface).unwrap();
    let frame = RenderFrame {
        generation: 1,
        size: TerminalSize {
            cols: 4,
            rows: 1,
            pixel_width: width as u32,
            pixel_height: height as u32,
            dpi: 96,
        },
        viewport_top: 0,
        rows: Arc::from([RenderRow {
            stable_row: 0,
            wrapped: false,
            cells: Arc::from([cell(text, columns, false)]),
        }]),
        cursor: None,
        title: String::new(),
        display_modes: Default::default(),
        alternate_screen: false,
        mouse_reporting: false,
    };
    renderer
        .draw(
            &context,
            &frame,
            &TerminalDecorations::default(),
            width,
            height,
        )
        .unwrap();
    drop(context);
    surface.flush();
    surface.data().unwrap().to_vec()
}

fn native_context() -> pango::Context {
    let font_map = pangocairo::FontMap::new();
    let context = pango::Context::new();
    context.set_font_map(Some(&font_map));
    context
}

fn single_cell_frame(
    text: &str,
    width: u8,
    metrics: FontMetrics,
    bold: bool,
    italic: bool,
) -> Arc<RenderFrame> {
    Arc::new(RenderFrame {
        generation: 1,
        size: TerminalSize {
            cols: 4,
            rows: 1,
            pixel_width: (metrics.cell_width * 8.0) as u32,
            pixel_height: (metrics.cell_height * 2.0) as u32,
            dpi: 192,
        },
        viewport_top: 0,
        rows: Arc::from([RenderRow {
            stable_row: 0,
            wrapped: false,
            cells: Arc::from([RenderCell {
                attributes: CellAttributes {
                    bold,
                    italic,
                    ..Default::default()
                },
                ..cell(text, width, false)
            }]),
        }]),
        cursor: None,
        title: String::new(),
        display_modes: Default::default(),
        alternate_screen: false,
        mouse_reporting: false,
    })
}

fn cell(text: &str, width: u8, selected: bool) -> RenderCell {
    RenderCell {
        text: text.into(),
        width,
        foreground: Color::Default,
        background: Color::Default,
        attributes: CellAttributes::default(),
        selected,
    }
}

fn size(cols: u16, rows: u16) -> TerminalSize {
    TerminalSize {
        cols,
        rows,
        pixel_width: u32::from(cols) * 9,
        pixel_height: u32::from(rows) * 18,
        dpi: 96,
    }
}

fn search_match(stable_row: i64) -> SearchMatch {
    SearchMatch {
        start: CellPosition {
            stable_row,
            column: 0,
        },
        end: CellPosition {
            stable_row,
            column: 1,
        },
    }
}

fn stable_pixel_hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}
