use std::fs::{self, File};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;

use anyhow::{anyhow, Context, Result};
use eframe::egui;

#[derive(Clone, Copy, PartialEq, Eq)]
enum RowKind {
    Static,
    Dynamic,
}

#[derive(Clone)]
struct Row {
    local_port: u16,
    kind: RowKind,
    remote_host: String,      // empty for Dynamic
    remote_port: Option<u16>, // None for Dynamic
}

impl Row {
    fn to_line(&self) -> String {
        match self.kind {
            RowKind::Dynamic => format!("D{}", self.local_port),
            RowKind::Static => format!(
                "{};{}:{}",
                self.local_port,
                self.remote_host,
                self.remote_port.unwrap_or(0)
            ),
        }
    }
}

enum DialogMode {
    Edit { index: usize },
    New,
}

struct EditorApp {
    // CLI args (used to run the tunnels)
    args: crate::Args,
    path: PathBuf,
    rows: Vec<Row>,
    selected: Option<usize>,
    status: String,
    dirty: bool,

    // Dialog state and buffers
    dialog_open: bool,
    dialog_mode: Option<DialogMode>,
    // Center the dialog when opened; reset after first frame
    dialog_center_next: bool,
    // Unique id per dialog open to avoid egui restoring previous position
    dialog_open_counter: u64,
    d_local_port: String,
    d_kind_dynamic: bool,
    d_remote_host: String,
    d_remote_port: String,

    // Run/logging state
    running: bool,
    child: Option<Child>,
    log_rx: Option<Receiver<String>>,
    show_logs: bool,
    logs: String,
}

impl EditorApp {
    fn new(args: crate::Args) -> Self {
        let mut app = Self {
            path: args.list.clone(),
            args,
            rows: Vec::new(),
            selected: None,
            status: String::new(),
            dirty: false,
            dialog_open: false,
            dialog_mode: None,
            dialog_center_next: false,
            dialog_open_counter: 0,
            d_local_port: String::new(),
            d_kind_dynamic: true,
            d_remote_host: String::new(),
            d_remote_port: String::new(),
            running: false,
            child: None,
            log_rx: None,
            show_logs: false,
            logs: String::new(),
        };
        if let Err(e) = app.reload() {
            app.status = format!("Failed to load: {e:#}");
        }
        app
    }

    fn reload(&mut self) -> Result<()> {
        self.rows = load_rows(&self.path)?;
        self.selected = None;
        self.clear_dialog_buffers();
        self.status = format!("Loaded {} entries", self.rows.len());
        self.dirty = false;
        Ok(())
    }

    fn clear_dialog_buffers(&mut self) {
        self.d_local_port.clear();
        self.d_kind_dynamic = true;
        self.d_remote_host.clear();
        self.d_remote_port.clear();
    }

    fn select(&mut self, idx: usize) {
        self.selected = Some(idx);
    }

    fn open_edit_dialog(&mut self, idx: usize) {
        self.select(idx);
        if let Some(row) = self.rows.get(idx) {
            self.d_local_port = row.local_port.to_string();
            self.d_kind_dynamic = matches!(row.kind, RowKind::Dynamic);
            self.d_remote_host = row.remote_host.clone();
            self.d_remote_port = row
                .remote_port
                .map(|p| p.to_string())
                .unwrap_or_else(String::new);
        }
        self.dialog_mode = Some(DialogMode::Edit { index: idx });
        self.dialog_open = true;
        self.dialog_center_next = true;
        self.dialog_open_counter = self.dialog_open_counter.wrapping_add(1);
    }

    fn open_new_dialog(&mut self) {
        self.selected = None;
        self.clear_dialog_buffers();
        self.dialog_mode = Some(DialogMode::New);
        self.dialog_open = true;
        self.dialog_center_next = true;
        self.dialog_open_counter = self.dialog_open_counter.wrapping_add(1);
    }

    fn apply_dialog_ok(&mut self) {
        match buffers_to_row(
            &self.d_local_port,
            self.d_kind_dynamic,
            &self.d_remote_host,
            &self.d_remote_port,
        ) {
            Ok(row) => {
                match self.dialog_mode {
                    Some(DialogMode::Edit { index }) => {
                        if index < self.rows.len() {
                            self.rows[index] = row;
                            self.status = "Updated row".into();
                            self.dirty = true;
                        }
                    }
                    Some(DialogMode::New) => {
                        self.rows.push(row);
                        self.status = "Added row".into();
                        self.dirty = true;
                    }
                    None => {}
                }
                self.dialog_open = false;
                self.dialog_mode = None;
            }
            Err(e) => {
                self.status = format!("Invalid data: {e}");
            }
        }
    }

    fn delete_selected(&mut self) {
        if let Some(idx) = self.selected.take() {
            if idx < self.rows.len() {
                self.rows.remove(idx);
                self.status = "Deleted row".into();
                self.dirty = true;
                self.clear_dialog_buffers();
            }
        } else {
            self.status = "No row selected".into();
        }
    }

    fn save(&mut self) {
        match save_rows(&self.path, &self.rows) {
            Ok(()) => {
                self.status = format!("Saved {} entries", self.rows.len());
                self.dirty = false;
            }
            Err(e) => self.status = format!("Save failed: {e:#}"),
        }
    }

    fn build_child_args(&self) -> Vec<String> {
        // Re-create CLI without --gui, but keep all other options and the list path
        let mut v = Vec::new();
        v.push("--host".to_string());
        v.push(self.args.host.clone());
        v.push("--port".to_string());
        v.push(self.args.port.to_string());
        v.push("--user".to_string());
        v.push(self.args.user.clone());
        v.push("--password".to_string());
        v.push(self.args.password.clone());
        v.push("--timeout".to_string());
        v.push(self.args.timeout.to_string());
        v.push("--retries".to_string());
        v.push(self.args.retries.to_string());
        v.push("--retry-interval".to_string());
        v.push(self.args.retry_interval.to_string());
        v.push("--keepalive".to_string());
        v.push(self.args.keepalive.to_string());
        v.push("--bind-wait".to_string());
        v.push(self.args.bind_wait.to_string());
        v.push("--list".to_string());
        v.push(self.path.display().to_string());
        v
    }

    fn start_tunneling(&mut self) {
        if self.running {
            return;
        }
        // Ensure tunnels file is up-to-date
        if self.dirty {
            self.save();
        }

        let exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                self.status = format!("Cannot get current executable: {e:#}");
                return;
            }
        };
        let args = self.build_child_args();

        self.status = "Starting tunnels...".into();
        self.logs.clear();

        let mut cmd = Command::new(exe);
        cmd.args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match cmd.spawn() {
            Ok(mut child) => {
                let (tx, rx) = mpsc::channel::<String>();

                // stdout reader
                if let Some(out) = child.stdout.take() {
                    let txo = tx.clone();
                    thread::spawn(move || {
                        let reader = io::BufReader::new(out);
                        for line in reader.lines() {
                            if let Ok(l) = line {
                                let _ = txo.send(l + "\n");
                            }
                        }
                    });
                }
                // stderr reader
                if let Some(err) = child.stderr.take() {
                    thread::spawn(move || {
                        let reader = io::BufReader::new(err);
                        for line in reader.lines() {
                            if let Ok(l) = line {
                                let _ = tx.send(l + "\n");
                            }
                        }
                    });
                }

                self.child = Some(child);
                self.log_rx = Some(rx);
                self.running = true;
                self.show_logs = true; // auto-open logs window
                self.status = "Tunnels running (see Logs)".into();
            }
            Err(e) => {
                self.status = format!("Failed to start tunnels: {e:#}");
            }
        }
    }

    fn stop_tunneling(&mut self) {
        // Stop the running child process if any
        if let Some(mut child) = self.child.take() {
            match child.kill() {
                Ok(()) => {
                    self.status = "Tunnels stopping (terminate sent)".into();
                }
                Err(e) => {
                    self.status = format!("Failed to stop tunnels: {e:#}");
                }
            }
        } else {
            self.status = "No running tunnels to stop".into();
        }
        // Reflect state in UI; logs remain visible
        self.running = false;
        self.show_logs = true;
    }
}

fn parse_host_port(s: &str) -> Result<(&str, u16)> {
    let mut it = s.rsplitn(2, ':');
    let port_str = it.next().ok_or_else(|| anyhow!("missing port"))?;
    let host = it.next().ok_or_else(|| anyhow!("missing host"))?;
    let port: u16 = port_str.parse().map_err(|_| anyhow!("invalid port"))?;
    Ok((host, port))
}

fn load_rows(path: &Path) -> Result<Vec<Row>> {
    let file = File::open(path).with_context(|| format!("open tunnels file: {:?}", path))?;
    let reader = io::BufReader::new(file);
    let mut res = Vec::new();
    for line in reader.lines() {
        let line_string = line?;
        let mut line = line_string.trim().to_string();
        if let Some(hash) = line.find('#') {
            line.truncate(hash);
            line = line.trim().into();
        }
        if line.is_empty() {
            continue;
        }

        if line.starts_with('D') || line.starts_with('d') {
            let port_str = &line[1..];
            if let Ok(lp) = port_str.parse::<u16>() {
                res.push(Row { local_port: lp, kind: RowKind::Dynamic, remote_host: String::new(), remote_port: None });
            }
            continue;
        }

        let parts: Vec<&str> = line.split(';').collect();
        if parts.len() == 2 && parts[1].eq_ignore_ascii_case("D") {
            if let Ok(lp) = parts[0].parse::<u16>() {
                res.push(Row { local_port: lp, kind: RowKind::Dynamic, remote_host: String::new(), remote_port: None });
            }
            continue;
        }

        if parts.len() == 2 {
            if let Ok(lp) = parts[0].parse::<u16>() {
                if let Ok((h, p)) = parse_host_port(parts[1]) {
                    res.push(Row { local_port: lp, kind: RowKind::Static, remote_host: h.to_string(), remote_port: Some(p) });
                }
            }
        }
    }
    Ok(res)
}

fn save_rows(path: &Path, rows: &[Row]) -> Result<()> {
    let mut content = String::new();
    for r in rows {
        content.push_str(&r.to_line());
        content.push('\n');
    }
    // Write atomically-ish: write to temp then replace
    let tmp_path = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp_path)
            .with_context(|| format!("create temp file: {:?}", tmp_path))?;
        f.write_all(content.as_bytes())?;
        f.flush()?;
    }
    fs::rename(&tmp_path, path).with_context(|| format!("replace {:?}", path))?;
    Ok(())
}

impl eframe::App for EditorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Increase global button padding for better visibility and click/tap targets
        // This affects all buttons (toolbar and dialog buttons).
        {
            let mut style = (*ctx.style()).clone();
            // Horizontal, Vertical padding in points (logical pixels)
            style.spacing.button_padding = egui::Vec2::new(14.0, 10.0);
            ctx.set_style(style);
        }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.heading("Metro Tunnels Editor");
            ui.label(format!("File: {}", self.path.display()));
            if self.dirty {
                ui.colored_label(egui::Color32::YELLOW, "Unsaved changes");
            }
        });

        egui::TopBottomPanel::bottom("bottom").show(ctx, |ui| {
            // Bottom area now only shows status info; all buttons moved above the list
            ui.separator();
            ui.label(&self.status);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Existing Tunnels");
            // Toolbar above the list — all actions are here
            ui.horizontal(|ui| {
                // New (green)
                let new_btn = egui::Button::new(
                    egui::RichText::new("New").strong().color(egui::Color32::BLACK),
                )
                // Lighter green for better readability with black label
                .fill(egui::Color32::from_rgb(163, 245, 208)) // light mint green
                .rounding(egui::Rounding::same(6.0))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_white_alpha(30)));
                if ui.add(new_btn).clicked() {
                    self.open_new_dialog();
                }

                ui.add_space(6.0);

                // Delete (red) — disabled when nothing is selected (egui will auto-dim it)
                let del_btn = egui::Button::new(
                    egui::RichText::new("Delete").strong().color(egui::Color32::BLACK),
                )
                // Lighter red for better readability with black label
                .fill(egui::Color32::from_rgb(255, 179, 169)) // light coral
                .rounding(egui::Rounding::same(6.0))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_white_alpha(30)));
                let del_resp = ui.add_enabled(self.selected.is_some(), del_btn);
                if del_resp.clicked() {
                    self.delete_selected();
                }

                ui.separator();

                // Keep default styling for utility buttons
                if ui.button("Reload").clicked() {
                    if let Err(e) = self.reload() {
                        self.status = format!("Reload failed: {e:#}");
                    }
                }
                if ui.button("Save").clicked() {
                    self.save();
                }

                // Divider before Run/Stop group
                ui.separator();

                // Run button (blue) — starts tunneling and opens log window
                ui.add_space(6.0);
                let run_btn = egui::Button::new(
                    egui::RichText::new("Run").strong().color(egui::Color32::WHITE),
                )
                .fill(egui::Color32::from_rgb(66, 133, 244)) // blue
                .rounding(egui::Rounding::same(6.0))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_white_alpha(30)));
                let run_resp = ui.add_enabled(!self.running, run_btn);
                if run_resp.clicked() {
                    self.start_tunneling();
                }

                // Stop button (purple) — stops tunneling
                ui.add_space(6.0);
                let stop_btn = egui::Button::new(
                    egui::RichText::new("Stop").strong().color(egui::Color32::WHITE),
                )
                .fill(egui::Color32::from_rgb(140, 82, 255)) // purple
                .rounding(egui::Rounding::same(6.0))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_white_alpha(30)));
                let stop_resp = ui.add_enabled(self.running, stop_btn);
                if stop_resp.clicked() {
                    self.stop_tunneling();
                }

                // Logs toggle
                if ui.button("Logs").clicked() {
                    self.show_logs = true;
                }
            });
            // Slightly reduce the space between the toolbar and the list
            ui.add_space(2.0);

            // Make the list more compact without affecting global/button padding by scoping a tighter style
            ui.scope(|ui| {
                // Clone the full Style (not the Arc) so we can mutate spacing locally
                let mut s: egui::Style = (*ui.ctx().style()).clone();
                // Reduce generic item spacing within the list (horizontal, vertical)
                s.spacing.item_spacing = egui::Vec2::new(6.0, 2.0);
                // Reduce the minimum interactive height so rows don't get extra vertical padding
                s.spacing.interact_size.y = 20.0; // default is ~24; smaller yields tighter rows
                ui.set_style(s);

                egui::ScrollArea::vertical().show(ui, |ui| {
                    egui::Grid::new("rows_grid")
                        .striped(true)
                        .spacing(egui::Vec2::new(8.0, 2.0))
                        .show(ui, |ui| {
                        ui.label("");
                        ui.label("Local Port");
                        ui.label("Kind");
                        ui.label("Remote Host");
                        ui.label("Remote Port");
                        ui.end_row();

                    let mut clicked_index: Option<usize> = None;
                    for (i, r) in self.rows.iter().enumerate() {
                        // Capture the start of the row to compute a full-row clickable rect later
                        let row_start = ui.cursor().min;
                        // In CentralPanel, use the full available right edge
                        let row_right = ui.max_rect().right();

                        let sel = self.selected == Some(i);
                        if ui.selectable_label(sel, "").clicked() { clicked_index = Some(i); }

                        let lp = ui.add(egui::Label::new(r.local_port.to_string()).sense(egui::Sense::click()));
                        if lp.clicked() { clicked_index = Some(i); }

                        let kind_str = match r.kind { RowKind::Static => "Static", RowKind::Dynamic => "Dynamic" };
                        let kd = ui.add(egui::Label::new(kind_str).sense(egui::Sense::click()));
                        if kd.clicked() { clicked_index = Some(i); }

                        let host_text = if r.remote_host.is_empty() { "-" } else { &r.remote_host };
                        let rh = ui.add(egui::Label::new(host_text).sense(egui::Sense::click()));
                        if rh.clicked() { clicked_index = Some(i); }

                        let rp_text: String = match r.remote_port { Some(p) => p.to_string(), None => "-".into() };
                        let rp = ui.add(egui::Label::new(rp_text).sense(egui::Sense::click()));
                        if rp.clicked() { clicked_index = Some(i); }

                        // End the row to advance the cursor to the next row start; this gives us row height
                        ui.end_row();

                        // Build a full-width rectangle for the row and make it clickable
                        let next_row_start = ui.cursor().min; // y of the next row start = bottom of this row
                        let row_rect = egui::Rect::from_min_max(
                            egui::Pos2::new(row_start.x, row_start.y),
                            egui::Pos2::new(row_right, next_row_start.y),
                        );
                        let resp = ui.interact(row_rect, ui.id().with(("row", i)), egui::Sense::click());
                        if resp.clicked() { clicked_index = Some(i); }
                    }
                    if let Some(i) = clicked_index { self.open_edit_dialog(i); }
                });
                // close ScrollArea
                });
            });
            // Delete button moved to toolbar above
        });

        // Dialog for new/edit
        if self.dialog_open {
            let title = match self.dialog_mode {
                Some(DialogMode::Edit { .. }) => "Edit Tunnel",
                Some(DialogMode::New) => "New Tunnel",
                None => "Tunnel",
            };
            // Use a local copy for the `.open()` flag to avoid conflicting borrows of `self`
            let mut open_flag = true; // the window will close itself by setting this to false
            let mut window = egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .open(&mut open_flag);
            // Center the dialog once on open to avoid covering important UI, but allow user dragging afterward
            if self.dialog_center_next {
                window = window.anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO);
                self.dialog_center_next = false;
            }
            // Give this dialog instance a unique id to prevent egui from restoring a previous position
            window = window.id(egui::Id::new(("tunnel_dialog", self.dialog_open_counter)));
            window.show(ctx, |ui| {
                    egui::Grid::new("dialog_grid").num_columns(2).show(ui, |ui| {
                        ui.label("Local Port");
                        ui.text_edit_singleline(&mut self.d_local_port);
                        ui.end_row();

                        ui.label("Kind");
                        ui.horizontal(|ui| {
                            ui.radio_value(&mut self.d_kind_dynamic, false, "Static");
                            ui.radio_value(&mut self.d_kind_dynamic, true, "Dynamic");
                        });
                        ui.end_row();

                        if !self.d_kind_dynamic {
                            ui.label("Remote Host");
                            ui.text_edit_singleline(&mut self.d_remote_host);
                            ui.end_row();

                            ui.label("Remote Port");
                            ui.text_edit_singleline(&mut self.d_remote_port);
                            ui.end_row();
                        }
                    });
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button("OK").clicked() {
                            self.apply_dialog_ok();
                        }
                        if ui.button("Cancel").clicked() {
                            // request window close
                            self.dialog_mode = None;
                            // Set flag to false by closing after window finishes rendering
                            // We'll update `self.dialog_open` below
                            // Using a separate variable avoids double borrow
                        }
                    });
                });
            // Close the window based on the local flag or after applying OK/Cancel
            if !open_flag || self.dialog_mode.is_none() {
                self.dialog_open = false;
            }
        }

        // Drain log channel and update state
        if let Some(rx) = &self.log_rx {
            for _ in 0..200 { // avoid spending too long in one frame
                match rx.try_recv() {
                    Ok(s) => self.logs.push_str(&s),
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
                }
            }
        }

        // Check child status
        if self.running {
            if let Some(child) = self.child.as_mut() {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        self.running = false;
                        self.status = format!("Tunnels exited with status: {}", status);
                        self.show_logs = true; // keep logs visible
                    }
                    Ok(None) => {
                        // still running
                    }
                    Err(e) => {
                        self.running = false;
                        self.status = format!("Failed to query process: {e:#}");
                    }
                }
            } else {
                self.running = false;
            }
        }

        // Logs window
        if self.show_logs {
            let mut open = true;
            egui::Window::new("Logs")
                .open(&mut open)
                .resizable(true)
                .default_size(egui::vec2(800.0, 400.0))
                .show(ctx, |ui| {
                    ui.label(if self.running { "Status: Running" } else { "Status: Stopped" });
                    ui.separator();
                    egui::ScrollArea::vertical()
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            let text = egui::TextEdit::multiline(&mut self.logs)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(f32::INFINITY)
                                .desired_rows(20)
                                .interactive(false);
                            ui.add(text);
                        });
                });
            if !open {
                self.show_logs = false;
            }
        }
    }
}

fn buffers_to_row(
    local_port: &str,
    is_dynamic: bool,
    remote_host: &str,
    remote_port: &str,
) -> Result<Row> {
    let lp: u16 = local_port.trim().parse().map_err(|_| anyhow!("invalid local port"))?;
    if is_dynamic {
        Ok(Row { local_port: lp, kind: RowKind::Dynamic, remote_host: String::new(), remote_port: None })
    } else {
        if remote_host.trim().is_empty() {
            return Err(anyhow!("remote host required for static tunnel"));
        }
        let rp: u16 = remote_port.trim().parse().map_err(|_| anyhow!("invalid remote port"))?;
        Ok(Row { local_port: lp, kind: RowKind::Static, remote_host: remote_host.trim().to_string(), remote_port: Some(rp) })
    }
}

pub fn run_gui(args: &crate::Args) -> Result<()> {
    // Configure a deterministic initial window: reasonable default size (not maximized)
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 680.0])
            .into(),
        ..Default::default()
    };
    let app_title = "Metro Tunnels Editor";
    let args = args.clone();
    eframe::run_native(
        app_title,
        options,
        Box::new(move |_cc| Box::new(EditorApp::new(args.clone()))),
    )
    .map_err(|e| anyhow!("eframe error: {e}"))
}
