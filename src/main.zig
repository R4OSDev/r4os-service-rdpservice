const std = @import("std");
const r4os = @import("r4os");
const bitmap_geometry = @import("bitmap_geometry.zig");

const service_name = "RDPSVC";
const selftest_arg = "/SELFTEST";
const ping_arg = "/PING";
const status_arg = "/STATUS";
const registry_key = "SYSTEM\\Services\\RDPSVC";
const log_origin = "RDPSVC";

const default_enabled = true;
const default_client_target = "WindowsMSTSC";
const default_user_name = "r4os";
const default_password = "rosebud";
const default_listen_port: u16 = 3389;
const default_max_sessions: u32 = 1;
const default_log_passwords = true;

const op_status: u16 = 1;
const op_ping: u16 = 2;
const listen_wait_ticks: u32 = 450;
const service_register_wait_ticks: u32 = 120;
const session_worker_slots_max: usize = 8;
const accept_idle_poll_ms: u64 = 100;
// 0.56.27: Hauptschleife wartet blockierend auf Endpoint-Requests statt
// jede Runde 1 Tick zu schlafen; Accept/Worker laufen im Wait-Raster.
const rdp_main_loop_wait_ms: u64 = 20;
const session_worker_stack_bytes: u64 = 4 * 1024 * 1024;
const session_slow_warn_ms: u64 = 30 * 1000;
const session_stop_join_ticks: u64 = 120;
const rdp_handshake_timeout_ms: u64 = 5000;
const rdp_remote_frame_wait_ms: u64 = 10000;
const rdp_session_input_timeout_ms: u64 = 500;
const rdp_session_input_burst: u32 = 16;
const rdp_session_loop_sleep_ticks: u64 = 1;
const rdp_session_idle_sleep_ms: u64 = 15;
const rdp_session_state_check_ms: u64 = 250;
// 0.56.35: 50ms (20 Updates/s) ueberflutete den softwaregebauten TLS-Pfad
// des Clients - jeder 256px-gekachelte Dirty-Frame einer 1280px-Zeile sind
// ~160 Rechtecke/~10 PDUs; bei 20/s brach mstsc mit 0xC06 (TLS-Decrypt)
// ab. 200ms (5 Updates/s) hält die Session stabil; die Kernel-Frame-
// Revision aggregiert Zwischenaenderungen ohnehin zum jeweils neuesten.
const rdp_session_frame_min_gap_ms: u64 = 200;
// 0.56.35: Der Initial-Schirm wird streifenweise gemalt (siehe
// runRdpSessionLoop). 48 Zeilen/Streifen = 15 Streifen fuer 720px, jeder
// ~240 Rechtecke/~15 PDUs (Groessenklasse eines funktionierenden Dirty-
// Updates), verteilt ueber 15 Loop-Iterationen mit Input/TCP dazwischen.
const rdp_session_stripe_rows: u32 = 48;
// Flags von handleSessionClientPdu.
const session_pdu_flag_repaint: u8 = 1;
const session_pdu_flag_input: u8 = 2;
const rdp_tcp_write_timeout_ms: u64 = 60000;
// 0.56.35: Einzel-Versuch pro Paced-Write im sendAll-Nachschiebe-Loop.
const rdp_tcp_write_chunk_ms: u64 = 2000;
const rdp_tcp_window_wait_ms: u64 = 10000;
const rdp_tcp_retransmit_wait_ms: u64 = 1500;
const tcp_service_wait_ms: u64 = 5000;
const tcp_service_cleanup_wait_ms: u64 = 5000;
// 0.56.35: 64K war identisch mit dem typischen mstsc-Empfangsfenster -
// der Initial-Burst lief das Fenster voll, BEVOR der erste Ack-Flush kam.
// 16K drainen proaktiv, bevor der Stau entsteht.
const rdp_tcp_ack_batch_bytes: u32 = 16 * 1024;
// 0.56.35: RLE-Zeilen werden zu EINEM Update-PDU mit vielen Rechtecken
// gebuendelt (numberRectangles>1). Vorher war JEDE Bildzeile ein eigenes
// TLS-verschluesseltes Paket: 720 Mini-PDUs pro Vollframe stauten das
// mstsc-Fenster (Session-Tod mitten im Frame) und machten selbst kleine
// Dirty-Updates traege (pro PDU ein Krypto-Dispatch im TCG-Gast).
// Budget haelt data_len sicher unter dem 0x3fff-Limit des PER-Rahmens.
// 0.56.35: Rechteck-Deckel pro PDU. Der Wire-Test nimmt auch PDUs mit
// ~500 Rechtecken an (3 PDUs pro Vollframe, Kachelfolge korrekt), aber
// mstsc verwirft solche Riesen-PDUs still - die nachweislich
// gerenderten Dirty-Updates haben <=~20 Rechtecke. Deshalb Vollframes
// in dieselbe Groessenklasse deckeln (Encoder bleibt UNVERAENDERT).
const rdp_bitmap_body_budget: usize = 12 * 1024;
const rdp_bitmap_body_max_rects: u16 = 16;
const rle_tile_comp_max: usize = @as(usize, bitmap_geometry.tile_pixels) * 3 + 16;
const rdp_bitmap_body_capacity: usize = rdp_bitmap_body_budget + 18 + rle_tile_comp_max;
const rdp_max_packet: usize = 16384;
// 0.56.35: Kachelbreite 256px statt volle Zeilenbreite. Breite Rechtecke
// (>287px) erzwingen MEGA_MEGA-RLE-Orders - die EINZIGE Kodierungsform,
// die nur in den (nie gerenderten) Vollframes vorkam; die nachweislich
// gerenderten Dirty-Flecken sind schmal und nutzen nur kurze Orders.
// Mit 256px-Kacheln laeuft JEDE Kachel durch den bewaehrten kurzen
// Encoder-Pfad; MEGA_MEGA wird gar nicht mehr erzeugt.
const rdp_bitmap_tile_pixels: usize = @intCast(bitmap_geometry.tile_pixels);
const rdp_protocol_rdp: u32 = 0;
const rdp_protocol_ssl: u32 = 0x0000_0001;
const rdp_protocol_hybrid: u32 = 0x0000_0002;
const rdp_protocol_rdstls: u32 = 0x0000_0004;
const rdp_protocol_hybrid_ex: u32 = 0x0000_0008;
const rdp_protocol_modern_mask: u32 = rdp_protocol_ssl | rdp_protocol_hybrid | rdp_protocol_rdstls | rdp_protocol_hybrid_ex;
const tls_record_header_len: usize = 5;
const tls_content_change_cipher_spec: u8 = 20;
const tls_content_alert: u8 = 21;
const tls_content_handshake: u8 = 22;
const tls_content_application_data: u8 = 23;
const tls_record_max: usize = 18432;
const r4tls_live_header_len: usize = 12;
const r4tls_live_state_max: usize = 8192;
const r4tls_live_stream_state_len: usize = 140;
const r4tls_app_io_header_len: usize = 4 + r4tls_live_stream_state_len;
const r4tls_dispatch_max: usize = r4tls_app_io_header_len + tls_record_max;
const tls_rdp_pending_capacity: usize = rdp_max_packet;
const r4tls_role = "security.tls";
const r4auth_role = "security.credssp";
const r4tls_op_selftest: u32 = 3;
const r4tls_op_stream_contract: u32 = 7;
const r4tls_op_productive_contract: u32 = 12;
const r4tls_op_stream_alert_record: u32 = 10;
const r4tls_op_tls12_session_contract: u32 = 20;
const r4tls_op_tls12_session_harness: u32 = 21;
const r4tls_op_tls12_live_begin: u32 = 22;
const r4tls_op_tls12_live_finish: u32 = 23;
const r4tls_op_tls12_app_write: u32 = 24;
const r4tls_op_tls12_app_read: u32 = 25;
const r4auth_op_ntlmv2_profile: u32 = 7;
const r4auth_op_validate_fixed_credentials: u32 = 8;
const r4auth_op_error_contract: u32 = 9;
const r4auth_op_credssp_state_contract: u32 = 10;
const r4auth_op_credssp_build_challenge: u32 = 12;
const r4auth_op_credssp_windows_contract: u32 = 15;
const r4auth_op_credssp_windows_harness: u32 = 17;
const r4auth_op_credssp_live_contract: u32 = 18;
const r4auth_op_credssp_process_live_state: u32 = 19;
const r4auth_op_credssp_live_harness: u32 = 20;
const r4auth_result_bad_token: i32 = -6;
const r4auth_result_bad_password: i32 = -20;
const r4auth_result_unsupported_kerberos: i32 = -21;
const r4auth_result_unsupported_domain: i32 = -22;
const r4auth_result_missing_tls_context: i32 = -23;
const r4auth_result_bad_pubkeyauth: i32 = -24;
const r4auth_result_bad_state: i32 = -25;
const r4auth_result_unsupported_ntlm: i32 = -26;
const security_state_classic = "classic";
const security_state_tls = "tls";
const security_state_credssp = "credssp";
const security_state_auth_ok = "auth_ok";
const security_state_auth_fail = "auth_fail";
const security_state_tls_alert = "tls_alert";
const security_state_tls_wire = "tls_wire";
const security_state_modern_active = "modern_active";
const security_state_blocker = "blocker";
const r4tls_magic_live_begin = "R4LB";
const r4tls_magic_live_finish = "R4LF";
const r4tls_magic_app_write_in = "R4AW";
const r4tls_magic_app_write_out = "R4WX";
const r4tls_magic_app_read_in = "R4AR";
const r4tls_magic_app_read_out = "R4RX";
const r4auth_magic_live_state = "R4CL";
const r4auth_live_header_len: usize = 12;
const r4auth_live_frame_max: usize = r4auth_live_header_len + r4tls_live_stream_state_len + rdp_max_packet;
const r4auth_live_phase_negotiate: u8 = 1;
const r4auth_live_phase_authenticate: u8 = 2;
const r4auth_live_phase_pubkeyauth: u8 = 3;
const r4auth_live_variant_ntlm: u8 = 1;
const r4auth_live_flag_tls: u8 = 0x01;
const rdp_neg_req_type: u8 = 1;
const rdp_neg_resp_type: u8 = 2;
const x224_cr_type: u8 = 0xE0;
const x224_cc_type: u8 = 0xD0;
const x224_dt_type: u8 = 0xF0;
const mcs_user_channel_base: u16 = 1001;
const rdp_user_channel: u16 = 1002;
const rdp_user_channel_offset: u16 = rdp_user_channel - mcs_user_channel_base;
const rdp_io_channel: u16 = 1003;
const rdp_static_channel_base: u16 = rdp_io_channel + 1;
const rdp_client_network_data_type: u16 = 0xC003;
const rdp_static_channel_max: u32 = 31;
const rdp_base_channel_join_count: u32 = 2;
const mcs_send_data_indication_header_len: usize = 6;
const rdp_share_id: u32 = 0x0001_0001;
const rdp_pdu_demand_active: u16 = 0x0011;
const rdp_pdu_confirm_active: u16 = 0x0013;
const rdp_pdu_data: u16 = 0x0017;
const rdp_pdu2_control: u8 = 20;
const rdp_pdu2_input: u8 = 28;
// 0.56.35: Client-Repaint-Anforderungen (MS-RDPBCGR 2.2.11.2 / 2.2.11.3).
// mstsc verwirft den Initial-Vollframe der Aktivierung und fordert danach
// per Refresh-Rect eine komplette Neuzeichnung an; ohne Antwort bleibt der
// Schirm schwarz (nur Dirty-Updates wurden sichtbar - "Flecken").
const rdp_pdu2_refresh_rect: u8 = 33;
const rdp_pdu2_suppress_output: u8 = 35;
const rdp_pdu2_update: u8 = 2;
const rdp_pdu2_synchronize: u8 = 31;
const rdp_pdu2_font_list: u8 = 39;
const rdp_pdu2_font_map: u8 = 40;
const rdp_pdu2_persistent_key_list: u8 = 43;
const rdp_control_action_request_control: u16 = 0x0001;
const rdp_control_action_granted_control: u16 = 0x0002;
const rdp_control_action_cooperate: u16 = 0x0004;
const rdp_sec_exchange_pkt: u16 = 0x0001;
const rdp_sec_info_pkt: u16 = 0x0040;
const rdp_sec_license_pkt: u16 = 0x0080;
const rdp_sec_license_encrypt_cs: u16 = 0x0280;
const rdp_license_msg_error_alert: u8 = 0xFF;
const rdp_license_version_3: u8 = 0x03;
const rdp_license_status_valid_client: u32 = 0x0000_0007;
const rdp_license_state_no_transition: u32 = 0x0000_0002;
const rdp_license_blob_type_error: u16 = 0x0004;
const rdp_update_type_bitmap: u16 = 0x0001;
const rdp_bitmap_bits_per_pixel: u16 = 32;
// 0.56.26: MS-RDPBCGR Interleaved-RLE-Bitmap-Kompression. Die Session laeuft
// dann als 16bpp (RGB565); Interleaved RLE ist laut Spec nur fuer <=24bpp
// definiert. Roh-Fallback (32bpp unkomprimiert, bisheriger Pfad) bleibt ueber
// Registry CompressRle16=0 erreichbar.
const rdp_bitmap_bits_per_pixel_rle: u16 = 16;
const rdp_bitmap_flag_compression: u16 = 0x0001;
// 0.56.35-Sichttest-Fix: Unsere General-Capability meldet extraFlags
// 0x0400 (NO_BITMAP_COMPRESSION_HDR) - komprimierte Bitmaps MUESSEN
// daher OHNE den 8-Byte-TS_CD_HEADER gesendet werden (mstsc las die
// Headerbytes sonst als RLE-Stream und trennte nach dem ersten Frame:
// session result=protocol-error trace=font-map, schwarzes Fenster).
const rdp_bitmap_flag_no_compression_hdr: u16 = 0x0400;
const default_compress_rle16 = true;
var g_compress_rle16: bool = default_compress_rle16;
// Worst-Case-Encoderausgabe pro Zeile: 1-Pixel-Literale zwischen Runs kosten
// max. 3 Bytes/Pixel; +16 Reserve fuer Header-Splits.
// Der Codec-Selftest behaelt bewusst >287 Pixel fuer MEGA_MEGA-Orders;
// Produktionsframes benutzen dagegen ausschliesslich 256-Pixel-Kacheln.
const rdp_selftest_max_pixels: usize = 512;
const rle_row_comp_max: usize = rdp_selftest_max_pixels * 3 + 16;
const rdp_demand_default_width: u16 = 1024;
const rdp_demand_default_height: u16 = 768;
const rdp_demand_capability_count: u16 = 10;
const rdp_cap_general: u16 = 0x0001;
const rdp_cap_bitmap: u16 = 0x0002;
const rdp_cap_order: u16 = 0x0003;
const rdp_cap_bitmap_cache_rev3_codec_id: u16 = 0x0006;
const rdp_cap_pointer: u16 = 0x0008;
const rdp_cap_share: u16 = 0x0009;
const rdp_cap_color_cache: u16 = 0x000A;
const rdp_cap_input: u16 = 0x000D;
const rdp_cap_font: u16 = 0x000E;
const rdp_cap_bitmap_codecs: u16 = 0x001D;
const rdp_input_event_sync: u16 = 0x0000;
const rdp_input_event_scancode: u16 = 0x0004;
const rdp_input_event_unicode: u16 = 0x0005;
const rdp_input_event_mouse: u16 = 0x8001;
const rdp_input_keyboard_flag_release: u16 = 0x8000;
const rdp_pointer_flag_wheel: u16 = 0x0200;
const rdp_pointer_flag_move: u16 = 0x0800;
const rdp_pointer_flag_button1: u16 = 0x1000;
const rdp_pointer_flag_button2: u16 = 0x2000;
const rdp_pointer_flag_button3: u16 = 0x4000;
const rdp_pointer_flag_down: u16 = 0x8000;

const App = struct {
    sys: r4os.r4sys.Context,
    net: r4os.r4net.Context,
    desk: r4os.r4desk.Context,
    dev: r4os.r4dev.Context,

    fn init(r4_app: *r4os.App) ?App {
        return .{
            .sys = r4_app.system(),
            .net = r4_app.networkLowLevel() orelse return null,
            .desk = r4_app.desktop() orelse return null,
            .dev = r4_app.devicesLowLevel() orelse return null,
        };
    }
};

const Config = struct {
    enabled: bool = default_enabled,
    listen_port: u16 = default_listen_port,
    max_sessions: u32 = default_max_sessions,
    log_passwords: bool = default_log_passwords,
    compress_rle16: bool = default_compress_rle16,
    client_target: [32]u8 = .{0} ** 32,
    user_name: [32]u8 = .{0} ** 32,
    password: [32]u8 = .{0} ** 32,
};

const ModernSecurityProfile = struct {
    ready: bool = false,
    tls_session_ready: bool = false,
    tls_live_ready: bool = false,
    tls_stream_ready: bool = false,
    credssp_windows_ready: bool = false,
    credssp_live_ready: bool = false,
    credssp_loop_ready: bool = false,
    blocker: [64]u8 = .{0} ** 64,
};

const SessionResult = enum(u8) {
    accepted,
    input_ok,
    client_disconnect,
    tls_wire_ok,
    credssp_live_ok,
    modern_activation_ok,
    protocol_error,
    timeout,
    auth_failed,
    tcp_error,
    close_error,
};

const ServiceStats = struct {
    requests: u32 = 0,
    status_requests: u32 = 0,
    pings: u32 = 0,
    bad_ops: u32 = 0,
    registry_repairs: u32 = 0,
    listen_ready: u32 = 0,
    accepted: u32 = 0,
    closed: u32 = 0,
    active_sessions: u32 = 0,
    completed_sessions: u32 = 0,
    reconnects: u32 = 0,
    disconnects: u32 = 0,
    cleanup_ok: u32 = 0,
    cleanup_errors: u32 = 0,
    close_errors: u32 = 0,
    listener_closed: u32 = 0,
    listener_close_errors: u32 = 0,
    max_session_waits: u32 = 0,
    last_session_id: u32 = 0,
    last_session_result: SessionResult = .accepted,
    session_worker_started: u32 = 0,
    session_worker_completed: u32 = 0,
    session_worker_joined: u32 = 0,
    session_worker_create_failed: u32 = 0,
    session_worker_join_errors: u32 = 0,
    session_slow_clients: u32 = 0,
    last_worker_id: u32 = 0,
    last_worker_thread: u32 = 0,
    last_worker_exit: i32 = 0,
    last_session_ticks: u64 = 0,
    max_session_ticks: u64 = 0,
    last_disconnect_state: u32 = 255,
    negotiation_ok: u32 = 0,
    compat_classic_selected: u32 = 0,
    compat_modern_requests: u32 = 0,
    compat_tls_requests: u32 = 0,
    compat_nla_requests: u32 = 0,
    compat_rdstls_requests: u32 = 0,
    compat_hybrid_ex_requests: u32 = 0,
    compat_unknown_requests: u32 = 0,
    compat_classic_downgrades: u32 = 0,
    security_classic: u32 = 0,
    security_tls: u32 = 0,
    security_credssp: u32 = 0,
    security_auth_ok: u32 = 0,
    security_auth_fail: u32 = 0,
    security_tls_alert: u32 = 0,
    security_blockers: u32 = 0,
    r4tls_dispatch_ok: u32 = 0,
    r4auth_dispatch_ok: u32 = 0,
    r4tls_session_ok: u32 = 0,
    r4tls_live_ok: u32 = 0,
    r4tls_stream_ok: u32 = 0,
    r4tls_wire_begin_ok: u32 = 0,
    r4tls_wire_finish_ok: u32 = 0,
    r4tls_wire_records: u32 = 0,
    r4tls_wire_errors: u32 = 0,
    r4tls_app_write_ok: u32 = 0,
    r4tls_app_read_ok: u32 = 0,
    r4auth_windows_ok: u32 = 0,
    r4auth_live_ok: u32 = 0,
    r4auth_loop_ok: u32 = 0,
    r4auth_live_negotiate_ok: u32 = 0,
    r4auth_live_authenticate_ok: u32 = 0,
    r4auth_live_pubkey_ok: u32 = 0,
    r4auth_live_errors: u32 = 0,
    modern_activation_ok: u32 = 0,
    modern_stream_activation_ok: u32 = 0,
    mcs_connect_initial: u32 = 0,
    mcs_connect_response: u32 = 0,
    mcs_erect_domain: u32 = 0,
    mcs_attach_user: u32 = 0,
    mcs_channel_joins: u32 = 0,
    mcs_static_channels: u32 = 0,
    mcs_expected_channel_joins: u32 = 0,
    security_none: u32 = 0,
    security_exchange: u32 = 0,
    client_info: u32 = 0,
    license_valid_client: u32 = 0,
    auth_successes: u32 = 0,
    auth_failures: u32 = 0,
    demand_active: u32 = 0,
    confirm_active: u32 = 0,
    client_sync: u32 = 0,
    client_control: u32 = 0,
    font_list: u32 = 0,
    font_map: u32 = 0,
    activation_ok: u32 = 0,
    bitmap_frames: u32 = 0,
    bitmap_updates: u32 = 0,
    bitmap_rectangles: u32 = 0,
    bitmap_pixels: u32 = 0,
    bitmap_bytes: u32 = 0,
    bitmap_errors: u32 = 0,
    bitmap_comp_bytes: u32 = 0,
    bitmap_raw_bytes: u32 = 0,
    bitmap_rle_rows: u32 = 0,
    bitmap_raw_rows: u32 = 0,
    // 0.56.38: Shared-Frame-Zeilen (direkt aus dem gemappten Puffer)
    // vs. Kompat-Kopien via remoteFrameRead.
    bitmap_map_rows: u32 = 0,
    bitmap_copy_rows: u32 = 0,
    input_pdus: u32 = 0,
    input_events: u32 = 0,
    input_keys: u32 = 0,
    input_mouse: u32 = 0,
    input_wheel: u32 = 0,
    input_errors: u32 = 0,
    input_pushes: u32 = 0,
    protocol_packets: u32 = 0,
    protocol_errors: u32 = 0,
    protocol_timeouts: u32 = 0,
    bytes_rx: u32 = 0,
    bytes_tx: u32 = 0,
    last_packet_len: u32 = 0,
    last_x224_type: u32 = 0,
    last_requested_protocols: u32 = 0,
    last_selected_protocol: u32 = 0,
    last_compat_mask: u32 = 0,
    last_channel_id: u32 = 0,
    refresh_rect_pdus: u32 = 0,
    suppress_output_pdus: u32 = 0,
    full_refreshes_sent: u32 = 0,
    last_client_width: u32 = 0,
    last_client_height: u32 = 0,
    session_width: u32 = 0,
    session_height: u32 = 0,
    last_frame_revision: u32 = 0,
    last_frame_width: u32 = 0,
    last_frame_height: u32 = 0,
    last_frame_region_x: u32 = 0,
    last_frame_region_y: u32 = 0,
    last_frame_region_w: u32 = 0,
    last_frame_region_h: u32 = 0,
    last_frame_dirty_x: i32 = 0,
    last_frame_dirty_y: i32 = 0,
    last_frame_dirty_w: u32 = 0,
    last_frame_dirty_h: u32 = 0,
    last_frame_checksum: u32 = 0,
    last_frame_non_black_pixels: u32 = 0,
    last_input_sequence: u32 = 0,
    last_input_kind: u32 = 0,
    last_input_key: u32 = 0,
    last_input_scancode: u32 = 0,
    last_input_modifiers: u32 = 0,
    last_input_x: i32 = 0,
    last_input_y: i32 = 0,
    last_input_wheel: i32 = 0,
    last_input_buttons: u32 = 0,
    last_input_pending: u32 = 0,
    last_input_pushed_total: u32 = 0,
    last_input_polled_total: u32 = 0,
    last_input_dropped_total: u32 = 0,
    tcp_errors: u32 = 0,
    last_tcp_result: i32 = 0,
    last_client_conn: u32 = 0,
    last_auth_user: [32]u8 = .{0} ** 32,
    last_auth_password: [64]u8 = .{0} ** 64,
    last_failed_auth_user: [32]u8 = .{0} ** 32,
    last_failed_auth_password: [64]u8 = .{0} ** 64,
    last_error: [48]u8 = .{0} ** 48,
    // 0.56.35: Die echte Session-Abbruchursache VOR dem TCP-Close festhalten.
    // rdpSessionWorkerMain schliesst danach das Handle und ueberschreibt
    // last_error pauschal mit "closed" - dadurch stand im RDPTRACE bisher
    // immer "last=closed" statt z.B. "frame-read" oder "bitmap-ack-final",
    // was die Schwarzbild-Diagnose (Frame stirbt nach font-map) blind machte.
    session_end_error: [48]u8 = .{0} ** 48,
    last_activation_trace: [48]u8 = .{0} ** 48,
    last_compat_blocker: [64]u8 = .{0} ** 64,
    last_security_state: [32]u8 = .{0} ** 32,
};

const SessionWorkerSlot = struct {
    used: bool = false,
    slow_reported: bool = false,
    thread_handle: r4os.abi.ProgramJoinHandle = .{},
    session_id: u32 = 0,
    stream: TcpStream = .{},
    started_tick: u64 = 0,
    finished_tick: u64 = 0,
    result: SessionResult = .accepted,
    exit_code: i32 = 0,
    close_ok: bool = false,
    close_result: i32 = 0,
    app: *const App = undefined,
    config: Config = .{},
    modern_security: ModernSecurityProfile = .{},
    stats: ServiceStats = .{},
};

fn sessionResultName(result: SessionResult) []const u8 {
    return switch (result) {
        .accepted => "accepted",
        .input_ok => "input-ok",
        .client_disconnect => "client-disconnect",
        .tls_wire_ok => "tls-wire-ok",
        .credssp_live_ok => "credssp-live-ok",
        .modern_activation_ok => "modern-activation-ok",
        .protocol_error => "protocol-error",
        .timeout => "timeout",
        .auth_failed => "auth-failed",
        .tcp_error => "tcp-error",
        .close_error => "close-error",
    };
}

pub fn r4_app_main(r4_app: *r4os.App) i32 {
    var app = App.init(r4_app) orelse return r4os.abi.err_no_group;
    if (hasArg(app.sys.argsRaw(), selftest_arg)) return runSelfTest(&app);
    if (hasArg(app.sys.argsRaw(), ping_arg)) return runPingClient(&app);
    if (hasArg(app.sys.argsRaw(), status_arg)) return runStatusClient(&app);
    return runService(&app);
}

fn runService(app: *const App) i32 {
    if (!app.sys.hasFn("service_call")) return r4os.abi.service_api_result_invalid;
    if (!app.sys.hasFn("thread_create_handle") or !app.sys.hasFn("thread_handle_join")) {
        app.sys.println("RDPSVC requires R4X session worker threads");
        return r4os.abi.thread_error_unsupported;
    }

    var stats = ServiceStats{};
    setLastError(&stats, "init");
    stats.registry_repairs = ensureRegistryDefaults(app);
    const config = loadConfig(app);
    g_compress_rle16 = config.compress_rle16;
    if (!config.enabled) {
        app.sys.println("RDPSVC disabled by Registry");
        return 0;
    }
    const modern_security = prepareModernSecurityProfile(app, &stats, &config);

    var info: r4os.abi.ServiceInfo = .{};
    var endpoint_handle: u32 = 0;
    var waited: u32 = 0;
    while (waited < service_register_wait_ticks and endpoint_handle == 0) : (waited += 1) {
        const rc = app.sys.serviceEndpointRegister(service_name, 0, &info);
        if (rc == r4os.abi.service_api_result_ok and info.handle != 0) {
            endpoint_handle = info.handle;
            app.sys.write("RDPSVC endpoint handle=");
            app.sys.printU64(@intCast(endpoint_handle));
            app.sys.println("");
            break;
        }
        app.sys.sleepTicks(1);
    }
    if (endpoint_handle == 0) {
        app.sys.println("RDPSVC endpoint registration failed");
        return r4os.abi.service_api_result_no_endpoint;
    }

    if (!waitForListen(app, config.listen_port, &stats)) {
        _ = app.sys.serviceEndpointUnregister(endpoint_handle);
        app.sys.println("RDPSVC listen failed");
        return -1;
    }
    var sessions = [_]SessionWorkerSlot{SessionWorkerSlot{}} ** session_worker_slots_max;

    var next_accept_poll: u64 = 0;
    while (!app.sys.programShouldClose()) {
        const now = app.sys.ticks();
        const poll = app.sys.serviceEndpointPoll(endpoint_handle);
        if (poll < 0) {
            closeListener(app, config.listen_port, &stats);
            _ = app.sys.serviceEndpointUnregister(endpoint_handle);
            logStopSummary(app, &stats, "endpoint-poll");
            return poll;
        }
        if (poll > 0) {
            const rc = handleRequest(app, endpoint_handle, &stats, &config);
            if (rc < 0) {
                closeListener(app, config.listen_port, &stats);
                _ = app.sys.serviceEndpointUnregister(endpoint_handle);
                logStopSummary(app, &stats, "endpoint-request");
                return rc;
            }
        }

        pollSessionWorkers(app, &stats, sessions[0..], false);
        if (now >= next_accept_poll) {
            if (pollClient(app, &stats, &config, &modern_security, sessions[0..])) {
                next_accept_poll = now;
            } else {
                const idle_ticks = app.sys.ticksFromMilliseconds(accept_idle_poll_ms);
                next_accept_poll = now + if (idle_ticks == 0) 1 else idle_ticks;
            }
        }
        // 0.56.27: blockierend auf Endpoint-Requests warten (0.56.19-API);
        // Accept-Drossel und Worker-Join laufen im Wait-Raster weiter.
        _ = app.sys.serviceEndpointWait(endpoint_handle, app.sys.ticksFromMilliseconds(rdp_main_loop_wait_ms));
    }

    closeListener(app, config.listen_port, &stats);
    stopSessionWorkers(app, &stats, sessions[0..]);
    _ = app.sys.serviceEndpointUnregister(endpoint_handle);
    logStopSummary(app, &stats, "program-close");
    app.sys.println("RDPSVC stopped cleanly");
    return 0;
}

fn handleRequest(app: *const App, endpoint_handle: u32, stats: *ServiceStats, config: *const Config) i32 {
    var header: r4os.abi.ServiceMessageHeader = .{};
    var payload: [r4os.abi.service_api_max_payload]u8 = undefined;
    const got = app.sys.serviceEndpointRecv(endpoint_handle, &header, payload[0..]);
    if (got < 0) return got;
    if (got == 0 and header.magic != r4os.abi.service_api_magic) return 0;

    stats.requests +%= 1;
    return switch (header.op) {
        op_status => replyStatus(app, endpoint_handle, header.request_id, stats, config),
        op_ping => replyPing(app, endpoint_handle, header.request_id, stats),
        else => blk: {
            stats.bad_ops +%= 1;
            setLastError(stats, "bad-op");
            break :blk app.sys.serviceEndpointReply(endpoint_handle, header.request_id, r4os.abi.service_api_result_bad_op, "BADOP");
        },
    };
}

fn replyStatus(app: *const App, endpoint_handle: u32, request_id: u32, stats: *ServiceStats, config: *const Config) i32 {
    stats.status_requests +%= 1;
    var out: [r4os.abi.service_api_max_payload]u8 = .{0} ** r4os.abi.service_api_max_payload;
    var pos: usize = 0;
    appendText(out[0..], &pos, "RDPSVC OK port=");
    appendU64(out[0..], &pos, @intCast(config.listen_port));
    appendText(out[0..], &pos, " target=");
    appendText(out[0..], &pos, spanZ(config.client_target[0..]));
    appendText(out[0..], &pos, " sessions=");
    appendU64(out[0..], &pos, @intCast(config.max_sessions));
    appendText(out[0..], &pos, " active=");
    appendU64(out[0..], &pos, @intCast(stats.active_sessions));
    appendText(out[0..], &pos, " workers=");
    appendU64(out[0..], &pos, @intCast(stats.active_sessions));
    appendText(out[0..], &pos, "/");
    appendU64(out[0..], &pos, @intCast(session_worker_slots_max));
    appendText(out[0..], &pos, " worker_started=");
    appendU64(out[0..], &pos, @intCast(stats.session_worker_started));
    appendText(out[0..], &pos, " worker_done=");
    appendU64(out[0..], &pos, @intCast(stats.session_worker_completed));
    appendText(out[0..], &pos, " worker_joined=");
    appendU64(out[0..], &pos, @intCast(stats.session_worker_joined));
    appendText(out[0..], &pos, " worker_spawn_fail=");
    appendU64(out[0..], &pos, @intCast(stats.session_worker_create_failed));
    appendText(out[0..], &pos, " worker_join_err=");
    appendU64(out[0..], &pos, @intCast(stats.session_worker_join_errors));
    appendText(out[0..], &pos, " slow=");
    appendU64(out[0..], &pos, @intCast(stats.session_slow_clients));
    appendText(out[0..], &pos, " last_worker=");
    appendU64(out[0..], &pos, @intCast(stats.last_worker_id));
    appendText(out[0..], &pos, " last_thread=");
    appendU64(out[0..], &pos, @intCast(stats.last_worker_thread));
    appendText(out[0..], &pos, " last_exit=");
    appendI32(out[0..], &pos, stats.last_worker_exit);
    appendText(out[0..], &pos, " last_ticks=");
    appendU64(out[0..], &pos, stats.last_session_ticks);
    appendText(out[0..], &pos, " max_ticks=");
    appendU64(out[0..], &pos, stats.max_session_ticks);
    appendText(out[0..], &pos, " listen=");
    appendU64(out[0..], &pos, @intCast(stats.listen_ready));
    appendText(out[0..], &pos, " accepted=");
    appendU64(out[0..], &pos, @intCast(stats.accepted));
    appendText(out[0..], &pos, " closed=");
    appendU64(out[0..], &pos, @intCast(stats.closed));
    appendText(out[0..], &pos, " completed=");
    appendU64(out[0..], &pos, @intCast(stats.completed_sessions));
    appendText(out[0..], &pos, " reconnects=");
    appendU64(out[0..], &pos, @intCast(stats.reconnects));
    appendText(out[0..], &pos, " disconnects=");
    appendU64(out[0..], &pos, @intCast(stats.disconnects));
    appendText(out[0..], &pos, " cleanup=");
    appendU64(out[0..], &pos, @intCast(stats.cleanup_ok));
    appendText(out[0..], &pos, " cleanup_errors=");
    appendU64(out[0..], &pos, @intCast(stats.cleanup_errors));
    appendText(out[0..], &pos, " close_errors=");
    appendU64(out[0..], &pos, @intCast(stats.close_errors));
    appendText(out[0..], &pos, " listener_closed=");
    appendU64(out[0..], &pos, @intCast(stats.listener_closed));
    appendText(out[0..], &pos, " listener_close_errors=");
    appendU64(out[0..], &pos, @intCast(stats.listener_close_errors));
    appendText(out[0..], &pos, " max_waits=");
    appendU64(out[0..], &pos, @intCast(stats.max_session_waits));
    appendText(out[0..], &pos, " session=");
    appendU64(out[0..], &pos, @intCast(stats.last_session_id));
    appendText(out[0..], &pos, " session_result=");
    appendText(out[0..], &pos, sessionResultName(stats.last_session_result));
    appendText(out[0..], &pos, " trace=");
    appendText(out[0..], &pos, spanZ(stats.last_activation_trace[0..]));
    appendText(out[0..], &pos, " disconnect_state=");
    appendU64(out[0..], &pos, @intCast(stats.last_disconnect_state));
    appendText(out[0..], &pos, " negotiated=");
    appendU64(out[0..], &pos, @intCast(stats.negotiation_ok));
    appendText(out[0..], &pos, " proto_packets=");
    appendU64(out[0..], &pos, @intCast(stats.protocol_packets));
    appendText(out[0..], &pos, " proto_errors=");
    appendU64(out[0..], &pos, @intCast(stats.protocol_errors));
    appendText(out[0..], &pos, " timeouts=");
    appendU64(out[0..], &pos, @intCast(stats.protocol_timeouts));
    appendText(out[0..], &pos, " rx=");
    appendU64(out[0..], &pos, @intCast(stats.bytes_rx));
    appendText(out[0..], &pos, " tx=");
    appendU64(out[0..], &pos, @intCast(stats.bytes_tx));
    appendText(out[0..], &pos, " pkt=");
    appendU64(out[0..], &pos, @intCast(stats.last_packet_len));
    appendText(out[0..], &pos, " x224=");
    appendU64(out[0..], &pos, @intCast(stats.last_x224_type));
    appendText(out[0..], &pos, " requested=");
    appendU64(out[0..], &pos, @intCast(stats.last_requested_protocols));
    appendText(out[0..], &pos, " selected=");
    appendU64(out[0..], &pos, @intCast(stats.last_selected_protocol));
    appendText(out[0..], &pos, " classic_sel=");
    appendU64(out[0..], &pos, @intCast(stats.compat_classic_selected));
    appendText(out[0..], &pos, " modern_req=");
    appendU64(out[0..], &pos, @intCast(stats.compat_modern_requests));
    appendText(out[0..], &pos, " tls_req=");
    appendU64(out[0..], &pos, @intCast(stats.compat_tls_requests));
    appendText(out[0..], &pos, " nla_req=");
    appendU64(out[0..], &pos, @intCast(stats.compat_nla_requests));
    appendText(out[0..], &pos, " rdstls_req=");
    appendU64(out[0..], &pos, @intCast(stats.compat_rdstls_requests));
    appendText(out[0..], &pos, " hybex_req=");
    appendU64(out[0..], &pos, @intCast(stats.compat_hybrid_ex_requests));
    appendText(out[0..], &pos, " unknown_req=");
    appendU64(out[0..], &pos, @intCast(stats.compat_unknown_requests));
    appendText(out[0..], &pos, " classic_only=");
    appendU64(out[0..], &pos, @intCast(stats.compat_classic_downgrades));
    appendText(out[0..], &pos, " compat_mask=");
    appendU64(out[0..], &pos, @intCast(stats.last_compat_mask));
    appendText(out[0..], &pos, " compat_blocker=");
    appendText(out[0..], &pos, spanZ(stats.last_compat_blocker[0..]));
    appendText(out[0..], &pos, " sec_state=");
    appendText(out[0..], &pos, spanZ(stats.last_security_state[0..]));
    appendText(out[0..], &pos, " sec_classic=");
    appendU64(out[0..], &pos, @intCast(stats.security_classic));
    appendText(out[0..], &pos, " sec_tls=");
    appendU64(out[0..], &pos, @intCast(stats.security_tls));
    appendText(out[0..], &pos, " sec_credssp=");
    appendU64(out[0..], &pos, @intCast(stats.security_credssp));
    appendText(out[0..], &pos, " sec_auth_ok=");
    appendU64(out[0..], &pos, @intCast(stats.security_auth_ok));
    appendText(out[0..], &pos, " sec_auth_fail=");
    appendU64(out[0..], &pos, @intCast(stats.security_auth_fail));
    appendText(out[0..], &pos, " tls_alert=");
    appendU64(out[0..], &pos, @intCast(stats.security_tls_alert));
    appendText(out[0..], &pos, " sec_blockers=");
    appendU64(out[0..], &pos, @intCast(stats.security_blockers));
    appendText(out[0..], &pos, " r4tls=");
    appendU64(out[0..], &pos, @intCast(stats.r4tls_dispatch_ok));
    appendText(out[0..], &pos, " r4auth=");
    appendU64(out[0..], &pos, @intCast(stats.r4auth_dispatch_ok));
    appendText(out[0..], &pos, " tls_session=");
    appendU64(out[0..], &pos, @intCast(stats.r4tls_session_ok));
    appendText(out[0..], &pos, " tls_live=");
    appendU64(out[0..], &pos, @intCast(stats.r4tls_live_ok));
    appendText(out[0..], &pos, " tls_stream=");
    appendU64(out[0..], &pos, @intCast(stats.r4tls_stream_ok));
    appendText(out[0..], &pos, " tls_wire=");
    appendU64(out[0..], &pos, @intCast(stats.r4tls_wire_begin_ok));
    appendText(out[0..], &pos, "/");
    appendU64(out[0..], &pos, @intCast(stats.r4tls_wire_finish_ok));
    appendText(out[0..], &pos, " tls_records=");
    appendU64(out[0..], &pos, @intCast(stats.r4tls_wire_records));
    appendText(out[0..], &pos, " tls_app=");
    appendU64(out[0..], &pos, @intCast(stats.r4tls_app_write_ok));
    appendText(out[0..], &pos, "/");
    appendU64(out[0..], &pos, @intCast(stats.r4tls_app_read_ok));
    appendText(out[0..], &pos, " tls_wire_errors=");
    appendU64(out[0..], &pos, @intCast(stats.r4tls_wire_errors));
    appendText(out[0..], &pos, " credssp_windows=");
    appendU64(out[0..], &pos, @intCast(stats.r4auth_windows_ok));
    appendText(out[0..], &pos, " credssp_live=");
    appendU64(out[0..], &pos, @intCast(stats.r4auth_live_ok));
    appendText(out[0..], &pos, " credssp_loop=");
    appendU64(out[0..], &pos, @intCast(stats.r4auth_loop_ok));
    appendText(out[0..], &pos, " credssp_wire=");
    appendU64(out[0..], &pos, @intCast(stats.r4auth_live_negotiate_ok));
    appendText(out[0..], &pos, "/");
    appendU64(out[0..], &pos, @intCast(stats.r4auth_live_authenticate_ok));
    appendText(out[0..], &pos, "/");
    appendU64(out[0..], &pos, @intCast(stats.r4auth_live_pubkey_ok));
    appendText(out[0..], &pos, " credssp_errors=");
    appendU64(out[0..], &pos, @intCast(stats.r4auth_live_errors));
    appendText(out[0..], &pos, " modern_active=");
    appendU64(out[0..], &pos, @intCast(stats.modern_activation_ok));
    appendText(out[0..], &pos, " modern_stream=");
    appendU64(out[0..], &pos, @intCast(stats.modern_stream_activation_ok));
    appendText(out[0..], &pos, " mcs=");
    appendU64(out[0..], &pos, @intCast(stats.mcs_connect_initial));
    appendText(out[0..], &pos, " mcs_resp=");
    appendU64(out[0..], &pos, @intCast(stats.mcs_connect_response));
    appendText(out[0..], &pos, " erect=");
    appendU64(out[0..], &pos, @intCast(stats.mcs_erect_domain));
    appendText(out[0..], &pos, " attach=");
    appendU64(out[0..], &pos, @intCast(stats.mcs_attach_user));
    appendText(out[0..], &pos, " joins=");
    appendU64(out[0..], &pos, @intCast(stats.mcs_channel_joins));
    appendText(out[0..], &pos, " static_ch=");
    appendU64(out[0..], &pos, @intCast(stats.mcs_static_channels));
    appendText(out[0..], &pos, " expected_joins=");
    appendU64(out[0..], &pos, @intCast(stats.mcs_expected_channel_joins));
    appendText(out[0..], &pos, " sec_none=");
    appendU64(out[0..], &pos, @intCast(stats.security_none));
    appendText(out[0..], &pos, " sec_exchange=");
    appendU64(out[0..], &pos, @intCast(stats.security_exchange));
    appendText(out[0..], &pos, " client_info=");
    appendU64(out[0..], &pos, @intCast(stats.client_info));
    appendText(out[0..], &pos, " license=");
    appendU64(out[0..], &pos, @intCast(stats.license_valid_client));
    appendText(out[0..], &pos, " auth_ok=");
    appendU64(out[0..], &pos, @intCast(stats.auth_successes));
    appendText(out[0..], &pos, " auth_fail=");
    appendU64(out[0..], &pos, @intCast(stats.auth_failures));
    appendText(out[0..], &pos, " demand=");
    appendU64(out[0..], &pos, @intCast(stats.demand_active));
    appendText(out[0..], &pos, " confirm=");
    appendU64(out[0..], &pos, @intCast(stats.confirm_active));
    appendText(out[0..], &pos, " sync=");
    appendU64(out[0..], &pos, @intCast(stats.client_sync));
    appendText(out[0..], &pos, " control=");
    appendU64(out[0..], &pos, @intCast(stats.client_control));
    appendText(out[0..], &pos, " font_list=");
    appendU64(out[0..], &pos, @intCast(stats.font_list));
    appendText(out[0..], &pos, " font_map=");
    appendU64(out[0..], &pos, @intCast(stats.font_map));
    appendText(out[0..], &pos, " active_ok=");
    appendU64(out[0..], &pos, @intCast(stats.activation_ok));
    appendText(out[0..], &pos, " bitmap_frames=");
    appendU64(out[0..], &pos, @intCast(stats.bitmap_frames));
    appendText(out[0..], &pos, " bitmap_updates=");
    appendU64(out[0..], &pos, @intCast(stats.bitmap_updates));
    appendText(out[0..], &pos, " bitmap_rects=");
    appendU64(out[0..], &pos, @intCast(stats.bitmap_rectangles));
    appendText(out[0..], &pos, " bitmap_pixels=");
    appendU64(out[0..], &pos, @intCast(stats.bitmap_pixels));
    appendText(out[0..], &pos, " bitmap_bytes=");
    appendU64(out[0..], &pos, @intCast(stats.bitmap_bytes));
    appendText(out[0..], &pos, " bitmap_errors=");
    appendU64(out[0..], &pos, @intCast(stats.bitmap_errors));
    appendText(out[0..], &pos, " frame_rows=map/");
    appendU64(out[0..], &pos, @intCast(stats.bitmap_map_rows));
    appendText(out[0..], &pos, ",copy/");
    appendU64(out[0..], &pos, @intCast(stats.bitmap_copy_rows));
    appendText(out[0..], &pos, " refresh=");
    appendU64(out[0..], &pos, @intCast(stats.refresh_rect_pdus));
    appendText(out[0..], &pos, "/");
    appendU64(out[0..], &pos, @intCast(stats.suppress_output_pdus));
    appendText(out[0..], &pos, "/");
    appendU64(out[0..], &pos, @intCast(stats.full_refreshes_sent));
    appendText(out[0..], &pos, " chan=");
    appendU64(out[0..], &pos, @intCast(stats.last_channel_id));
    appendText(out[0..], &pos, " size=");
    appendU64(out[0..], &pos, @intCast(stats.last_client_width));
    appendText(out[0..], &pos, "x");
    appendU64(out[0..], &pos, @intCast(stats.last_client_height));
    appendText(out[0..], &pos, " session=");
    appendU64(out[0..], &pos, @intCast(stats.session_width));
    appendText(out[0..], &pos, "x");
    appendU64(out[0..], &pos, @intCast(stats.session_height));
    appendText(out[0..], &pos, " frame=");
    appendU64(out[0..], &pos, @intCast(stats.last_frame_width));
    appendText(out[0..], &pos, "x");
    appendU64(out[0..], &pos, @intCast(stats.last_frame_height));
    appendText(out[0..], &pos, " frame_rev=");
    appendU64(out[0..], &pos, @intCast(stats.last_frame_revision));
    appendText(out[0..], &pos, " dirty=");
    appendI32(out[0..], &pos, stats.last_frame_dirty_x);
    appendText(out[0..], &pos, ",");
    appendI32(out[0..], &pos, stats.last_frame_dirty_y);
    appendText(out[0..], &pos, ",");
    appendU64(out[0..], &pos, @intCast(stats.last_frame_dirty_w));
    appendText(out[0..], &pos, ",");
    appendU64(out[0..], &pos, @intCast(stats.last_frame_dirty_h));
    appendText(out[0..], &pos, " checksum=");
    appendU64(out[0..], &pos, @intCast(stats.last_frame_checksum));
    appendText(out[0..], &pos, " nonblack=");
    appendU64(out[0..], &pos, @intCast(stats.last_frame_non_black_pixels));
    appendText(out[0..], &pos, " input_pdus=");
    appendU64(out[0..], &pos, @intCast(stats.input_pdus));
    appendText(out[0..], &pos, " input_events=");
    appendU64(out[0..], &pos, @intCast(stats.input_events));
    appendText(out[0..], &pos, " input_keys=");
    appendU64(out[0..], &pos, @intCast(stats.input_keys));
    appendText(out[0..], &pos, " input_mouse=");
    appendU64(out[0..], &pos, @intCast(stats.input_mouse));
    appendText(out[0..], &pos, " input_wheel=");
    appendU64(out[0..], &pos, @intCast(stats.input_wheel));
    appendText(out[0..], &pos, " input_pushes=");
    appendU64(out[0..], &pos, @intCast(stats.input_pushes));
    appendText(out[0..], &pos, " input_status=");
    appendU64(out[0..], &pos, @intCast(stats.last_input_pushed_total));
    appendText(out[0..], &pos, ",");
    appendU64(out[0..], &pos, @intCast(stats.last_input_polled_total));
    appendText(out[0..], &pos, ",");
    appendU64(out[0..], &pos, @intCast(stats.last_input_pending));
    appendText(out[0..], &pos, ",");
    appendU64(out[0..], &pos, @intCast(stats.last_input_dropped_total));
    appendText(out[0..], &pos, " input_errors=");
    appendU64(out[0..], &pos, @intCast(stats.input_errors));
    appendText(out[0..], &pos, " input_last=");
    appendU64(out[0..], &pos, @intCast(stats.last_input_kind));
    appendText(out[0..], &pos, ",");
    appendU64(out[0..], &pos, @intCast(stats.last_input_key));
    appendText(out[0..], &pos, ",");
    appendI32(out[0..], &pos, stats.last_input_x);
    appendText(out[0..], &pos, ",");
    appendI32(out[0..], &pos, stats.last_input_y);
    appendText(out[0..], &pos, ",");
    appendI32(out[0..], &pos, stats.last_input_wheel);
    appendText(out[0..], &pos, ",");
    appendU64(out[0..], &pos, @intCast(stats.last_input_buttons));
    appendText(out[0..], &pos, " tcp_errors=");
    appendU64(out[0..], &pos, @intCast(stats.tcp_errors));
    appendText(out[0..], &pos, " last_tcp=");
    appendI32(out[0..], &pos, stats.last_tcp_result);
    appendText(out[0..], &pos, " conn=");
    appendU64(out[0..], &pos, @intCast(stats.last_client_conn));
    appendText(out[0..], &pos, " user=");
    appendText(out[0..], &pos, spanZ(config.user_name[0..]));
    appendText(out[0..], &pos, " logpw=");
    appendText(out[0..], &pos, if (config.log_passwords) "on" else "off");
    if (spanZ(stats.last_auth_user[0..]).len != 0) {
        appendText(out[0..], &pos, " last_auth_user=");
        appendText(out[0..], &pos, spanZ(stats.last_auth_user[0..]));
    }
    if (config.log_passwords and spanZ(stats.last_auth_password[0..]).len != 0) {
        appendText(out[0..], &pos, " last_password=");
        appendText(out[0..], &pos, spanZ(stats.last_auth_password[0..]));
    }
    if (spanZ(stats.last_failed_auth_user[0..]).len != 0) {
        appendText(out[0..], &pos, " last_failed_user=");
        appendText(out[0..], &pos, spanZ(stats.last_failed_auth_user[0..]));
    }
    if (config.log_passwords and spanZ(stats.last_failed_auth_password[0..]).len != 0) {
        appendText(out[0..], &pos, " failed_password=");
        appendText(out[0..], &pos, spanZ(stats.last_failed_auth_password[0..]));
    }
    appendText(out[0..], &pos, " repairs=");
    appendU64(out[0..], &pos, @intCast(stats.registry_repairs));
    appendText(out[0..], &pos, " last=");
    appendText(out[0..], &pos, spanZ(stats.last_error[0..]));
    return app.sys.serviceEndpointReply(endpoint_handle, request_id, r4os.abi.service_api_result_ok, out[0..pos]);
}

fn replyPing(app: *const App, endpoint_handle: u32, request_id: u32, stats: *ServiceStats) i32 {
    stats.pings +%= 1;
    return app.sys.serviceEndpointReply(endpoint_handle, request_id, r4os.abi.service_api_result_ok, "RDPSVC PONG");
}

fn pollClient(app: *const App, stats: *ServiceStats, config: *const Config, modern_security: *const ModernSecurityProfile, sessions: []SessionWorkerSlot) bool {
    if (stats.active_sessions >= sessionLimit(config)) {
        stats.max_session_waits +%= 1;
        setLastError(stats, "session-limit");
        return false;
    }

    var accept: r4os.abi.TcpAcceptResult = .{};
    var structured: r4os.abi.NetServiceTcpResult = .{};
    const rc = app.net.tcpAcceptPollServiceResultWait(config.listen_port, &accept, &structured, tcpServiceWaitTicks(app));
    if (rc == 0) return false;
    if (rc < 0) {
        stats.tcp_errors +%= 1;
        stats.last_tcp_result = rc;
        setLastError(stats, "accept");
        return false;
    }

    if (structured.conn_id == 0) {
        stats.tcp_errors +%= 1;
        stats.last_tcp_result = r4os.abi.tcp_result_no_connection;
        setLastError(stats, "accept-conn");
        _ = closeTcpHandle(app, accept.conn_id, stats);
        return true;
    }

    const stream = TcpStream{
        .service_handle = accept.conn_id,
        .conn_id = structured.conn_id,
    };

    if (stats.accepted != 0) stats.reconnects +%= 1;
    stats.accepted +%= 1;
    stats.active_sessions +%= 1;
    const session_id = stats.accepted;
    stats.last_session_id = session_id;
    stats.last_session_result = .accepted;
    stats.last_client_conn = stream.conn_id;
    stats.last_tcp_result = structured.result;
    setLastError(stats, "accepted");
    const slot = freeSessionSlot(sessions) orelse {
        stats.max_session_waits +%= 1;
        stats.active_sessions -|= 1;
        _ = closeTcpHandle(app, accept.conn_id, stats);
        setLastError(stats, "worker-slots");
        return true;
    };
    slot.* = .{
        .used = true,
        .session_id = session_id,
        .stream = stream,
        .started_tick = app.sys.ticks(),
        .app = app,
        .config = config.*,
        .modern_security = modern_security.*,
        .stats = .{
            .last_session_id = session_id,
            .last_session_result = .accepted,
            .last_client_conn = stream.conn_id,
        },
    };
    app.sys.write("RDPSVC client accepted conn=");
    app.sys.printU64(@intCast(stream.conn_id));
    app.sys.write(" handle=");
    app.sys.printU64(@intCast(stream.service_handle));
    app.sys.println("");

    var thread_handle: r4os.abi.ProgramJoinHandle = .{};
    const spawn_rc = app.sys.threadCreateHandle(rdpSessionWorkerMain, @intFromPtr(slot), session_worker_stack_bytes, 0, &thread_handle);
    if (spawn_rc != r4os.abi.thread_ok) {
        stats.session_worker_create_failed +%= 1;
        stats.tcp_errors +%= 1;
        stats.active_sessions -|= 1;
        slot.* = .{};
        _ = closeTcpHandle(app, stream.service_handle, stats);
        setLastError(stats, "worker-spawn");
        return true;
    }
    slot.thread_handle = thread_handle;
    stats.session_worker_started +%= 1;
    stats.last_worker_id = session_id;
    stats.last_worker_thread = thread_handle.thread_id;
    app.sys.write("RDPSVC session worker=");
    app.sys.printU64(@intCast(session_id));
    app.sys.write(" thread=");
    app.sys.printU64(@intCast(thread_handle.thread_id));
    app.sys.println("");
    return true;
}

fn rdpSessionWorkerMain(arg: u64) callconv(.c) i32 {
    const slot: *SessionWorkerSlot = @ptrFromInt(arg);
    const app = slot.app;
    var session_result = handleRdpClient(app, slot.stream, &slot.stats, &slot.config, &slot.modern_security);
    slot.result = session_result;
    slot.stats.last_session_result = session_result;
    // 0.56.35: echte Ursache sichern, bevor der Close last_error auf "closed"
    // setzt (siehe session_end_error).
    copyFixedZ(slot.stats.session_end_error[0..], spanZ(slot.stats.last_error[0..]));
    if (session_result == .input_ok or session_result == .client_disconnect or session_result == .tls_wire_ok or session_result == .credssp_live_ok or session_result == .modern_activation_ok) {
        slot.stats.completed_sessions +%= 1;
    }

    slot.close_ok = closeTcpHandleWithResult(app, slot.stream.service_handle, &slot.stats, &slot.close_result);
    if (slot.close_ok) {
        slot.stats.closed +%= 1;
        setLastError(&slot.stats, "closed");
        app.sys.write("RDPSVC client closed conn=");
        app.sys.printU64(@intCast(slot.stream.conn_id));
        app.sys.println("");
    } else {
        slot.stats.tcp_errors +%= 1;
        slot.stats.close_errors +%= 1;
        session_result = .close_error;
        slot.result = session_result;
        slot.stats.last_session_result = session_result;
        setLastError(&slot.stats, "close");
        app.sys.write("RDPSVC client close failed conn=");
        app.sys.printU64(@intCast(slot.stream.conn_id));
        app.sys.write(" rc=");
        app.sys.printI32(slot.close_result);
        app.sys.println("");
    }
    if (slot.close_ok) {
        slot.stats.cleanup_ok +%= 1;
    } else {
        slot.stats.cleanup_errors +%= 1;
    }
    slot.exit_code = @intFromEnum(slot.result);
    slot.finished_tick = app.sys.ticks();
    app.sys.threadExit(slot.exit_code);
    return slot.exit_code;
}

fn pollSessionWorkers(app: *const App, stats: *ServiceStats, sessions: []SessionWorkerSlot, stopping: bool) void {
    const now = app.sys.ticks();
    const slow_ticks = app.sys.ticksFromMilliseconds(session_slow_warn_ms);
    var i: usize = 0;
    while (i < sessions.len) : (i += 1) {
        var slot = &sessions[i];
        if (!slot.used) continue;
        if (!slot.slow_reported and slow_ticks != 0 and now - slot.started_tick >= slow_ticks) {
            slot.slow_reported = true;
            stats.session_slow_clients +%= 1;
        }
        var exit_code: i32 = 0;
        const wait_ticks: u64 = if (stopping) session_stop_join_ticks else 0;
        const join_rc = app.sys.threadHandleJoin(&slot.thread_handle, wait_ticks, &exit_code);
        if (join_rc == r4os.abi.thread_error_timeout) continue;
        if (join_rc != r4os.abi.thread_ok) {
            stats.session_worker_join_errors +%= 1;
            stats.active_sessions -|= 1;
            slot.* = .{};
            continue;
        }
        slot.exit_code = exit_code;
        finishSessionWorker(app, stats, slot);
    }
}

fn stopSessionWorkers(app: *const App, stats: *ServiceStats, sessions: []SessionWorkerSlot) void {
    var i: usize = 0;
    while (i < sessions.len) : (i += 1) {
        if (sessions[i].used and sessions[i].stream.service_handle != 0) _ = app.net.tcpAbortServiceWait(sessions[i].stream.service_handle, tcpServiceCleanupWaitTicks(app));
    }
    var waited: u32 = 0;
    while (waited < 8 and stats.active_sessions != 0) : (waited += 1) {
        pollSessionWorkers(app, stats, sessions, true);
        app.sys.sleepTicks(1);
    }
}

fn closeTcpHandle(app: *const App, handle: u32, stats: *ServiceStats) bool {
    var close_result: i32 = 0;
    return closeTcpHandleWithResult(app, handle, stats, &close_result);
}

fn closeTcpHandleWithResult(app: *const App, handle: u32, stats: *ServiceStats, close_result_out: *i32) bool {
    if (handle == 0) {
        close_result_out.* = r4os.abi.tcp_result_no_connection;
        stats.last_tcp_result = r4os.abi.tcp_result_no_connection;
        return true;
    }

    var close_result: r4os.abi.NetServiceTcpResult = .{};
    const close_rc = app.net.tcpCloseServiceResultWait(handle, &close_result, tcpServiceCleanupWaitTicks(app));
    close_result_out.* = if (close_rc == 0) close_result.result else close_rc;
    stats.last_tcp_result = close_result_out.*;
    if (close_rc == 0 and (close_result.result == r4os.abi.tcp_result_ok or close_result.result == r4os.abi.tcp_result_no_connection)) return true;

    var abort_result: r4os.abi.NetServiceTcpResult = .{};
    const abort_rc = app.net.tcpAbortServiceResultWait(handle, &abort_result, tcpServiceCleanupWaitTicks(app));
    close_result_out.* = if (abort_rc == 0) abort_result.result else abort_rc;
    stats.last_tcp_result = close_result_out.*;
    return abort_rc == 0 and (abort_result.result == r4os.abi.tcp_result_ok or abort_result.result == r4os.abi.tcp_result_no_connection);
}

fn finishSessionWorker(app: *const App, stats: *ServiceStats, slot: *SessionWorkerSlot) void {
    const end_tick = if (slot.finished_tick != 0) slot.finished_tick else app.sys.ticks();
    const elapsed = if (end_tick >= slot.started_tick) end_tick - slot.started_tick else 0;
    mergeSessionStats(stats, &slot.stats);
    stats.session_worker_completed +%= 1;
    stats.session_worker_joined +%= 1;
    stats.active_sessions -|= 1;
    stats.last_session_id = slot.session_id;
    stats.last_session_result = slot.result;
    stats.last_worker_id = slot.session_id;
    stats.last_worker_thread = slot.thread_handle.thread_id;
    stats.last_worker_exit = slot.exit_code;
    stats.last_session_ticks = elapsed;
    if (elapsed > stats.max_session_ticks) stats.max_session_ticks = elapsed;
    logLifecycle(app, stats, slot.stream, slot.result, slot.close_ok);
    app.sys.write("RDPSVC session done worker=");
    app.sys.printU64(@intCast(slot.session_id));
    app.sys.write(" thread=");
    app.sys.printU64(@intCast(slot.thread_handle.thread_id));
    app.sys.write(" result=");
    app.sys.write(sessionResultName(slot.result));
    app.sys.write(" ticks=");
    app.sys.printU64(elapsed);
    app.sys.println("");
    slot.* = .{};
}

fn freeSessionSlot(sessions: []SessionWorkerSlot) ?*SessionWorkerSlot {
    var i: usize = 0;
    while (i < sessions.len) : (i += 1) {
        if (!sessions[i].used) return &sessions[i];
    }
    return null;
}

fn sessionLimit(config: *const Config) u32 {
    const cap: u32 = @intCast(session_worker_slots_max);
    if (config.max_sessions == 0) return 1;
    return @min(config.max_sessions, cap);
}

fn mergeSessionStats(out: *ServiceStats, session: *const ServiceStats) void {
    out.closed +%= session.closed;
    out.completed_sessions +%= session.completed_sessions;
    out.disconnects +%= session.disconnects;
    out.cleanup_ok +%= session.cleanup_ok;
    out.cleanup_errors +%= session.cleanup_errors;
    out.close_errors +%= session.close_errors;
    out.negotiation_ok +%= session.negotiation_ok;
    out.compat_classic_selected +%= session.compat_classic_selected;
    out.compat_modern_requests +%= session.compat_modern_requests;
    out.compat_tls_requests +%= session.compat_tls_requests;
    out.compat_nla_requests +%= session.compat_nla_requests;
    out.compat_rdstls_requests +%= session.compat_rdstls_requests;
    out.compat_hybrid_ex_requests +%= session.compat_hybrid_ex_requests;
    out.compat_unknown_requests +%= session.compat_unknown_requests;
    out.compat_classic_downgrades +%= session.compat_classic_downgrades;
    out.security_classic +%= session.security_classic;
    out.security_tls +%= session.security_tls;
    out.security_credssp +%= session.security_credssp;
    out.security_auth_ok +%= session.security_auth_ok;
    out.security_auth_fail +%= session.security_auth_fail;
    out.security_tls_alert +%= session.security_tls_alert;
    out.security_blockers +%= session.security_blockers;
    out.r4tls_dispatch_ok +%= session.r4tls_dispatch_ok;
    out.r4auth_dispatch_ok +%= session.r4auth_dispatch_ok;
    out.r4tls_session_ok +%= session.r4tls_session_ok;
    out.r4tls_live_ok +%= session.r4tls_live_ok;
    out.r4tls_stream_ok +%= session.r4tls_stream_ok;
    out.r4tls_wire_begin_ok +%= session.r4tls_wire_begin_ok;
    out.r4tls_wire_finish_ok +%= session.r4tls_wire_finish_ok;
    out.r4tls_wire_records +%= session.r4tls_wire_records;
    out.r4tls_wire_errors +%= session.r4tls_wire_errors;
    out.r4tls_app_write_ok +%= session.r4tls_app_write_ok;
    out.r4tls_app_read_ok +%= session.r4tls_app_read_ok;
    out.r4auth_windows_ok +%= session.r4auth_windows_ok;
    out.r4auth_live_ok +%= session.r4auth_live_ok;
    out.r4auth_loop_ok +%= session.r4auth_loop_ok;
    out.r4auth_live_negotiate_ok +%= session.r4auth_live_negotiate_ok;
    out.r4auth_live_authenticate_ok +%= session.r4auth_live_authenticate_ok;
    out.r4auth_live_pubkey_ok +%= session.r4auth_live_pubkey_ok;
    out.r4auth_live_errors +%= session.r4auth_live_errors;
    out.modern_activation_ok +%= session.modern_activation_ok;
    out.modern_stream_activation_ok +%= session.modern_stream_activation_ok;
    out.mcs_connect_initial +%= session.mcs_connect_initial;
    out.mcs_connect_response +%= session.mcs_connect_response;
    out.mcs_erect_domain +%= session.mcs_erect_domain;
    out.mcs_attach_user +%= session.mcs_attach_user;
    out.mcs_channel_joins +%= session.mcs_channel_joins;
    out.mcs_static_channels +%= session.mcs_static_channels;
    out.mcs_expected_channel_joins +%= session.mcs_expected_channel_joins;
    out.security_none +%= session.security_none;
    out.security_exchange +%= session.security_exchange;
    out.client_info +%= session.client_info;
    out.license_valid_client +%= session.license_valid_client;
    out.auth_successes +%= session.auth_successes;
    out.auth_failures +%= session.auth_failures;
    out.demand_active +%= session.demand_active;
    out.confirm_active +%= session.confirm_active;
    out.client_sync +%= session.client_sync;
    out.client_control +%= session.client_control;
    out.font_list +%= session.font_list;
    out.font_map +%= session.font_map;
    out.activation_ok +%= session.activation_ok;
    out.bitmap_frames +%= session.bitmap_frames;
    out.bitmap_updates +%= session.bitmap_updates;
    out.bitmap_rectangles +%= session.bitmap_rectangles;
    out.bitmap_pixels +%= session.bitmap_pixels;
    out.bitmap_bytes +%= session.bitmap_bytes;
    out.bitmap_errors +%= session.bitmap_errors;
    out.bitmap_comp_bytes +%= session.bitmap_comp_bytes;
    out.bitmap_raw_bytes +%= session.bitmap_raw_bytes;
    out.bitmap_rle_rows +%= session.bitmap_rle_rows;
    out.bitmap_raw_rows +%= session.bitmap_raw_rows;
    out.bitmap_map_rows +%= session.bitmap_map_rows;
    out.bitmap_copy_rows +%= session.bitmap_copy_rows;
    out.refresh_rect_pdus +%= session.refresh_rect_pdus;
    out.suppress_output_pdus +%= session.suppress_output_pdus;
    out.full_refreshes_sent +%= session.full_refreshes_sent;
    out.input_pdus +%= session.input_pdus;
    out.input_events +%= session.input_events;
    out.input_keys +%= session.input_keys;
    out.input_mouse +%= session.input_mouse;
    out.input_wheel +%= session.input_wheel;
    out.input_errors +%= session.input_errors;
    out.input_pushes +%= session.input_pushes;
    out.protocol_packets +%= session.protocol_packets;
    out.protocol_errors +%= session.protocol_errors;
    out.protocol_timeouts +%= session.protocol_timeouts;
    out.bytes_rx +%= session.bytes_rx;
    out.bytes_tx +%= session.bytes_tx;
    out.tcp_errors +%= session.tcp_errors;
    if (session.last_session_id != 0) out.last_session_id = session.last_session_id;
    out.last_session_result = session.last_session_result;
    if (session.last_disconnect_state != 255) out.last_disconnect_state = session.last_disconnect_state;
    if (session.last_packet_len != 0) out.last_packet_len = session.last_packet_len;
    if (session.last_x224_type != 0) out.last_x224_type = session.last_x224_type;
    if (session.last_requested_protocols != 0) out.last_requested_protocols = session.last_requested_protocols;
    if (session.last_selected_protocol != 0) out.last_selected_protocol = session.last_selected_protocol;
    if (session.last_compat_mask != 0) out.last_compat_mask = session.last_compat_mask;
    if (session.last_channel_id != 0) out.last_channel_id = session.last_channel_id;
    if (session.last_client_width != 0) out.last_client_width = session.last_client_width;
    if (session.last_client_height != 0) out.last_client_height = session.last_client_height;
    if (session.session_width != 0) out.session_width = session.session_width;
    if (session.session_height != 0) out.session_height = session.session_height;
    if (session.bitmap_frames != 0) {
        out.last_frame_revision = session.last_frame_revision;
        out.last_frame_width = session.last_frame_width;
        out.last_frame_height = session.last_frame_height;
        out.last_frame_region_x = session.last_frame_region_x;
        out.last_frame_region_y = session.last_frame_region_y;
        out.last_frame_region_w = session.last_frame_region_w;
        out.last_frame_region_h = session.last_frame_region_h;
        out.last_frame_dirty_x = session.last_frame_dirty_x;
        out.last_frame_dirty_y = session.last_frame_dirty_y;
        out.last_frame_dirty_w = session.last_frame_dirty_w;
        out.last_frame_dirty_h = session.last_frame_dirty_h;
        out.last_frame_checksum = session.last_frame_checksum;
        out.last_frame_non_black_pixels = session.last_frame_non_black_pixels;
    }
    if (session.last_input_sequence != 0) out.last_input_sequence = session.last_input_sequence;
    if (session.last_input_kind != 0) out.last_input_kind = session.last_input_kind;
    if (session.last_input_key != 0) out.last_input_key = session.last_input_key;
    if (session.last_input_scancode != 0) out.last_input_scancode = session.last_input_scancode;
    if (session.last_input_modifiers != 0) out.last_input_modifiers = session.last_input_modifiers;
    if (session.last_input_x != 0) out.last_input_x = session.last_input_x;
    if (session.last_input_y != 0) out.last_input_y = session.last_input_y;
    if (session.last_input_wheel != 0) out.last_input_wheel = session.last_input_wheel;
    if (session.last_input_buttons != 0) out.last_input_buttons = session.last_input_buttons;
    if (session.last_input_pending != 0) out.last_input_pending = session.last_input_pending;
    if (session.last_input_pushed_total != 0) out.last_input_pushed_total = session.last_input_pushed_total;
    if (session.last_input_polled_total != 0) out.last_input_polled_total = session.last_input_polled_total;
    if (session.last_input_dropped_total != 0) out.last_input_dropped_total = session.last_input_dropped_total;
    if (session.last_tcp_result != 0) out.last_tcp_result = session.last_tcp_result;
    if (session.last_client_conn != 0) out.last_client_conn = session.last_client_conn;
    copyLatestZ(out.last_auth_user[0..], session.last_auth_user[0..]);
    copyLatestZ(out.last_auth_password[0..], session.last_auth_password[0..]);
    copyLatestZ(out.last_failed_auth_user[0..], session.last_failed_auth_user[0..]);
    copyLatestZ(out.last_failed_auth_password[0..], session.last_failed_auth_password[0..]);
    copyLatestZ(out.last_error[0..], session.last_error[0..]);
    copyLatestZ(out.session_end_error[0..], session.session_end_error[0..]);
    copyLatestZ(out.last_activation_trace[0..], session.last_activation_trace[0..]);
    copyLatestZ(out.last_compat_blocker[0..], session.last_compat_blocker[0..]);
    copyLatestZ(out.last_security_state[0..], session.last_security_state[0..]);
}

fn copyLatestZ(dest: []u8, src: []const u8) void {
    if (spanZ(src).len != 0) copyFixedZ(dest, spanZ(src));
}

const RdpInitial = struct {
    source_ref: u16 = 0,
    requested_protocols: u32 = 0,
    has_negotiation: bool = false,
};

fn recordNegotiationCompatibility(stats: *ServiceStats, initial: *const RdpInitial) void {
    const requested = if (initial.has_negotiation) initial.requested_protocols else rdp_protocol_rdp;
    const modern = requested & rdp_protocol_modern_mask;
    const unknown = requested & ~rdp_protocol_modern_mask;
    const selected = selectedProtocolForInitial(initial);

    stats.last_requested_protocols = requested;
    stats.last_selected_protocol = selected;
    stats.last_compat_mask = modern | unknown;

    if ((requested & rdp_protocol_ssl) != 0) stats.compat_tls_requests +%= 1;
    if ((requested & rdp_protocol_rdstls) != 0) stats.compat_rdstls_requests +%= 1;
    if ((requested & rdp_protocol_hybrid) != 0 or (requested & rdp_protocol_hybrid_ex) != 0) stats.compat_nla_requests +%= 1;
    if ((requested & rdp_protocol_hybrid_ex) != 0) stats.compat_hybrid_ex_requests +%= 1;
    if (modern != 0) stats.compat_modern_requests +%= 1;
    if (unknown != 0) stats.compat_unknown_requests +%= 1;

    if (unknown != 0 and modern == 0) {
        stats.security_blockers +%= 1;
        copyFixedZ(stats.last_security_state[0..], security_state_blocker);
        copyFixedZ(stats.last_compat_blocker[0..], "unknown-negotiation-mask");
    } else if (selected == rdp_protocol_rdstls) {
        stats.security_blockers +%= 1;
        copyFixedZ(stats.last_security_state[0..], security_state_blocker);
        copyFixedZ(stats.last_compat_blocker[0..], "rdstls-not-supported");
    } else if (selected == rdp_protocol_rdp) {
        stats.compat_classic_selected +%= 1;
        stats.security_classic +%= 1;
        copyFixedZ(stats.last_security_state[0..], security_state_classic);
        copyFixedZ(stats.last_compat_blocker[0..], "none");
    } else {
        stats.security_tls +%= 1;
        if (isCredsspSelected(selected)) {
            stats.security_credssp +%= 1;
            copyFixedZ(stats.last_security_state[0..], security_state_credssp);
        } else {
            copyFixedZ(stats.last_security_state[0..], security_state_tls);
        }
        copyFixedZ(stats.last_compat_blocker[0..], "none");
    }
}

fn selectedProtocolForInitial(initial: *const RdpInitial) u32 {
    if (!initial.has_negotiation or initial.requested_protocols == 0) return rdp_protocol_rdp;
    const requested = initial.requested_protocols;
    if ((requested & rdp_protocol_hybrid_ex) != 0) return rdp_protocol_hybrid_ex;
    if ((requested & rdp_protocol_hybrid) != 0) return rdp_protocol_hybrid;
    if ((requested & rdp_protocol_ssl) != 0) return rdp_protocol_ssl;
    if ((requested & rdp_protocol_rdstls) != 0) return rdp_protocol_rdstls;
    return rdp_protocol_rdp;
}

fn isModernSelected(protocol: u32) bool {
    return protocol == rdp_protocol_ssl or protocol == rdp_protocol_hybrid or protocol == rdp_protocol_hybrid_ex;
}

fn isCredsspSelected(protocol: u32) bool {
    return protocol == rdp_protocol_hybrid or protocol == rdp_protocol_hybrid_ex;
}

const RdpClientInfo = struct {
    user_name: [32]u8 = .{0} ** 32,
    password: [64]u8 = .{0} ** 64,
};

const BitmapSendState = struct {
    batch_start_seq: u32 = 0,
    pending_bytes: u32 = 0,
};

// 0.56.35: Cursor-Geisterspur. R4OS zeichnet den Cursor in den Framebuffer;
// bei niedriger Update-Rate faellt der "alte Position aufraeumen"-Frame
// zwischen zwei RDP-Updates weg -> mstsc behaelt alte Cursor-Abbilder. Fix:
// letzte an den Client gesendete Cursor-Position merken und die naechste
// Dirty-Region um die Bounding-Box alt->neu erweitern (dieser Pfad ist im
// AKTUELLEN Frame bereits sauber = Hintergrund + Cursor an der neuen Stelle,
// so werden die Geister ueberschrieben).
const CursorTrack = struct {
    x: i32 = -1,
    y: i32 = -1,
};
// Rand um die Cursor-Bounding-Box (Cursorgroesse + Reserve).
const rdp_cursor_margin: u32 = 24;
// Obergrenze fuer die Cursor-Aufraeum-Box; bei groesseren Spruengen raeumt
// der naechste regulaere Frame auf statt ein Riesen-Update zu erzwingen.
const rdp_cursor_max_span: u32 = 400;

const TcpStream = struct {
    service_handle: u32 = 0,
    conn_id: u32 = 0,
};

const TlsWireState = struct {
    active: bool = false,
    stream_state: [r4tls_live_stream_state_len]u8 = .{0} ** r4tls_live_stream_state_len,
    rdp_pending: [tls_rdp_pending_capacity]u8 = .{0} ** tls_rdp_pending_capacity,
    rdp_pending_start: usize = 0,
    rdp_pending_len: usize = 0,
};

const RdpActivationMode = enum(u8) {
    classic_plain,
    modern_protected,
};

const RdpTransport = struct {
    tls: ?*TlsWireState = null,

    fn plain() RdpTransport {
        return .{};
    }

    fn protected(tls: *TlsWireState) RdpTransport {
        return .{ .tls = tls };
    }
};

fn handleRdpClient(app: *const App, stream: TcpStream, stats: *ServiceStats, config: *const Config, modern_security: *const ModernSecurityProfile) SessionResult {
    var packet: [rdp_max_packet]u8 = .{0} ** rdp_max_packet;
    const packet_len = readTpktPacket(app, stream, packet[0..], 11, stats, "initial") orelse return classifySessionError(stats);
    var initial = parseInitialPacket(packet[0..packet_len], stats) orelse return classifySessionError(stats);
    var response: [32]u8 = .{0} ** 32;
    const response_len = buildConnectionConfirm(response[0..], &initial) orelse {
        stats.protocol_errors +%= 1;
        setLastError(stats, "response-build");
        return .protocol_error;
    };
    if (!sendAll(app, stream, response[0..response_len], stats, "connection-confirm")) return .tcp_error;
    stats.negotiation_ok +%= 1;
    recordNegotiationCompatibility(stats, &initial);
    if (bytesEq(spanZ(stats.last_security_state[0..]), security_state_blocker)) {
        setLastError(stats, spanZ(stats.last_compat_blocker[0..]));
    } else {
        setLastError(stats, if (initial.has_negotiation) "negotiated" else "x224-confirm");
    }
    app.sys.write("RDPSVC negotiation OK conn=");
    app.sys.printU64(@intCast(stream.conn_id));
    app.sys.write(" requested=");
    app.sys.printU64(@intCast(initial.requested_protocols));
    app.sys.write(" selected=");
    app.sys.printU64(@intCast(stats.last_selected_protocol));
    app.sys.write(" state=");
    app.sys.write(spanZ(stats.last_security_state[0..]));
    app.sys.write(" compat=");
    app.sys.write(spanZ(stats.last_compat_blocker[0..]));
    app.sys.println("");

    if (isModernSelected(stats.last_selected_protocol)) {
        if (!runModernSecurityPrelude(app, stream, packet[0..], stats, config, modern_security, &initial)) return classifySessionError(stats);
        var tls_wire = TlsWireState{};
        if (runModernTlsWireHandshake(app, stream, stats, &tls_wire)) {
            app.sys.write("RDPSVC TLS wire OK conn=");
            app.sys.printU64(@intCast(stream.conn_id));
            app.sys.println("");
            if (isCredsspSelected(stats.last_selected_protocol)) {
                if (runModernCredsspLiveLoop(app, stream, stats, config, &tls_wire)) {
                    app.sys.write("RDPSVC CredSSP live OK conn=");
                    app.sys.printU64(@intCast(stream.conn_id));
                    app.sys.println("");
                    if (runModernProtectedActivation(app, stream, packet[0..], stats, config, &initial, &tls_wire)) {
                        app.sys.write("RDPSVC modern protected activation OK conn=");
                        app.sys.printU64(@intCast(stream.conn_id));
                        app.sys.println("");
                        return runRdpSessionLoop(app, stream, RdpTransport.protected(&tls_wire), packet[0..], stats);
                    }
                    return classifySessionError(stats);
                }
                return classifySessionError(stats);
            }
            if (runModernProtectedActivation(app, stream, packet[0..], stats, config, &initial, &tls_wire)) {
                app.sys.write("RDPSVC modern TLS-only protected activation OK conn=");
                app.sys.printU64(@intCast(stream.conn_id));
                app.sys.println("");
                return runRdpSessionLoop(app, stream, RdpTransport.protected(&tls_wire), packet[0..], stats);
            }
            return classifySessionError(stats);
        }
        return classifySessionError(stats);
    }
    if (stats.last_selected_protocol != rdp_protocol_rdp or bytesEq(spanZ(stats.last_security_state[0..]), security_state_blocker)) {
        stats.protocol_errors +%= 1;
        return classifySessionError(stats);
    }

    if (runClassicActivation(app, stream, packet[0..], stats, config, &initial)) {
        stats.activation_ok +%= 1;
        setLastError(stats, "activated");
        app.sys.write("RDPSVC activation OK conn=");
        app.sys.printU64(@intCast(stream.conn_id));
        app.sys.println("");
        return runRdpSessionLoop(app, stream, RdpTransport.plain(), packet[0..], stats);
    }
    return classifySessionError(stats);
}

fn classifySessionError(stats: *const ServiceStats) SessionResult {
    const last = spanZ(stats.last_error[0..]);
    if (bytesEq(last, "auth-fail") or bytesEq(last, "credssp-bad-password") or bytesEq(last, "credssp-bad-pubkeyauth")) return .auth_failed;
    if (bytesEq(last, "initial") or bytesEq(last, "read-body") or bytesEq(last, "input-pdu")) return .timeout;
    return .protocol_error;
}

fn tcpConnectionState(app: *const App, conn_id: u32) ?u32 {
    var index: u32 = 0;
    while (index < @as(u32, @intCast(r4os.abi.net_detail_max_tcp_connections))) : (index += 1) {
        var info: r4os.abi.TcpConnectionInfo = .{};
        if (app.net.tcpConnection(index, &info) <= 0) continue;
        if (info.id == conn_id) return info.state;
    }
    return null;
}

fn readTpktPacket(app: *const App, stream: TcpStream, out: []u8, min_len: u16, stats: *ServiceStats, stage: []const u8) ?usize {
    return readTpktPacketWithTimeout(app, stream, out, min_len, stats, stage, rdp_handshake_timeout_ms);
}

fn readTpktPacketWithTimeout(app: *const App, stream: TcpStream, out: []u8, min_len: u16, stats: *ServiceStats, stage: []const u8, timeout_ms: u64) ?usize {
    if (out.len < 4) return null;
    const timeout = app.sys.ticksFromMilliseconds(timeout_ms);
    if (!readExact(app, stream, out[0..4], timeout)) {
        stats.protocol_timeouts +%= 1;
        setLastError(stats, stage);
        return null;
    }
    if (out[0] != 3 or out[1] != 0) {
        stats.protocol_errors +%= 1;
        stats.last_packet_len = 0;
        setLastError(stats, "tpkt-version");
        return null;
    }
    const total_len = readBe16(out[2..4]);
    stats.last_packet_len = total_len;
    if (total_len < min_len or total_len > out.len) {
        stats.protocol_errors +%= 1;
        setLastError(stats, "tpkt-length");
        return null;
    }
    if (!readExact(app, stream, out[4..@intCast(total_len)], timeout)) {
        stats.protocol_timeouts +%= 1;
        setLastError(stats, "read-body");
        return null;
    }
    stats.bytes_rx +%= total_len;
    stats.protocol_packets +%= 1;
    return @intCast(total_len);
}

fn readRdpPacket(app: *const App, stream: TcpStream, transport: RdpTransport, out: []u8, min_len: u16, stats: *ServiceStats, stage: []const u8) ?usize {
    return readRdpPacketWithTimeout(app, stream, transport, out, min_len, stats, stage, rdp_handshake_timeout_ms);
}

fn readRdpPacketWithTimeout(app: *const App, stream: TcpStream, transport: RdpTransport, out: []u8, min_len: u16, stats: *ServiceStats, stage: []const u8, timeout_ms: u64) ?usize {
    if (transport.tls) |tls| {
        return tlsWireReadRdpPacket(app, stream, tls, out, min_len, stats, stage, timeout_ms);
    }
    return readTpktPacketWithTimeout(app, stream, out, min_len, stats, stage, timeout_ms);
}

fn validateRdpPacketBytes(packet: []const u8, min_len: u16, stats: *ServiceStats, stage: []const u8) ?usize {
    if (packet.len < 4) {
        stats.protocol_errors +%= 1;
        stats.last_packet_len = @intCast(packet.len);
        setLastError(stats, stage);
        return null;
    }
    if (packet[0] != 3 or packet[1] != 0) {
        stats.protocol_errors +%= 1;
        stats.last_packet_len = @intCast(packet.len);
        setLastError(stats, "tpkt-version");
        return null;
    }
    const total_len = readBe16(packet[2..4]);
    stats.last_packet_len = total_len;
    if (total_len < min_len or total_len > packet.len or total_len != packet.len) {
        stats.protocol_errors +%= 1;
        setLastError(stats, "tpkt-length");
        return null;
    }
    return packet.len;
}

fn parseInitialPacket(packet: []const u8, stats: *ServiceStats) ?RdpInitial {
    if (packet.len < 11) return protocolError(stats, "packet-short");
    const x224 = packet[4..];
    const li: usize = x224[0];
    if (li + 1 != x224.len) return protocolError(stats, "x224-length");
    const pdu_type = x224[1] & 0xF0;
    stats.last_x224_type = pdu_type;
    if (pdu_type != x224_cr_type) return protocolError(stats, "x224-type");
    if (li < 6 or x224.len < 7) return protocolError(stats, "x224-short");

    var initial = RdpInitial{
        .source_ref = readBe16(x224[4..6]),
    };
    const user_data = x224[7..];
    if (findNegotiationRequest(user_data)) |offset| {
        if (offset + 8 > user_data.len) return protocolError(stats, "neg-short");
        const req = user_data[offset .. offset + 8];
        const length = readLe16(req[2..4]);
        if (req[0] != rdp_neg_req_type or length != 8) return protocolError(stats, "neg-length");
        initial.has_negotiation = true;
        initial.requested_protocols = readLe32(req[4..8]);
        stats.last_requested_protocols = initial.requested_protocols;
    } else {
        stats.last_requested_protocols = 0;
    }
    return initial;
}

fn protocolError(stats: *ServiceStats, label: []const u8) ?RdpInitial {
    stats.protocol_errors +%= 1;
    setLastError(stats, label);
    return null;
}

fn findNegotiationRequest(data: []const u8) ?usize {
    var i: usize = 0;
    while (i + 8 <= data.len) : (i += 1) {
        if (data[i] != rdp_neg_req_type) continue;
        const length = readLe16(data[i + 2 .. i + 4]);
        if (length == 8 and i + @as(usize, @intCast(length)) <= data.len) return i;
    }
    return null;
}

fn buildConnectionConfirm(out: []u8, initial: *const RdpInitial) ?usize {
    const has_negotiation = initial.has_negotiation;
    const total_len: u16 = if (has_negotiation) 19 else 11;
    if (out.len < total_len) return null;
    out[0] = 3;
    out[1] = 0;
    writeBe16(out[2..4], total_len);
    out[4] = if (has_negotiation) 14 else 6;
    out[5] = x224_cc_type;
    writeBe16(out[6..8], initial.source_ref);
    out[8] = 0;
    out[9] = 0;
    out[10] = 0;
    if (has_negotiation) {
        out[11] = rdp_neg_resp_type;
        out[12] = 0;
        writeLe16(out[13..15], 8);
        writeLe32(out[15..19], selectedProtocolForInitial(initial));
    }
    return total_len;
}

fn readExact(app: *const App, stream: TcpStream, out: []u8, timeout_ticks: u64) bool {
    var offset: usize = 0;
    const start = app.sys.ticks();
    while (offset < out.len and app.sys.ticks() - start < timeout_ticks) {
        const got = app.net.tcpReadWaitServiceBounded(stream.service_handle, out[offset..], app.sys.ticksFromMilliseconds(50), tcpServiceWaitTicks(app));
        if (got < 0) return false;
        if (got == 0) {
            app.sys.sleepTicks(1);
            continue;
        }
        offset += @intCast(got);
    }
    return offset == out.len;
}

fn prepareModernSecurityProfile(app: *const App, stats: *ServiceStats, config: *const Config) ModernSecurityProfile {
    var profile = ModernSecurityProfile{};
    var probe: ServiceStats = .{};
    if (selfTestModernProtocolContracts(app, &probe, config)) {
        profile.ready = true;
        profile.tls_session_ready = probe.r4tls_session_ok != 0;
        profile.tls_live_ready = probe.r4tls_live_ok != 0;
        profile.tls_stream_ready = probe.r4tls_stream_ok != 0;
        profile.credssp_windows_ready = probe.r4auth_windows_ok != 0;
        profile.credssp_live_ready = probe.r4auth_live_ok != 0;
        profile.credssp_loop_ready = probe.r4auth_loop_ok != 0;
        copyFixedZ(profile.blocker[0..], "none");
        stats.r4tls_dispatch_ok +%= probe.r4tls_dispatch_ok;
        stats.r4auth_dispatch_ok +%= probe.r4auth_dispatch_ok;
        stats.r4tls_session_ok +%= probe.r4tls_session_ok;
        stats.r4tls_live_ok +%= probe.r4tls_live_ok;
        stats.r4tls_stream_ok +%= probe.r4tls_stream_ok;
        stats.r4auth_windows_ok +%= probe.r4auth_windows_ok;
        stats.r4auth_live_ok +%= probe.r4auth_live_ok;
        stats.r4auth_loop_ok +%= probe.r4auth_loop_ok;
        stats.auth_successes +%= probe.auth_successes;
        stats.security_auth_ok +%= probe.security_auth_ok;
        app.sys.println("RDPSVC modern security profile: ready");
        return profile;
    }

    const blocker = if (spanZ(probe.last_compat_blocker[0..]).len != 0)
        spanZ(probe.last_compat_blocker[0..])
    else if (spanZ(probe.last_error[0..]).len != 0)
        spanZ(probe.last_error[0..])
    else
        "modern-contract";
    copyFixedZ(profile.blocker[0..], blocker);
    stats.security_blockers +%= 1;
    stats.protocol_errors +%= 1;
    copyFixedZ(stats.last_compat_blocker[0..], blocker);
    copyFixedZ(stats.last_security_state[0..], security_state_blocker);
    setLastError(stats, blocker);
    app.sys.write("RDPSVC modern security profile: blocked=");
    app.sys.write(blocker);
    app.sys.println("");
    return profile;
}

fn runModernSecurityPrelude(app: *const App, stream: TcpStream, scratch: []u8, stats: *ServiceStats, config: *const Config, modern_security: *const ModernSecurityProfile, initial: *const RdpInitial) bool {
    _ = scratch;
    _ = initial;
    if (!modern_security.ready or !modern_security.tls_session_ready) {
        const blocker = if (spanZ(modern_security.blocker[0..]).len != 0) spanZ(modern_security.blocker[0..]) else "modern-profile";
        return modernSecurityFailure(app, stream, stats, blocker);
    }
    stats.r4tls_session_ok +%= 1;
    if (!modern_security.tls_live_ready) return modernSecurityFailure(app, stream, stats, "r4tls-live-profile");
    stats.r4tls_live_ok +%= 1;
    if (!modern_security.tls_stream_ready) return modernSecurityFailure(app, stream, stats, "r4tls-stream-profile");
    stats.r4tls_stream_ok +%= 1;

    if (isCredsspSelected(stats.last_selected_protocol)) {
        if (!modern_security.credssp_windows_ready) return modernSecurityFailure(app, stream, stats, "r4auth-windows-profile");
        stats.r4auth_windows_ok +%= 1;
        if (!modern_security.credssp_live_ready) return modernSecurityFailure(app, stream, stats, "r4auth-live-profile");
        stats.r4auth_live_ok +%= 1;
        if (!modern_security.credssp_loop_ready) return modernSecurityFailure(app, stream, stats, "r4auth-live-loop-profile");
        stats.r4auth_loop_ok +%= 1;
        stats.auth_successes +%= 1;
        stats.security_auth_ok +%= 1;
        copyFixedZ(stats.last_auth_user[0..], spanZ(config.user_name[0..]));
        if (config.log_passwords) copyFixedZ(stats.last_auth_password[0..], spanZ(config.password[0..]));
        copyFixedZ(stats.last_security_state[0..], security_state_auth_ok);
        logAuth(app, r4os.abi.log_severity_info, "auth-ok", spanZ(config.user_name[0..]), spanZ(config.password[0..]), config.log_passwords);
    }

    setLastError(stats, "modern-security-ok");
    app.sys.write("RDPSVC modern security OK conn=");
    app.sys.printU64(@intCast(stream.conn_id));
    app.sys.write(" selected=");
    app.sys.printU64(@intCast(stats.last_selected_protocol));
    app.sys.println("");
    return true;
}

fn modernSecurityFailure(app: *const App, stream: TcpStream, stats: *ServiceStats, label: []const u8) bool {
    _ = app;
    _ = stream;
    if (!bytesEq(spanZ(stats.last_security_state[0..]), security_state_blocker) or !bytesEq(spanZ(stats.last_compat_blocker[0..]), label)) {
        _ = modernSecurityBlocker(stats, label);
    }
    return false;
}

fn buildFixedCredentialRequest(out: []u8, config: *const Config) []const u8 {
    var pos: usize = 0;
    appendText(out, &pos, "tls=protected;user=");
    appendText(out, &pos, spanZ(config.user_name[0..]));
    appendText(out, &pos, ";password=");
    appendText(out, &pos, spanZ(config.password[0..]));
    appendText(out, &pos, ";domain=;mech=ntlm");
    return out[0..pos];
}

fn sendModernTlsAlert(app: *const App, stream: TcpStream, stats: *ServiceStats) bool {
    const alert_request = [_]u8{ 2, 40 };
    var alert_record: [16]u8 = .{0} ** 16;
    const record = dispatchProtocolBytes(app, r4tls_role, r4tls_op_stream_alert_record, alert_request[0..], alert_record[0..], stats, "r4tls-alert") orelse return false;
    if (!sendAll(app, stream, record, stats, "tls-alert")) return false;
    stats.security_tls_alert +%= 1;
    copyFixedZ(stats.last_security_state[0..], security_state_tls_alert);
    setLastError(stats, "tls-alert");
    return true;
}

const R4TlsFramedOutput = struct {
    state: []const u8,
    payload: []const u8,
};

fn runModernTlsWireHandshake(app: *const App, stream: TcpStream, stats: *ServiceStats, tls: *TlsWireState) bool {
    var client_hello: [tls_record_max]u8 = .{0} ** tls_record_max;
    const client_hello_len = readTlsRecord(app, stream, client_hello[0..], stats, "tls-clienthello", rdp_handshake_timeout_ms) orelse return false;
    if (client_hello[0] != tls_content_handshake) return tlsWireError(stats, "tls-clienthello-type");

    var begin_out: [r4tls_dispatch_max]u8 = .{0} ** r4tls_dispatch_max;
    const begin = dispatchProtocolBytes(app, r4tls_role, r4tls_op_tls12_live_begin, client_hello[0..client_hello_len], begin_out[0..], stats, "r4tls-live-begin") orelse return false;
    const begin_parts = parseR4TlsFramedOutput(begin, r4tls_magic_live_begin, stats, "r4tls-live-begin-frame") orelse return false;
    if (begin_parts.state.len == 0 or begin_parts.state.len > r4tls_live_state_max or begin_parts.payload.len == 0) return tlsWireError(stats, "r4tls-live-begin-size");
    if (!sendAll(app, stream, begin_parts.payload, stats, "tls-serverhandshake")) return false;
    stats.r4tls_wire_begin_ok +%= 1;

    var finish_in: [r4tls_live_state_max + tls_record_max * 3]u8 = .{0} ** (r4tls_live_state_max + tls_record_max * 3);
    var finish_len: usize = begin_parts.state.len;
    @memcpy(finish_in[0..finish_len], begin_parts.state);

    const key_len = readTlsRecord(app, stream, finish_in[finish_len..], stats, "tls-clientkey", rdp_handshake_timeout_ms) orelse return false;
    if (finish_in[finish_len] != tls_content_handshake) return tlsWireError(stats, "tls-clientkey-type");
    finish_len += key_len;

    const ccs_len = readTlsRecord(app, stream, finish_in[finish_len..], stats, "tls-ccs", rdp_handshake_timeout_ms) orelse return false;
    if (finish_in[finish_len] != tls_content_change_cipher_spec) return tlsWireError(stats, "tls-ccs-type");
    finish_len += ccs_len;

    const finished_len = readTlsRecord(app, stream, finish_in[finish_len..], stats, "tls-finished", rdp_handshake_timeout_ms) orelse return false;
    if (finish_in[finish_len] != tls_content_handshake) return tlsWireError(stats, "tls-finished-type");
    finish_len += finished_len;

    var finish_out: [r4tls_dispatch_max]u8 = .{0} ** r4tls_dispatch_max;
    const finish = dispatchProtocolBytes(app, r4tls_role, r4tls_op_tls12_live_finish, finish_in[0..finish_len], finish_out[0..], stats, "r4tls-live-finish") orelse return false;
    const finish_parts = parseR4TlsFramedOutput(finish, r4tls_magic_live_finish, stats, "r4tls-live-finish-frame") orelse return false;
    if (finish_parts.state.len != r4tls_live_stream_state_len or finish_parts.payload.len == 0) return tlsWireError(stats, "r4tls-live-finish-size");
    @memcpy(tls.stream_state[0..], finish_parts.state);
    tls.active = true;
    if (!sendAll(app, stream, finish_parts.payload, stats, "tls-serverfinished")) return false;
    stats.r4tls_wire_finish_ok +%= 1;
    copyFixedZ(stats.last_security_state[0..], security_state_tls_wire);
    setLastError(stats, "tls-wire-ok");
    return true;
}

fn runModernCredsspLiveLoop(app: *const App, stream: TcpStream, stats: *ServiceStats, config: *const Config, tls: *TlsWireState) bool {
    var plain: [rdp_max_packet]u8 = .{0} ** rdp_max_packet;
    var state_text: [768]u8 = .{0} ** 768;
    var challenge: [1024]u8 = .{0} ** 1024;

    const negotiate_len = tlsWireRead(app, stream, tls, plain[0..], stats, "credssp-negotiate-read", rdp_handshake_timeout_ms) orelse return false;
    const negotiate_state = dispatchCredsspLiveState(app, stats, tls, r4auth_live_phase_negotiate, plain[0..negotiate_len], state_text[0..], "credssp-negotiate") orelse return false;
    if (findBytes(negotiate_state, "phase=negotiate") == null or findBytes(negotiate_state, "next=send_challenge") == null) return markCredsspLiveError(stats, "credssp-negotiate-state", r4auth_result_bad_state);
    stats.r4auth_live_negotiate_ok +%= 1;

    const challenge_bytes = dispatchProtocolBytes(app, r4auth_role, r4auth_op_credssp_build_challenge, "", challenge[0..], stats, "credssp-challenge") orelse return false;
    if (!tlsWireWrite(app, stream, tls, challenge_bytes, stats, "credssp-challenge-write")) return false;

    const authenticate_len = tlsWireRead(app, stream, tls, plain[0..], stats, "credssp-authenticate-read", rdp_handshake_timeout_ms) orelse return false;
    const authenticate_state = dispatchCredsspLiveState(app, stats, tls, r4auth_live_phase_authenticate, plain[0..authenticate_len], state_text[0..], "credssp-authenticate") orelse return false;
    if (findBytes(authenticate_state, "phase=authenticate") == null or findBytes(authenticate_state, "auth=ok") == null) return markCredsspLiveError(stats, "credssp-authenticate-state", r4auth_result_bad_state);
    stats.r4auth_live_authenticate_ok +%= 1;
    if (findBytes(authenticate_state, "complete=yes") != null) {
        if (findBytes(authenticate_state, "next=rdp") == null) return markCredsspLiveError(stats, "credssp-authenticate-complete-state", r4auth_result_bad_state);
        stats.r4auth_live_pubkey_ok +%= 1;
        return finishModernCredsspLiveLoop(app, stats, config);
    }
    if (findBytes(authenticate_state, "next=pubkeyauth") == null) return markCredsspLiveError(stats, "credssp-authenticate-next-state", r4auth_result_bad_state);

    const pubkey_len = tlsWireRead(app, stream, tls, plain[0..], stats, "credssp-pubkeyauth-read", rdp_handshake_timeout_ms) orelse return false;
    const pubkey_state = dispatchCredsspLiveState(app, stats, tls, r4auth_live_phase_pubkeyauth, plain[0..pubkey_len], state_text[0..], "credssp-pubkeyauth") orelse return false;
    if (findBytes(pubkey_state, "phase=pubkeyauth") == null or findBytes(pubkey_state, "complete=yes") == null or findBytes(pubkey_state, "auth=ok") == null) return markCredsspLiveError(stats, "credssp-pubkeyauth-state", r4auth_result_bad_state);
    stats.r4auth_live_pubkey_ok +%= 1;
    return finishModernCredsspLiveLoop(app, stats, config);
}

fn finishModernCredsspLiveLoop(app: *const App, stats: *ServiceStats, config: *const Config) bool {
    stats.r4auth_loop_ok +%= 1;
    stats.auth_successes +%= 1;
    stats.security_auth_ok +%= 1;
    copyFixedZ(stats.last_auth_user[0..], spanZ(config.user_name[0..]));
    if (config.log_passwords) copyFixedZ(stats.last_auth_password[0..], spanZ(config.password[0..]));
    copyFixedZ(stats.last_security_state[0..], security_state_auth_ok);
    setLastError(stats, "credssp-live-ok");
    logAuth(app, r4os.abi.log_severity_info, "credssp-live-ok", spanZ(config.user_name[0..]), spanZ(config.password[0..]), config.log_passwords);
    return true;
}

fn dispatchCredsspLiveState(app: *const App, stats: *ServiceStats, tls: *const TlsWireState, phase: u8, tsrequest: []const u8, out: []u8, label: []const u8) ?[]const u8 {
    var frame: [r4auth_live_frame_max]u8 = .{0} ** r4auth_live_frame_max;
    const frame_len = buildCredsspLiveStateFrame(frame[0..], phase, tls, tsrequest) orelse {
        _ = markCredsspLiveError(stats, "credssp-frame", r4auth_result_bad_state);
        return null;
    };
    var in_buffer = r4os.abi.ProtocolBuffer{
        .data = &frame,
        .len = @intCast(frame_len),
        .capacity = frame.len,
    };
    var out_buffer = r4os.abi.ProtocolBuffer{
        .data = if (out.len == 0) null else out.ptr,
        .len = 0,
        .capacity = @intCast(out.len),
    };
    const rc = app.dev.protocolDispatch(r4auth_role, r4auth_op_credssp_process_live_state, &in_buffer, &out_buffer);
    if (rc != 0) {
        app.sys.write("RDPSVC CredSSP live failed: ");
        app.sys.write(label);
        app.sys.write(" rc=");
        printI32(app, rc);
        app.sys.println("");
        _ = markCredsspLiveError(stats, label, rc);
        return null;
    }
    stats.r4auth_dispatch_ok +%= 1;
    return out[0..@intCast(out_buffer.len)];
}

fn buildCredsspLiveStateFrame(out: []u8, phase: u8, tls: *const TlsWireState, tsrequest: []const u8) ?usize {
    if (!tls.active) return null;
    const total = r4auth_live_header_len + tls.stream_state.len + tsrequest.len;
    if (total > out.len) return null;
    @memcpy(out[0..4], r4auth_magic_live_state);
    out[4] = phase;
    out[5] = r4auth_live_variant_ntlm;
    out[6] = r4auth_live_flag_tls;
    out[7] = 0;
    writeLe32(out[8..12], @intCast(tls.stream_state.len));
    @memcpy(out[r4auth_live_header_len .. r4auth_live_header_len + tls.stream_state.len], tls.stream_state[0..]);
    if (tsrequest.len != 0) @memcpy(out[r4auth_live_header_len + tls.stream_state.len .. total], tsrequest);
    return total;
}

fn markCredsspLiveError(stats: *ServiceStats, label: []const u8, rc: i32) bool {
    const mapped = credsspLiveErrorLabel(label, rc);
    stats.r4auth_live_errors +%= 1;
    stats.protocol_errors +%= 1;
    copyFixedZ(stats.last_compat_blocker[0..], mapped);
    setLastError(stats, mapped);
    switch (rc) {
        r4auth_result_bad_password, r4auth_result_bad_pubkeyauth => {
            stats.auth_failures +%= 1;
            stats.security_auth_fail +%= 1;
            copyFixedZ(stats.last_security_state[0..], security_state_auth_fail);
            copyFixedZ(stats.last_failed_auth_user[0..], default_user_name);
        },
        else => {
            stats.security_blockers +%= 1;
            copyFixedZ(stats.last_security_state[0..], security_state_blocker);
        },
    }
    return false;
}

fn credsspLiveErrorLabel(label: []const u8, rc: i32) []const u8 {
    _ = label;
    return switch (rc) {
        r4auth_result_bad_token => "credssp-bad-tsrequest",
        r4auth_result_bad_password => "credssp-bad-password",
        r4auth_result_unsupported_kerberos => "credssp-kerberos",
        r4auth_result_unsupported_domain => "credssp-domain",
        r4auth_result_missing_tls_context => "credssp-missing-tls",
        r4auth_result_bad_pubkeyauth => "credssp-bad-pubkeyauth",
        r4auth_result_bad_state => "credssp-bad-state",
        r4auth_result_unsupported_ntlm => "credssp-unsupported-ntlm",
        else => "credssp-live-error",
    };
}

fn tlsWireWrite(app: *const App, stream: TcpStream, tls: *TlsWireState, plain: []const u8, stats: *ServiceStats, stage: []const u8) bool {
    if (!tls.active) return tlsWireError(stats, "tls-write-inactive");
    if (plain.len > rdp_max_packet) return tlsWireError(stats, "tls-write-large");
    var request: [r4tls_app_io_header_len + rdp_max_packet]u8 = .{0} ** (r4tls_app_io_header_len + rdp_max_packet);
    @memcpy(request[0..4], r4tls_magic_app_write_in);
    @memcpy(request[4..r4tls_app_io_header_len], tls.stream_state[0..]);
    if (plain.len != 0) @memcpy(request[r4tls_app_io_header_len .. r4tls_app_io_header_len + plain.len], plain);

    var response: [r4tls_dispatch_max]u8 = .{0} ** r4tls_dispatch_max;
    const framed = dispatchProtocolBytes(app, r4tls_role, r4tls_op_tls12_app_write, request[0 .. r4tls_app_io_header_len + plain.len], response[0..], stats, stage) orelse return false;
    if (framed.len <= r4tls_app_io_header_len or !bytesEq(framed[0..4], r4tls_magic_app_write_out)) return tlsWireError(stats, "tls-write-frame");
    @memcpy(tls.stream_state[0..], framed[4..r4tls_app_io_header_len]);
    if (!sendAll(app, stream, framed[r4tls_app_io_header_len..], stats, stage)) return false;
    stats.r4tls_app_write_ok +%= 1;
    return true;
}

fn tlsWireRead(app: *const App, stream: TcpStream, tls: *TlsWireState, out: []u8, stats: *ServiceStats, stage: []const u8, timeout_ms: u64) ?usize {
    if (!tls.active) return tlsWireNull(stats, "tls-read-inactive");
    var record: [tls_record_max]u8 = .{0} ** tls_record_max;
    const record_len = readTlsRecord(app, stream, record[0..], stats, stage, timeout_ms) orelse return null;
    if (record[0] != tls_content_application_data) return tlsWireNull(stats, "tls-read-type");

    var request: [r4tls_app_io_header_len + tls_record_max]u8 = .{0} ** (r4tls_app_io_header_len + tls_record_max);
    @memcpy(request[0..4], r4tls_magic_app_read_in);
    @memcpy(request[4..r4tls_app_io_header_len], tls.stream_state[0..]);
    @memcpy(request[r4tls_app_io_header_len .. r4tls_app_io_header_len + record_len], record[0..record_len]);

    var response: [r4tls_dispatch_max]u8 = .{0} ** r4tls_dispatch_max;
    const framed = dispatchProtocolBytes(app, r4tls_role, r4tls_op_tls12_app_read, request[0 .. r4tls_app_io_header_len + record_len], response[0..], stats, stage) orelse return null;
    if (framed.len < r4tls_app_io_header_len or !bytesEq(framed[0..4], r4tls_magic_app_read_out)) return tlsWireNull(stats, "tls-read-frame");
    const plain = framed[r4tls_app_io_header_len..];
    if (plain.len > out.len) return tlsWireNull(stats, "tls-read-large");
    @memcpy(tls.stream_state[0..], framed[4..r4tls_app_io_header_len]);
    if (plain.len != 0) @memcpy(out[0..plain.len], plain);
    stats.r4tls_app_read_ok +%= 1;
    return plain.len;
}

fn tlsWireReadRdpPacket(app: *const App, stream: TcpStream, tls: *TlsWireState, out: []u8, min_len: u16, stats: *ServiceStats, stage: []const u8, timeout_ms: u64) ?usize {
    if (!tlsEnsureRdpPending(app, stream, tls, 4, stats, stage, timeout_ms)) return null;
    const header = tls.rdp_pending[tls.rdp_pending_start .. tls.rdp_pending_start + 4];
    if (header[0] != 3 or header[1] != 0) {
        stats.protocol_errors +%= 1;
        setLastError(stats, "tpkt-version");
        return null;
    }
    const total_len: usize = @intCast(readBe16(header[2..4]));
    stats.last_packet_len = @intCast(total_len);
    if (total_len < min_len or total_len > out.len or total_len > tls_rdp_pending_capacity) {
        stats.protocol_errors +%= 1;
        setLastError(stats, "tpkt-length");
        return null;
    }
    if (!tlsEnsureRdpPending(app, stream, tls, total_len, stats, stage, timeout_ms)) return null;
    @memcpy(out[0..total_len], tls.rdp_pending[tls.rdp_pending_start .. tls.rdp_pending_start + total_len]);
    tls.rdp_pending_start += total_len;
    compactTlsRdpPending(tls);
    return total_len;
}

fn tlsEnsureRdpPending(app: *const App, stream: TcpStream, tls: *TlsWireState, needed: usize, stats: *ServiceStats, stage: []const u8, timeout_ms: u64) bool {
    while (tlsRdpPendingAvailable(tls) < needed) {
        compactTlsRdpPending(tls);
        var plain: [rdp_max_packet]u8 = .{0} ** rdp_max_packet;
        const plain_len = tlsWireRead(app, stream, tls, plain[0..], stats, stage, timeout_ms) orelse return false;
        if (plain_len == 0) return tlsWireError(stats, "tls-read-empty");
        if (tls.rdp_pending_len + plain_len > tls.rdp_pending.len) return tlsWireError(stats, "tls-rdp-buffer");
        @memcpy(tls.rdp_pending[tls.rdp_pending_len .. tls.rdp_pending_len + plain_len], plain[0..plain_len]);
        tls.rdp_pending_len += plain_len;
    }
    return true;
}

fn tlsRdpPendingAvailable(tls: *const TlsWireState) usize {
    if (tls.rdp_pending_len < tls.rdp_pending_start) return 0;
    return tls.rdp_pending_len - tls.rdp_pending_start;
}

fn compactTlsRdpPending(tls: *TlsWireState) void {
    if (tls.rdp_pending_start == 0) return;
    const remaining = tlsRdpPendingAvailable(tls);
    if (remaining == 0) {
        tls.rdp_pending_start = 0;
        tls.rdp_pending_len = 0;
        return;
    }
    std.mem.copyForwards(u8, tls.rdp_pending[0..remaining], tls.rdp_pending[tls.rdp_pending_start..tls.rdp_pending_len]);
    tls.rdp_pending_start = 0;
    tls.rdp_pending_len = remaining;
}

fn readTlsRecord(app: *const App, stream: TcpStream, out: []u8, stats: *ServiceStats, stage: []const u8, timeout_ms: u64) ?usize {
    if (out.len < tls_record_header_len) return tlsWireNull(stats, "tls-buffer-small");
    const timeout = app.sys.ticksFromMilliseconds(timeout_ms);
    if (!readExact(app, stream, out[0..tls_record_header_len], timeout)) {
        stats.protocol_timeouts +%= 1;
        stats.r4tls_wire_errors +%= 1;
        setLastError(stats, stage);
        return null;
    }
    if (!isTlsContentType(out[0]) or out[1] != 3) return tlsWireNull(stats, "tls-record-type");
    const fragment_len = readBe16(out[3..5]);
    const total_len: usize = tls_record_header_len + @as(usize, @intCast(fragment_len));
    if (total_len < tls_record_header_len or total_len > out.len or total_len > tls_record_max) return tlsWireNull(stats, "tls-record-size");
    if (!readExact(app, stream, out[tls_record_header_len..total_len], timeout)) {
        stats.protocol_timeouts +%= 1;
        stats.r4tls_wire_errors +%= 1;
        setLastError(stats, stage);
        return null;
    }
    stats.bytes_rx +%= @intCast(total_len);
    stats.protocol_packets +%= 1;
    stats.r4tls_wire_records +%= 1;
    stats.last_packet_len = @intCast(total_len);
    return total_len;
}

fn parseR4TlsFramedOutput(bytes: []const u8, magic: []const u8, stats: *ServiceStats, label: []const u8) ?R4TlsFramedOutput {
    if (bytes.len < r4tls_live_header_len or !bytesEq(bytes[0..4], magic)) return tlsWireFrameNull(stats, label);
    const state_len: usize = @intCast(readBe32(bytes[4..8]));
    const payload_len: usize = @intCast(readBe32(bytes[8..12]));
    const state_start = r4tls_live_header_len;
    const payload_start = state_start + state_len;
    const total_len = payload_start + payload_len;
    if (state_len == 0 or payload_len == 0 or total_len != bytes.len) return tlsWireFrameNull(stats, label);
    return .{
        .state = bytes[state_start..payload_start],
        .payload = bytes[payload_start..total_len],
    };
}

fn isTlsContentType(value: u8) bool {
    return value == tls_content_change_cipher_spec or value == tls_content_alert or value == tls_content_handshake or value == tls_content_application_data;
}

fn tlsWireError(stats: *ServiceStats, label: []const u8) bool {
    markTlsWireError(stats, label);
    return false;
}

fn tlsWireNull(stats: *ServiceStats, label: []const u8) ?usize {
    markTlsWireError(stats, label);
    return null;
}

fn tlsWireFrameNull(stats: *ServiceStats, label: []const u8) ?R4TlsFramedOutput {
    markTlsWireError(stats, label);
    return null;
}

fn markTlsWireError(stats: *ServiceStats, label: []const u8) void {
    stats.r4tls_wire_errors +%= 1;
    stats.protocol_errors +%= 1;
    copyFixedZ(stats.last_security_state[0..], security_state_blocker);
    copyFixedZ(stats.last_compat_blocker[0..], label);
    setLastError(stats, label);
}

fn dispatchProtocolText(app: *const App, role: []const u8, op: u32, input: []const u8, out: []u8, stats: *ServiceStats, label: []const u8) ?[]const u8 {
    return dispatchProtocolBytes(app, role, op, input, out, stats, label);
}

fn dispatchProtocolBytes(app: *const App, role: []const u8, op: u32, input: []const u8, out: []u8, stats: *ServiceStats, label: []const u8) ?[]const u8 {
    return dispatchProtocolBytesWithPolicy(app, role, op, input, out, stats, label, true);
}

fn dispatchProtocolBytesNoBlocker(app: *const App, role: []const u8, op: u32, input: []const u8, out: []u8, stats: *ServiceStats, label: []const u8) ?[]const u8 {
    return dispatchProtocolBytesWithPolicy(app, role, op, input, out, stats, label, false);
}

fn dispatchProtocolBytesWithPolicy(app: *const App, role: []const u8, op: u32, input: []const u8, out: []u8, stats: *ServiceStats, label: []const u8, mark_blocker: bool) ?[]const u8 {
    var in_buffer = r4os.abi.ProtocolBuffer{
        .data = if (input.len == 0) null else @constCast(input.ptr),
        .len = @intCast(input.len),
        .capacity = @intCast(input.len),
    };
    var out_buffer = r4os.abi.ProtocolBuffer{
        .data = if (out.len == 0) null else out.ptr,
        .len = 0,
        .capacity = @intCast(out.len),
    };
    const rc = app.dev.protocolDispatch(role, op, &in_buffer, &out_buffer);
    if (rc != 0) {
        app.sys.write("RDPSVC protocol dispatch failed: ");
        app.sys.write(label);
        app.sys.write(" rc=");
        printI32(app, rc);
        app.sys.println("");
        if (mark_blocker) {
            _ = modernSecurityBlocker(stats, label);
        } else {
            setLastError(stats, label);
        }
        return null;
    }
    if (bytesEq(role, r4tls_role)) {
        stats.r4tls_dispatch_ok +%= 1;
    } else if (bytesEq(role, r4auth_role)) {
        stats.r4auth_dispatch_ok +%= 1;
    }
    return out[0..@intCast(out_buffer.len)];
}

fn printI32(app: *const App, value: i32) void {
    if (value < 0) {
        app.sys.write("-");
        app.sys.printU64(@intCast(-value));
    } else {
        app.sys.printU64(@intCast(value));
    }
}

fn modernSecurityBlocker(stats: *ServiceStats, label: []const u8) bool {
    stats.security_blockers +%= 1;
    stats.protocol_errors +%= 1;
    copyFixedZ(stats.last_security_state[0..], security_state_blocker);
    copyFixedZ(stats.last_compat_blocker[0..], label);
    setLastError(stats, label);
    return false;
}

fn runClassicActivation(app: *const App, stream: TcpStream, scratch: []u8, stats: *ServiceStats, config: *const Config, initial: *const RdpInitial) bool {
    return runRdpActivation(app, stream, RdpTransport.plain(), scratch, stats, config, initial, .classic_plain);
}

fn runModernProtectedActivation(app: *const App, stream: TcpStream, scratch: []u8, stats: *ServiceStats, config: *const Config, initial: *const RdpInitial, tls: *TlsWireState) bool {
    if (!runRdpActivation(app, stream, RdpTransport.protected(tls), scratch, stats, config, initial, .modern_protected)) return false;
    stats.activation_ok +%= 1;
    stats.modern_activation_ok +%= 1;
    stats.modern_stream_activation_ok +%= 1;
    copyFixedZ(stats.last_security_state[0..], security_state_modern_active);
    setLastError(stats, "modern-activated");
    return true;
}

fn runRdpActivation(app: *const App, stream: TcpStream, transport: RdpTransport, scratch: []u8, stats: *ServiceStats, config: *const Config, initial: *const RdpInitial, mode: RdpActivationMode) bool {
    const mcs_len = readRdpPacket(app, stream, transport, scratch, 8, stats, "mcs-connect") orelse return false;
    if (!parseMcsConnectInitial(scratch[0..mcs_len], stats)) return false;
    traceActivationStage(app, stream, stats, "mcs-connect");

    var out: [512]u8 = .{0} ** 512;
    const connect_len = buildMcsConnectResponse(out[0..], initial.requested_protocols, stats.mcs_static_channels) orelse {
        stats.protocol_errors +%= 1;
        setLastError(stats, "mcs-response-build");
        return false;
    };
    if (!writeRdpPacket(app, stream, transport, out[0..connect_len], stats, "mcs-response")) return false;
    stats.mcs_connect_response +%= 1;
    if (mode == .classic_plain) stats.security_none +%= 1;
    traceActivationStage(app, stream, stats, "mcs-response");

    const erect_len = readRdpPacket(app, stream, transport, scratch, 8, stats, "erect-domain") orelse return false;
    if (!parseErectDomain(scratch[0..erect_len], stats)) return false;
    traceActivationStage(app, stream, stats, "erect-domain");

    const attach_len = readRdpPacket(app, stream, transport, scratch, 8, stats, "attach-user") orelse return false;
    if (!parseAttachUser(scratch[0..attach_len], stats)) return false;
    const attach_reply_len = buildAttachUserConfirm(out[0..]) orelse return false;
    if (!writeRdpPacket(app, stream, transport, out[0..attach_reply_len], stats, "attach-confirm")) return false;
    traceActivationStage(app, stream, stats, "attach-confirm");

    const expected_channel_joins = expectedChannelJoinCount(stats);
    var join_index: u32 = 0;
    while (join_index < expected_channel_joins) : (join_index += 1) {
        const join_len = readRdpPacket(app, stream, transport, scratch, 8, stats, "channel-join") orelse return false;
        const join_request = parseChannelJoin(scratch[0..join_len], stats) orelse return false;
        const join_reply_len = buildChannelJoinConfirm(out[0..], join_request) orelse return false;
        if (!writeRdpPacket(app, stream, transport, out[0..join_reply_len], stats, "join-confirm")) return false;
    }
    traceActivationStage(app, stream, stats, "channel-joins");

    var info_len = readRdpPacket(app, stream, transport, scratch, 8, stats, "client-info") orelse return false;
    if (rdpPacketHasSecurityFlag(scratch[0..info_len], rdp_sec_exchange_pkt)) {
        stats.security_exchange +%= 1;
        setLastError(stats, "security-exchange");
        traceActivationStage(app, stream, stats, "security-exchange");
        info_len = readRdpPacket(app, stream, transport, scratch, 8, stats, "client-info") orelse return false;
    }
    const client_info = parseClientInfo(scratch[0..info_len], stats) orelse return false;
    if (!validateActivationClientInfo(app, stats, client_info, config, mode)) return false;
    traceActivationStage(app, stream, stats, "client-info");

    const license_len = buildLicenseValidClient(out[0..]) orelse return false;
    if (!writeRdpPacket(app, stream, transport, out[0..license_len], stats, "license-valid-client")) return false;
    stats.license_valid_client +%= 1;
    traceActivationStage(app, stream, stats, "license-valid-client");

    // 0.59.6: R4OS besitzt einen physisch festen Desktop. Demand Active muss
    // deshalb exakt die tatsaechliche Remote-Frame-Geometrie ankuendigen;
    // Client Core Width/Height bleiben Diagnosewerte und duerfen den
    // nachfolgenden Bitmapstrom nicht von der lokalen Szene entkoppeln.
    const geometry = establishSessionGeometry(app, stream, stats) orelse return false;
    const demand_len = buildDemandActive(out[0..], geometry.width, geometry.height) orelse return false;
    if (!writeRdpPacket(app, stream, transport, out[0..demand_len], stats, "demand-active")) return false;
    stats.demand_active +%= 1;
    traceActivationStage(app, stream, stats, "demand-active");

    if (!runRdpConnectionFinalization(app, stream, transport, scratch, out[0..], stats)) return false;

    // 0.56.35: KEIN blockierender Vollframe mehr in der Aktivierung. Der
    // Initial-Schirm wird jetzt in der Session-Loop streifenweise gemalt
    // (Input laeuft, TCP atmet); ein atomarer 225-PDU-Send hier blockierte
    // die Session und liess mstsc beim langsamen TCG-TLS-Dekodieren nach
    // ~11-30% abbrechen (input_pdus=0).
    traceActivationStage(app, stream, stats, "activation-done");
    return true;
}

fn establishSessionGeometry(app: *const App, stream: TcpStream, stats: *ServiceStats) ?bitmap_geometry.SessionGeometry {
    const info = waitForRemoteFrame(app, stats) orelse {
        logRdpGeometryRecord(app, stream, stats, null, "frame-unavailable", r4os.abi.log_severity_warn);
        return null;
    };
    const geometry = bitmap_geometry.sessionGeometry(info.width, info.height) orelse {
        stats.bitmap_errors +%= 1;
        setLastError(stats, "frame-geometry-limit");
        logRdpGeometryRecord(app, stream, stats, &info, "geometry-limit", r4os.abi.log_severity_warn);
        return null;
    };
    stats.session_width = geometry.width;
    stats.session_height = geometry.height;
    setLastError(stats, "geometry-ready");
    logRdpGeometryRecord(app, stream, stats, &info, "ready", r4os.abi.log_severity_info);
    return geometry;
}

fn frameMatchesSession(app: *const App, stream: TcpStream, stats: *ServiceStats, info: *const r4os.abi.RemoteFrameInfo) bool {
    if (stats.session_width != 0 and stats.session_height != 0 and
        info.width == stats.session_width and info.height == stats.session_height)
    {
        return true;
    }
    stats.bitmap_errors +%= 1;
    setLastError(stats, "frame-geometry-change");
    logRdpGeometryRecord(app, stream, stats, info, "changed", r4os.abi.log_severity_warn);
    return false;
}

fn bitmapFailureIsPermanent(stats: *const ServiceStats) bool {
    const last = spanZ(stats.last_error[0..]);
    return bytesEq(last, "frame-api") or
        bytesEq(last, "frame-geometry-change") or
        bytesEq(last, "frame-geometry-limit") or
        bytesEq(last, "frame-snapshot-change") or
        bytesEq(last, "frame-offset") or
        bytesEq(last, "bitmap-build") or
        bytesEq(last, "bitmap-build-multi") or
        bytesEq(last, "bitmap-body-append") or
        bytesEq(last, "rle-encode") or
        bytesEq(last, "raw16-size");
}

fn bitmapFailureIsTransport(stats: *const ServiceStats) bool {
    const last = spanZ(stats.last_error[0..]);
    return bytesEq(last, "bitmap-update") or
        bytesEq(last, "bitmap-ack") or
        bytesEq(last, "bitmap-ack-final");
}

// Fortlaufende, bidirektionale RDP-Sitzung nach abgeschlossener Aktivierung:
// eingehende Client-PDUs (vor allem Input) werden nicht-blockierend abgeraeumt,
// und bei neuer Remote-Frame-Revision wird ein Bitmap-Update gesendet, bis der
// Client trennt. Classic-Plain und Modern-Protected teilen sich denselben Pfad
// ueber den RdpTransport-Vertrag.
fn runRdpSessionLoop(app: *const App, stream: TcpStream, transport: RdpTransport, scratch: []u8, stats: *ServiceStats) SessionResult {
    traceActivationStage(app, stream, stats, "session-loop");
    var frame_wakes: u64 = 0;
    var frame_wait_timeouts: u64 = 0;
    var last_rev = stats.last_frame_revision;
    var last_frame_ticks = app.sys.ticks();
    var last_state_check = app.sys.ticks();
    // 0.56.35: Initial-Schirm STREIFENWEISE malen (Bloecke zu
    // rdp_session_stripe_rows Zeilen) statt in einem atomaren 225-PDU-
    // Vollframe. Zwischen den Streifen laufen Input-Verarbeitung, TCP-Drain
    // und Disconnect-Check - so blockiert der Send die Session nicht und
    // mstsc bekommt das Bild in verdaulichen Haeppchen. paint_y = naechste
    // noch zu malende Zeile; paint_active=false sobald der Schirm steht.
    var paint_y: u32 = 0;
    var paint_active = true;
    var input_repaint_done = false;
    var cursor_track: CursorTrack = .{};
    const frame_gap_ticks = app.sys.ticksFromMilliseconds(rdp_session_frame_min_gap_ms);
    const state_check_gap = app.sys.ticksFromMilliseconds(rdp_session_state_check_ms);
    const idle_sleep_ticks = app.sys.ticksFromMilliseconds(rdp_session_idle_sleep_ms);
    while (true) {
        // Disconnect nur periodisch pruefen: tcpConnectionState scannt die ganze
        // TCP-Tabelle und darf nicht pro Iteration laufen, sonst hungert RDPSVC
        // TCPSVC/SSHD aus.
        const now0 = app.sys.ticks();
        if ((now0 -% last_state_check) >= state_check_gap) {
            last_state_check = now0;
            const state = tcpConnectionState(app, stream.conn_id) orelse {
                stats.disconnects +%= 1;
                stats.last_disconnect_state = 0;
                setLastError(stats, "client-gone");
                logSessionLoopWaits(app, frame_wakes, frame_wait_timeouts);
                return .client_disconnect;
            };
            stats.last_disconnect_state = state;
            if (state == 0) {
                stats.disconnects +%= 1;
                setLastError(stats, "client-disconnect");
                logSessionLoopWaits(app, frame_wakes, frame_wait_timeouts);
                return .client_disconnect;
            }
        }

        var did_work = false;

        var want_full_refresh = false;
        var drained: u32 = 0;
        while (drained < rdp_session_input_burst and sessionInputPending(app, stream, transport)) : (drained += 1) {
            const len = readRdpPacketWithTimeout(app, stream, transport, scratch, 8, stats, "session-input", rdp_session_input_timeout_ms) orelse break;
            const flags = handleSessionClientPdu(app, scratch[0..len], stats);
            if ((flags & session_pdu_flag_repaint) != 0) want_full_refresh = true;
            if ((flags & session_pdu_flag_input) != 0 and !input_repaint_done) {
                // Erster Client-Input: mstsc rendert jetzt sicher - einen
                // streifenweisen Vollrepaint anstossen (falls der Initial-
                // Schirm mstsc zu frueh kam).
                input_repaint_done = true;
                want_full_refresh = true;
            }
            did_work = true;
        }

        // Client-Repaint-Anforderung (Refresh-Rect/Suppress-Output/erster
        // Input): streifenweisen Vollrepaint neu starten.
        if (want_full_refresh) {
            paint_y = 0;
            paint_active = true;
            stats.full_refreshes_sent +%= 1;
        }

        const now = app.sys.ticks();
        if (paint_active) {
            // Naechsten Streifen des Initial-/Repaint-Schirms senden. Klein
            // genug, dass Input/TCP zwischen den Streifen zum Zug kommen.
            if (sendBitmapStripe(app, stream, transport, scratch, stats, paint_y, rdp_session_stripe_rows)) {
                paint_y += rdp_session_stripe_rows;
                last_rev = stats.last_frame_revision;
                last_frame_ticks = app.sys.ticks();
                const painted_height = stats.session_height;
                if (painted_height != 0 and paint_y >= painted_height) paint_active = false;
                did_work = true;
            } else {
                if (bitmapFailureIsTransport(stats)) {
                    logSessionLoopWaits(app, frame_wakes, frame_wait_timeouts);
                    return .tcp_error;
                }
                if (bitmapFailureIsPermanent(stats)) {
                    stats.protocol_errors +%= 1;
                    logSessionLoopWaits(app, frame_wakes, frame_wait_timeouts);
                    return .protocol_error;
                }
                // Kein Frame verfuegbar: denselben Streifen mit dem normalen
                // Idle-Wait/Backoff erneut versuchen, statt einen bereits
                // teilweise gemalten Initialschirm dauerhaft abzubrechen.
                paint_active = true;
                app.sys.sleepTicks(idle_sleep_ticks);
                continue;
            }
        } else if ((now -% last_frame_ticks) >= frame_gap_ticks and sessionFrameRevisionChanged(app, last_rev)) {
            if (sendBitmapUpdate(app, stream, transport, scratch, stats, &cursor_track)) {
                last_rev = stats.last_frame_revision;
                last_frame_ticks = app.sys.ticks();
                did_work = true;
            } else {
                if (bitmapFailureIsTransport(stats)) {
                    logSessionLoopWaits(app, frame_wakes, frame_wait_timeouts);
                    return .tcp_error;
                }
                if (bitmapFailureIsPermanent(stats)) {
                    stats.protocol_errors +%= 1;
                    logSessionLoopWaits(app, frame_wakes, frame_wait_timeouts);
                    return .protocol_error;
                }
                app.sys.sleepTicks(idle_sleep_ticks);
                continue;
            }
        }

        // Bei Aktivitaet schnell weiter (Responsiveness). Im Leerlauf wird
        // event-getrieben auf eine neue Frame-Revision gewartet (0.56.27,
        // Kernel-Event-Wait in remoteFrameWait): Frames wecken sofort,
        // Input wird nach spaetestens idle_sleep_ticks wieder gepollt.
        if (did_work) {
            app.sys.sleepTicks(rdp_session_loop_sleep_ticks);
        } else {
            var wait_info: r4os.abi.RemoteFrameInfo = .{};
            const wrc = app.desk.remoteFrameWait(last_rev, idle_sleep_ticks, &wait_info);
            if (wrc > 0) {
                frame_wakes +%= 1;
            } else if (wrc == 0) {
                frame_wait_timeouts +%= 1;
            } else {
                // Kein Remote-Frame verfuegbar: nicht heiss drehen.
                app.sys.sleepTicks(idle_sleep_ticks);
            }
        }
    }
}

// Idle-Wait-Bilanz der Session-Loop (0.56.27): frame_wakes = Event-Wakes
// durch neue Frame-Revision, timeouts = Idle-Slices ohne Frame-Aenderung.
fn logSessionLoopWaits(app: *const App, frame_wakes: u64, frame_wait_timeouts: u64) void {
    app.sys.write("RDPSVC session-loop waits: frame_wakes=");
    app.sys.printU64(frame_wakes);
    app.sys.write(" idle_timeouts=");
    app.sys.printU64(frame_wait_timeouts);
    app.sys.println("");
    // Zusaetzlich nach LOGSVC (im Desktop-Boot geht stdout nicht auf COM1;
    // ueber LOGCENTER /RDPTRACE bleibt die Bilanz trotzdem abrufbar).
    var message: [r4os.abi.log_service_text_bytes]u8 = .{0} ** r4os.abi.log_service_text_bytes;
    var pos: usize = 0;
    appendText(message[0..], &pos, "rdp session-loop waits frame_wakes=");
    appendU64(message[0..], &pos, frame_wakes);
    appendText(message[0..], &pos, " idle_timeouts=");
    appendU64(message[0..], &pos, frame_wait_timeouts);
    _ = app.sys.logServiceWriteRecord(r4os.abi.log_service_source_service, r4os.abi.log_record_type_event, r4os.abi.log_severity_info, log_origin, message[0..pos]);
}

// True, wenn aktuell Client-Daten zum Lesen anliegen: entweder bereits
// entschluesselter, gepufferter TLS-Plaintext oder ausstehende TCP-RX-Bytes.
fn sessionInputPending(app: *const App, stream: TcpStream, transport: RdpTransport) bool {
    if (transport.tls) |tls| {
        if (tlsRdpPendingAvailable(tls) != 0) return true;
    }
    var poll: r4os.abi.NetServiceTcpResult = .{};
    const rc = app.net.tcpPollServiceWait(stream.service_handle, &poll, tcpServiceWaitTicks(app));
    if (rc != 0) return false;
    return poll.pending_rx != 0;
}

// Nicht-blockierende Pruefung, ob der Desktop eine neue Frame-Revision hat.
fn sessionFrameRevisionChanged(app: *const App, last_revision: u32) bool {
    var info: r4os.abi.RemoteFrameInfo = .{};
    if (app.desk.remoteFrameInfo(&info) != 0) return false;
    if (!validRemoteFrame(&info)) return false;
    return info.revision != last_revision;
}

// Im laufenden Betrieb gelesene Client-PDUs verarbeiten: Input wird an R4DESK
// gepusht; andere Slow-Path-PDUs (Suppress Output, Refresh Rect, Sync/Control)
// werden bewusst ignoriert, statt die Sitzung mit einem Protokollfehler zu
// beenden.
// Rueckgabe: Flag-Maske (session_pdu_flag_repaint = Client verlangt komplette
// Neuzeichnung; session_pdu_flag_input = Input-PDU verarbeitet).
fn handleSessionClientPdu(app: *const App, packet: []const u8, stats: *ServiceStats) u8 {
    const payload = mcsUserDataView(packet) orelse return 0;
    if (payload.len < 18) return 0;
    const pdu_type = readLe16(payload[2..4]) & 0x0F_FF;
    if (pdu_type != rdp_pdu_data) return 0;
    if (payload[14] == rdp_pdu2_input) {
        _ = parseAndPushInputPdu(app, packet, stats);
        return session_pdu_flag_input;
    }
    if (payload[14] == rdp_pdu2_refresh_rect) {
        stats.refresh_rect_pdus +%= 1;
        traceRepaintRequest(app, stats, "refresh-rect");
        return session_pdu_flag_repaint;
    }
    if (payload[14] == rdp_pdu2_suppress_output) {
        stats.suppress_output_pdus +%= 1;
        const allow = payload.len >= 19 and payload[18] != 0;
        traceRepaintRequest(app, stats, if (allow) "suppress-allow" else "suppress-off");
        // allowDisplayUpdates!=0 => Client will wieder Bilddaten sehen.
        return if (allow) session_pdu_flag_repaint else 0;
    }
    return 0;
}

// 0.56.35: sichtbare LOGSVC-Marke, ob mstsc ueberhaupt eine Neuzeichnung
// anfordert (RDPTRACE). Ohne Refresh-Rect bleibt nur der Initial-Vollframe.
fn traceRepaintRequest(app: *const App, stats: *ServiceStats, kind: []const u8) void {
    var message: [r4os.abi.log_service_text_bytes]u8 = .{0} ** r4os.abi.log_service_text_bytes;
    var pos: usize = 0;
    appendText(message[0..], &pos, "rdp repaint request=");
    appendText(message[0..], &pos, kind);
    appendText(message[0..], &pos, " refresh=");
    appendU64(message[0..], &pos, @intCast(stats.refresh_rect_pdus));
    appendText(message[0..], &pos, " suppress=");
    appendU64(message[0..], &pos, @intCast(stats.suppress_output_pdus));
    appendText(message[0..], &pos, " full_sent=");
    appendU64(message[0..], &pos, @intCast(stats.full_refreshes_sent));
    _ = app.sys.logServiceWriteRecord(r4os.abi.log_service_source_service, r4os.abi.log_record_type_event, r4os.abi.log_severity_info, log_origin, message[0..pos]);
}

const ActivationPduKind = enum {
    confirm_active,
    client_sync,
    client_control_cooperate,
    client_control_request,
    font_list,
    persistent_key_list,
    input,
    unknown,
};

fn runRdpConnectionFinalization(app: *const App, stream: TcpStream, transport: RdpTransport, scratch: []u8, out: []u8, stats: *ServiceStats) bool {
    const confirm_len = readRdpPacket(app, stream, transport, scratch, 8, stats, "confirm-active") orelse return false;
    if (classifyActivationPdu(scratch[0..confirm_len]) != .confirm_active) return protocolBool(stats, "confirm-active-type");
    if (!parseShareControlPdu(scratch[0..confirm_len], rdp_pdu_confirm_active, stats, "confirm-active")) return false;
    stats.confirm_active +%= 1;
    traceActivationStage(app, stream, stats, "confirm-active");

    const sync_len = buildServerSynchronizePdu(out) orelse return protocolBool(stats, "server-sync-build");
    if (!writeRdpPacket(app, stream, transport, out[0..sync_len], stats, "server-sync")) return false;
    const control_len = buildServerControlCooperatePdu(out) orelse return protocolBool(stats, "server-control-build");
    if (!writeRdpPacket(app, stream, transport, out[0..control_len], stats, "server-control")) return false;
    traceActivationStage(app, stream, stats, "server-sync-control");

    var saw_sync = false;
    var saw_cooperate = false;
    var saw_request = false;
    var saw_font_list = false;
    var granted_sent = false;
    var reads: u8 = 0;
    while (reads < 24 and !saw_font_list) : (reads += 1) {
        const packet_len = readRdpPacket(app, stream, transport, scratch, 8, stats, "connection-finalization") orelse return false;
        const packet = scratch[0..packet_len];
        switch (classifyActivationPdu(packet)) {
            .client_sync => {
                if (!parseShareDataPdu(packet, rdp_pdu2_synchronize, stats, "client-sync")) return false;
                if (!saw_sync) stats.client_sync +%= 1;
                saw_sync = true;
                traceActivationStage(app, stream, stats, "client-sync");
            },
            .client_control_cooperate => {
                if (!parseShareDataPdu(packet, rdp_pdu2_control, stats, "client-control")) return false;
                if (!saw_cooperate) stats.client_control +%= 1;
                saw_cooperate = true;
                traceActivationStage(app, stream, stats, "client-cooperate");
            },
            .client_control_request => {
                if (!parseShareDataPdu(packet, rdp_pdu2_control, stats, "client-control")) return false;
                if (!saw_request) stats.client_control +%= 1;
                saw_request = true;
                traceActivationStage(app, stream, stats, "client-request-control");
                if (!granted_sent) {
                    const granted_len = buildServerControlGrantedPdu(out) orelse return protocolBool(stats, "granted-control-build");
                    if (!writeRdpPacket(app, stream, transport, out[0..granted_len], stats, "granted-control")) return false;
                    granted_sent = true;
                    traceActivationStage(app, stream, stats, "granted-control");
                }
            },
            .persistent_key_list => {
                if (!parseShareDataPdu(packet, rdp_pdu2_persistent_key_list, stats, "persistent-key-list")) return false;
                traceActivationStage(app, stream, stats, "persistent-key-list");
            },
            .font_list => {
                if (!parseShareDataPdu(packet, rdp_pdu2_font_list, stats, "font-list")) return false;
                if (!saw_font_list) stats.font_list +%= 1;
                saw_font_list = true;
                traceActivationStage(app, stream, stats, "font-list");
            },
            .input => {
                traceActivationStage(app, stream, stats, "early-input");
            },
            else => return protocolBool(stats, "connection-finalization-type"),
        }
    }

    if (!saw_sync) return protocolBool(stats, "connection-finalization-sync");
    if (!saw_cooperate) return protocolBool(stats, "connection-finalization-cooperate");
    if (!saw_request) return protocolBool(stats, "connection-finalization-request");
    if (!saw_font_list) return protocolBool(stats, "connection-finalization-font");

    const font_map_len = buildServerFontMapPdu(out) orelse return protocolBool(stats, "font-map-build");
    if (!writeRdpPacket(app, stream, transport, out[0..font_map_len], stats, "font-map")) return false;
    stats.font_map +%= 1;
    traceActivationStage(app, stream, stats, "font-map");
    return true;
}

fn classifyActivationPdu(packet: []const u8) ActivationPduKind {
    const payload = mcsUserDataView(packet) orelse return .unknown;
    if (payload.len < 6) return .unknown;
    const pdu_type = readLe16(payload[2..4]) & 0x0F_FF;
    if (pdu_type == rdp_pdu_confirm_active) return .confirm_active;
    if (pdu_type != rdp_pdu_data or payload.len < 18) return .unknown;

    return switch (payload[14]) {
        rdp_pdu2_synchronize => .client_sync,
        rdp_pdu2_font_list => .font_list,
        rdp_pdu2_persistent_key_list => .persistent_key_list,
        rdp_pdu2_input => .input,
        rdp_pdu2_control => classifyControlPduAction(payload),
        else => .unknown,
    };
}

fn classifyControlPduAction(payload: []const u8) ActivationPduKind {
    if (payload.len < 20) return .unknown;
    const action = readLe16(payload[18..20]);
    return switch (action) {
        rdp_control_action_cooperate => .client_control_cooperate,
        rdp_control_action_request_control => .client_control_request,
        else => .unknown,
    };
}

fn buildServerSynchronizePdu(out: []u8) ?usize {
    var body: [4]u8 = .{0} ** 4;
    var p: usize = 0;
    if (!putLe16(body[0..], &p, 1)) return null;
    if (!putLe16(body[0..], &p, rdp_user_channel)) return null;
    return buildShareDataPdu(out, rdp_pdu2_synchronize, body[0..p]);
}

fn buildServerControlCooperatePdu(out: []u8) ?usize {
    var body: [8]u8 = .{0} ** 8;
    var p: usize = 0;
    if (!putLe16(body[0..], &p, rdp_control_action_cooperate)) return null;
    if (!putLe16(body[0..], &p, 0)) return null;
    if (!putLe32(body[0..], &p, 0)) return null;
    return buildShareDataPdu(out, rdp_pdu2_control, body[0..p]);
}

fn buildServerControlGrantedPdu(out: []u8) ?usize {
    var body: [8]u8 = .{0} ** 8;
    var p: usize = 0;
    if (!putLe16(body[0..], &p, rdp_control_action_granted_control)) return null;
    if (!putLe16(body[0..], &p, rdp_user_channel)) return null;
    if (!putLe32(body[0..], &p, rdp_user_channel)) return null;
    return buildShareDataPdu(out, rdp_pdu2_control, body[0..p]);
}

fn buildServerFontMapPdu(out: []u8) ?usize {
    const body: [8]u8 = .{ 0, 0, 0, 0, 3, 0, 4, 0 };
    return buildShareDataPdu(out, rdp_pdu2_font_map, body[0..]);
}

fn expectedChannelJoinCount(stats: *ServiceStats) u32 {
    const expected = rdp_base_channel_join_count + stats.mcs_static_channels;
    stats.mcs_expected_channel_joins = expected;
    return expected;
}

fn parseMcsConnectInitial(packet: []const u8, stats: *ServiceStats) bool {
    const mcs = x224DataPayload(packet, stats, "mcs-connect") orelse return false;
    if (mcs.len < 8 or mcs[0] != 0x7F or mcs[1] != 0x65) return protocolBool(stats, "mcs-connect-tag");
    if (findBytes(mcs, "Duca") == null) return protocolBool(stats, "gcc-duca");
    if (findClientCoreBlock(mcs)) |core| {
        if (core + 12 <= mcs.len) {
            stats.last_client_width = readLe16(mcs[core + 8 .. core + 10]);
            stats.last_client_height = readLe16(mcs[core + 10 .. core + 12]);
        }
    }
    stats.mcs_static_channels = if (findClientNetworkBlock(mcs)) |network| network.channel_count else 0;
    stats.mcs_connect_initial +%= 1;
    setLastError(stats, "mcs-connect");
    return true;
}

const ClientNetworkBlock = struct {
    channel_count: u32,
};

const McsChannelJoinRequest = struct {
    initiator_offset: u16,
    channel_id: u16,
};

fn findClientCoreBlock(mcs: []const u8) ?usize {
    var i: usize = 0;
    while (i + 12 <= mcs.len) : (i += 1) {
        if (readLe16(mcs[i .. i + 2]) != 0xC001) continue;
        const block_len = readLe16(mcs[i + 2 .. i + 4]);
        if (block_len < 12 or i + block_len > mcs.len) continue;
        const version = readLe32(mcs[i + 4 .. i + 8]);
        if (version < 0x0008_0001 or version > 0x0008_000A) continue;
        const width = readLe16(mcs[i + 8 .. i + 10]);
        const height = readLe16(mcs[i + 10 .. i + 12]);
        if (width < 200 or width > 8192 or height < 200 or height > 8192) continue;
        return i;
    }
    return null;
}

fn findClientNetworkBlock(mcs: []const u8) ?ClientNetworkBlock {
    var i: usize = 0;
    while (i + 8 <= mcs.len) : (i += 1) {
        if (readLe16(mcs[i .. i + 2]) != rdp_client_network_data_type) continue;
        const block_len: usize = @intCast(readLe16(mcs[i + 2 .. i + 4]));
        if (block_len < 8 or i + block_len > mcs.len) continue;
        const channel_count = readLe32(mcs[i + 4 .. i + 8]);
        if (channel_count > rdp_static_channel_max) continue;
        const required_len = 8 + @as(usize, @intCast(channel_count)) * 12;
        if (required_len > block_len) continue;
        return .{ .channel_count = channel_count };
    }
    return null;
}

fn parseErectDomain(packet: []const u8, stats: *ServiceStats) bool {
    const mcs = x224DataPayload(packet, stats, "erect-domain") orelse return false;
    if (mcs.len < 1 or mcs[0] != 0x04) return protocolBool(stats, "erect-domain");
    stats.mcs_erect_domain +%= 1;
    return true;
}

fn parseAttachUser(packet: []const u8, stats: *ServiceStats) bool {
    const mcs = x224DataPayload(packet, stats, "attach-user") orelse return false;
    if (mcs.len < 1 or mcs[0] != 0x28) return protocolBool(stats, "attach-user");
    stats.mcs_attach_user +%= 1;
    return true;
}

fn parseChannelJoin(packet: []const u8, stats: *ServiceStats) ?McsChannelJoinRequest {
    const mcs = x224DataPayload(packet, stats, "channel-join") orelse return null;
    if (mcs.len != 5 or mcs[0] != 0x38) {
        _ = protocolBool(stats, "channel-join");
        return null;
    }
    const initiator_offset = readBe16(mcs[1..3]);
    const initiator = @as(u32, mcs_user_channel_base) + @as(u32, initiator_offset);
    if (initiator != rdp_user_channel) {
        _ = protocolBool(stats, "channel-join-initiator");
        return null;
    }
    const channel_id = readBe16(mcs[3..5]);
    stats.last_channel_id = channel_id;
    stats.mcs_channel_joins +%= 1;
    return .{
        .initiator_offset = initiator_offset,
        .channel_id = channel_id,
    };
}

fn parseClientInfo(packet: []const u8, stats: *ServiceStats) ?RdpClientInfo {
    const payload = mcsUserDataView(packet) orelse {
        _ = protocolBool(stats, "client-info-mcs");
        return null;
    };
    const flags = rdpSecurityFlags(payload) orelse {
        _ = protocolBool(stats, "client-info-security");
        return null;
    };
    if ((flags & rdp_sec_info_pkt) == 0) {
        _ = protocolBool(stats, "client-info-flag");
        return null;
    }
    var info = RdpClientInfo{};
    if (!parseInfoPacketStrings(payload[4..], &info)) {
        _ = protocolBool(stats, "client-info-strings");
        return null;
    }
    stats.client_info +%= 1;
    return info;
}

fn checkAuth(app: *const App, stats: *ServiceStats, info: RdpClientInfo, config: *const Config) bool {
    const user = spanZ(info.user_name[0..]);
    const password = spanZ(info.password[0..]);
    if (bytesEq(user, spanZ(config.user_name[0..])) and bytesEq(password, spanZ(config.password[0..]))) {
        stats.auth_successes +%= 1;
        stats.security_auth_ok +%= 1;
        copyFixedZ(stats.last_security_state[0..], security_state_auth_ok);
        copyFixedZ(stats.last_auth_user[0..], user);
        if (config.log_passwords) copyFixedZ(stats.last_auth_password[0..], password);
        logAuth(app, r4os.abi.log_severity_info, "auth-ok", user, password, config.log_passwords);
        return true;
    }
    stats.auth_failures +%= 1;
    stats.security_auth_fail +%= 1;
    copyFixedZ(stats.last_security_state[0..], security_state_auth_fail);
    copyFixedZ(stats.last_failed_auth_user[0..], user);
    if (config.log_passwords) copyFixedZ(stats.last_failed_auth_password[0..], password);
    logAuth(app, r4os.abi.log_severity_warn, "auth-fail", user, password, config.log_passwords);
    setLastError(stats, "auth-fail");
    return false;
}

fn validateActivationClientInfo(app: *const App, stats: *ServiceStats, info: RdpClientInfo, config: *const Config, mode: RdpActivationMode) bool {
    return switch (mode) {
        .classic_plain => checkAuth(app, stats, info, config),
        .modern_protected => validateModernActivationClientInfo(app, stats, info, config),
    };
}

fn validateModernActivationClientInfo(app: *const App, stats: *ServiceStats, info: RdpClientInfo, config: *const Config) bool {
    const user = spanZ(info.user_name[0..]);
    const expected = spanZ(config.user_name[0..]);
    if (user.len != 0 and !bytesEq(user, expected)) {
        stats.auth_failures +%= 1;
        stats.security_auth_fail +%= 1;
        copyFixedZ(stats.last_security_state[0..], security_state_auth_fail);
        copyFixedZ(stats.last_failed_auth_user[0..], user);
        logAuth(app, r4os.abi.log_severity_warn, "modern-client-info-user-fail", user, "", false);
        setLastError(stats, "modern-client-info-user-fail");
        return false;
    }
    copyFixedZ(stats.last_auth_user[0..], expected);
    if (config.log_passwords) copyFixedZ(stats.last_auth_password[0..], spanZ(config.password[0..]));
    setLastError(stats, "modern-client-info-ok");
    return true;
}

fn parseShareControlPdu(packet: []const u8, expected: u16, stats: *ServiceStats, label: []const u8) bool {
    const payload = mcsUserData(packet, stats, label) orelse return false;
    if (payload.len < 6) return protocolBool(stats, label);
    const pdu_type = readLe16(payload[2..4]) & 0x0F_FF;
    if (pdu_type != expected) return protocolBool(stats, label);
    return true;
}

fn parseShareDataPdu(packet: []const u8, expected: u8, stats: *ServiceStats, label: []const u8) bool {
    const payload = mcsUserData(packet, stats, label) orelse return false;
    if (payload.len < 18) return protocolBool(stats, label);
    const pdu_type = readLe16(payload[2..4]) & 0x0F_FF;
    if (pdu_type != rdp_pdu_data) return protocolBool(stats, label);
    if (payload[14] != expected) return protocolBool(stats, label);
    return true;
}

fn shareDataBody(packet: []const u8, expected: u8, stats: *ServiceStats, label: []const u8) ?[]const u8 {
    const payload = mcsUserData(packet, stats, label) orelse return null;
    if (payload.len < 18) return protocolNull(stats, label);
    const pdu_type = readLe16(payload[2..4]) & 0x0F_FF;
    if (pdu_type != rdp_pdu_data or payload[14] != expected) return protocolNull(stats, label);
    const declared: usize = @intCast(readLe16(payload[12..14]));
    const available = payload.len - 18;
    const body_len = if (declared == available + 4)
        available
    else if (declared <= available)
        declared
    else if (declared >= 4 and declared - 4 <= available)
        declared - 4
    else
        return protocolNull(stats, label);
    return payload[18 .. 18 + body_len];
}

fn parseAndPushInputPdu(app: *const App, packet: []const u8, stats: *ServiceStats) bool {
    const body = shareDataBody(packet, rdp_pdu2_input, stats, "input") orelse return false;
    if (body.len < 4) return inputBool(stats, "input-short");
    const count = readLe16(body[0..2]);
    var pos: usize = 4;
    var pushed: u32 = 0;
    var i: u16 = 0;
    while (i < count) : (i += 1) {
        if (pos + 12 > body.len) return inputBool(stats, "input-event-short");
        const message_type = readLe16(body[pos + 4 .. pos + 6]);
        const event = body[pos + 6 .. pos + 12];
        if (message_type == rdp_input_event_sync) {
            pos += 12;
            continue;
        }
        if (!pushInputEvent(app, stats, message_type, event)) return false;
        pushed +%= 1;
        pos += 12;
    }
    if (pushed == 0) return inputBool(stats, "input-empty");
    stats.input_pdus +%= 1;
    setLastError(stats, "input-ok");
    return true;
}

fn pushInputEvent(app: *const App, stats: *ServiceStats, message_type: u16, data: []const u8) bool {
    if (data.len < 6) return inputBool(stats, "input-data-short");
    return switch (message_type) {
        rdp_input_event_scancode => pushKeyboardScancode(app, stats, data),
        rdp_input_event_unicode => pushUnicodeKey(app, stats, data),
        rdp_input_event_mouse => pushMouseInput(app, stats, data),
        else => inputBool(stats, "input-type"),
    };
}

fn pushUnicodeKey(app: *const App, stats: *ServiceStats, data: []const u8) bool {
    const flags = readLe16(data[0..2]);
    const code = readLe16(data[2..4]);
    if (code == 0 or code > 0xff) return inputBool(stats, "input-unicode");
    const kind = if ((flags & rdp_input_keyboard_flag_release) != 0)
        r4os.abi.remote_input_kind_key_up
    else
        r4os.abi.remote_input_kind_key_down;
    var event = r4os.abi.RemoteInputEvent{
        .kind = kind,
        .flags = if (kind == r4os.abi.remote_input_kind_key_down) r4os.abi.remote_input_flag_down else r4os.abi.remote_input_flag_up,
        .modifiers = stats.last_input_modifiers,
        .key = code,
        .timestamp_ticks = app.sys.ticks(),
    };
    return pushRemoteInput(app, stats, &event);
}

fn pushKeyboardScancode(app: *const App, stats: *ServiceStats, data: []const u8) bool {
    const flags = readLe16(data[0..2]);
    const code = readLe16(data[2..4]) & 0x00ff;
    const released = (flags & rdp_input_keyboard_flag_release) != 0;
    if (updateInputModifiers(stats, code, released)) return true;
    const key = scancodeToDesktopKey(code) orelse return true;
    var event = r4os.abi.RemoteInputEvent{
        .kind = if (released) r4os.abi.remote_input_kind_key_up else r4os.abi.remote_input_kind_key_down,
        .flags = if (released) r4os.abi.remote_input_flag_up else r4os.abi.remote_input_flag_down,
        .modifiers = stats.last_input_modifiers,
        .key = key,
        .scancode = code,
        .timestamp_ticks = app.sys.ticks(),
    };
    return pushRemoteInput(app, stats, &event);
}

fn pushMouseInput(app: *const App, stats: *ServiceStats, data: []const u8) bool {
    const flags = readLe16(data[0..2]);
    var x: i32 = @intCast(readLe16(data[2..4]));
    var y: i32 = @intCast(readLe16(data[4..6]));
    if (stats.session_width != 0) x = @min(x, @as(i32, @intCast(stats.session_width - 1)));
    if (stats.session_height != 0) y = @min(y, @as(i32, @intCast(stats.session_height - 1)));
    var buttons = stats.last_input_buttons;
    var kind: u32 = r4os.abi.remote_input_kind_mouse_move;
    var wheel: i32 = 0;
    var event_flags: u32 = r4os.abi.remote_input_flag_absolute;

    if ((flags & rdp_pointer_flag_button1) != 0) {
        kind = r4os.abi.remote_input_kind_mouse_buttons;
        if ((flags & rdp_pointer_flag_down) != 0) {
            buttons |= 1;
            event_flags |= r4os.abi.remote_input_flag_down;
        } else {
            buttons &= ~@as(u32, 1);
            event_flags |= r4os.abi.remote_input_flag_up;
        }
    }
    if ((flags & rdp_pointer_flag_button2) != 0) {
        kind = r4os.abi.remote_input_kind_mouse_buttons;
        if ((flags & rdp_pointer_flag_down) != 0) {
            buttons |= 2;
            event_flags |= r4os.abi.remote_input_flag_down;
        } else {
            buttons &= ~@as(u32, 2);
            event_flags |= r4os.abi.remote_input_flag_up;
        }
    }
    if ((flags & rdp_pointer_flag_wheel) != 0) {
        kind = r4os.abi.remote_input_kind_mouse_wheel;
        wheel = @intCast(flags & 0x00ff);
        if (wheel == 0) wheel = 1;
        if ((flags & 0x0100) != 0) wheel = -wheel;
    } else if ((flags & rdp_pointer_flag_move) != 0) {
        kind = r4os.abi.remote_input_kind_mouse_move;
    }

    stats.last_input_buttons = buttons;
    var event = r4os.abi.RemoteInputEvent{
        .kind = kind,
        .flags = event_flags,
        .modifiers = stats.last_input_modifiers,
        .x = x,
        .y = y,
        .wheel = wheel,
        .buttons = buttons,
        .timestamp_ticks = app.sys.ticks(),
    };
    return pushRemoteInput(app, stats, &event);
}

fn pushRemoteInput(app: *const App, stats: *ServiceStats, event: *r4os.abi.RemoteInputEvent) bool {
    const rc = app.desk.remoteInputPush(event);
    if (rc <= 0) return inputBool(stats, "input-push");
    stats.input_events +%= 1;
    stats.input_pushes +%= 1;
    stats.last_input_kind = event.kind;
    stats.last_input_key = event.key;
    stats.last_input_scancode = event.scancode;
    stats.last_input_modifiers = event.modifiers;
    stats.last_input_x = event.x;
    stats.last_input_y = event.y;
    stats.last_input_wheel = event.wheel;
    stats.last_input_buttons = event.buttons;
    if (event.kind == r4os.abi.remote_input_kind_key_down or event.kind == r4os.abi.remote_input_kind_key_up) {
        stats.input_keys +%= 1;
    } else if (event.kind == r4os.abi.remote_input_kind_mouse_wheel) {
        stats.input_mouse +%= 1;
        stats.input_wheel +%= 1;
    } else {
        stats.input_mouse +%= 1;
    }
    var status: r4os.abi.RemoteInputStatus = .{};
    if (captureRemoteInputStatus(app, stats, &status)) stats.last_input_sequence = status.last_sequence;
    logRemoteInput(app, stats);
    return true;
}

fn captureRemoteInputStatus(app: *const App, stats: *ServiceStats, status: *r4os.abi.RemoteInputStatus) bool {
    if (app.desk.remoteInputStatus(status) != 0) return false;
    if (status.magic != r4os.abi.remote_input_magic or status.version != r4os.abi.remote_input_version) return false;
    stats.last_input_pending = status.pending;
    stats.last_input_pushed_total = status.pushed;
    stats.last_input_polled_total = status.polled;
    stats.last_input_dropped_total = status.dropped;
    return true;
}

fn logRemoteInput(app: *const App, stats: *const ServiceStats) void {
    app.sys.write("RDPSVC remote input: kind=");
    app.sys.printU64(@intCast(stats.last_input_kind));
    app.sys.write(" seq=");
    app.sys.printU64(@intCast(stats.last_input_sequence));
    app.sys.write(" key=");
    app.sys.printU64(@intCast(stats.last_input_key));
    app.sys.write(" x=");
    app.sys.printI32(stats.last_input_x);
    app.sys.write(" y=");
    app.sys.printI32(stats.last_input_y);
    app.sys.write(" wheel=");
    app.sys.printI32(stats.last_input_wheel);
    app.sys.write(" buttons=");
    app.sys.printU64(@intCast(stats.last_input_buttons));
    app.sys.println("");
}

fn updateInputModifiers(stats: *ServiceStats, scancode: u16, released: bool) bool {
    const mask: u32 = switch (scancode) {
        0x2a, 0x36 => r4os.abi.remote_input_modifier_shift,
        0x1d => r4os.abi.remote_input_modifier_ctrl,
        0x38 => r4os.abi.remote_input_modifier_alt,
        else => return false,
    };
    if (released) {
        stats.last_input_modifiers &= ~mask;
    } else {
        stats.last_input_modifiers |= mask;
    }
    return true;
}

fn scancodeToDesktopKey(scancode: u16) ?u8 {
    return switch (scancode) {
        0x01 => 0x1b,
        0x0f => '\t',
        0x1c => '\r',
        0x39 => ' ',
        0x13 => 'r',
        0x14 => 't',
        0x20 => 'd',
        else => null,
    };
}

fn inputBool(stats: *ServiceStats, label: []const u8) bool {
    stats.input_errors +%= 1;
    setLastError(stats, label);
    return false;
}

fn buildMcsConnectResponse(out: []u8, client_requested_protocols: u32, static_channel_count_raw: u32) ?usize {
    var server_data: [128]u8 = .{0} ** 128;
    var sd: usize = 0;
    if (!putBytes(server_data[0..], &sd, &.{ 0x01, 0x0C, 0x0C, 0x00 })) return null;
    if (!putLe32(server_data[0..], &sd, 0x0008_0004)) return null;
    if (!putLe32(server_data[0..], &sd, client_requested_protocols)) return null;
    if (!writeServerNetworkData(server_data[0..], &sd, static_channel_count_raw)) return null;
    if (!putBytes(server_data[0..], &sd, &.{ 0x02, 0x0C, 0x0C, 0x00 })) return null;
    if (!putLe32(server_data[0..], &sd, 0)) return null;
    if (!putLe32(server_data[0..], &sd, 0)) return null;

    var gcc: [128]u8 = .{0} ** 128;
    var gp: usize = 0;
    if (!putBytes(gcc[0..], &gp, &.{ 0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01 })) return null;
    if (!putPerLength(gcc[0..], &gp, 13 + perLengthSize(sd) + sd)) return null;
    if (!putBytes(gcc[0..], &gp, &.{ 0x14, 0x76, 0x0A, 0x01, 0x01, 0x00, 0x01, 0xC0, 0x00 })) return null;
    if (!putBytes(gcc[0..], &gp, "McDn")) return null;
    if (!putPerLength(gcc[0..], &gp, sd)) return null;
    if (!putBytes(gcc[0..], &gp, server_data[0..sd])) return null;

    var mcs_body: [192]u8 = .{0} ** 192;
    var mp: usize = 0;
    if (!putBytes(mcs_body[0..], &mp, &.{ 0x0A, 0x01, 0x00, 0x02, 0x01, 0x00 })) return null;
    if (!putBytes(mcs_body[0..], &mp, &.{ 0x30, 0x1A, 0x02, 0x01, 0x22, 0x02, 0x01, 0x03, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x03, 0x00, 0xFF, 0xF8, 0x02, 0x01, 0x02 })) return null;
    if (!putByte(mcs_body[0..], &mp, 0x04)) return null;
    if (!putBerLength(mcs_body[0..], &mp, gp)) return null;
    if (!putBytes(mcs_body[0..], &mp, gcc[0..gp])) return null;

    var mcs: [224]u8 = .{0} ** 224;
    var p: usize = 0;
    if (!putBytes(mcs[0..], &p, &.{ 0x7F, 0x66 })) return null;
    if (!putBerLength(mcs[0..], &p, mp)) return null;
    if (!putBytes(mcs[0..], &p, mcs_body[0..mp])) return null;
    return buildTpktX224Data(out, mcs[0..p]);
}

fn writeServerNetworkData(out: []u8, p: *usize, static_channel_count_raw: u32) bool {
    const channel_count: u16 = @intCast(@min(static_channel_count_raw, rdp_static_channel_max));
    const channel_bytes: u16 = channel_count * 2;
    const padding_bytes: u16 = if ((channel_count & 1) != 0) 2 else 0;
    const block_len: u16 = 8 + channel_bytes + padding_bytes;
    if (!putBytes(out, p, &.{ 0x03, 0x0C })) return false;
    if (!putLe16(out, p, block_len)) return false;
    if (!putLe16(out, p, rdp_io_channel)) return false;
    if (!putLe16(out, p, channel_count)) return false;
    var index: u16 = 0;
    while (index < channel_count) : (index += 1) {
        if (!putLe16(out, p, rdp_static_channel_base + index)) return false;
    }
    if (padding_bytes != 0 and !putLe16(out, p, 0)) return false;
    return true;
}

fn buildAttachUserConfirm(out: []u8) ?usize {
    var mcs: [4]u8 = .{ 0x2E, 0x00, 0, 0 };
    writeBe16(mcs[2..4], rdp_user_channel_offset);
    return buildTpktX224Data(out, mcs[0..]);
}

fn buildChannelJoinConfirm(out: []u8, request: McsChannelJoinRequest) ?usize {
    var mcs: [8]u8 = .{ 0x3E, 0x00, 0, 0, 0, 0, 0, 0 };
    writeBe16(mcs[2..4], request.initiator_offset);
    writeBe16(mcs[4..6], request.channel_id);
    writeBe16(mcs[6..8], request.channel_id);
    return buildTpktX224Data(out, mcs[0..]);
}

fn buildLicenseValidClient(out: []u8) ?usize {
    var payload: [24]u8 = .{0} ** 24;
    var p: usize = 0;
    if (!putLe16(payload[0..], &p, rdp_sec_license_pkt | rdp_sec_license_encrypt_cs)) return null;
    if (!putLe16(payload[0..], &p, 0)) return null;
    if (!putByte(payload[0..], &p, rdp_license_msg_error_alert)) return null;
    if (!putByte(payload[0..], &p, rdp_license_version_3)) return null;
    if (!putLe16(payload[0..], &p, 16)) return null;
    if (!putLe32(payload[0..], &p, rdp_license_status_valid_client)) return null;
    if (!putLe32(payload[0..], &p, rdp_license_state_no_transition)) return null;
    if (!putLe16(payload[0..], &p, rdp_license_blob_type_error)) return null;
    if (!putLe16(payload[0..], &p, 0)) return null;
    return buildMcsSendDataIndication(out, rdp_io_channel, payload[0..p]);
}

fn buildDemandActive(out: []u8, client_width: u32, client_height: u32) ?usize {
    var pdu: [512]u8 = .{0} ** 512;
    var p: usize = 0;
    if (!putLe16(pdu[0..], &p, 0)) return null;
    if (!putLe16(pdu[0..], &p, rdp_pdu_demand_active)) return null;
    if (!putLe16(pdu[0..], &p, rdp_user_channel)) return null;
    if (!putLe32(pdu[0..], &p, rdp_share_id)) return null;

    const source_descriptor = [_]u8{ 'R', 'D', 'P', 0 };
    if (!putLe16(pdu[0..], &p, source_descriptor.len)) return null;
    const capability_len_pos = p;
    if (!putLe16(pdu[0..], &p, 0)) return null;
    if (!putBytes(pdu[0..], &p, source_descriptor[0..])) return null;

    const capability_start = p;
    if (!putLe16(pdu[0..], &p, rdp_demand_capability_count)) return null;
    if (!putLe16(pdu[0..], &p, 0)) return null;
    if (!writeDemandActiveShareCapability(pdu[0..], &p)) return null;
    if (!writeDemandActiveGeneralCapability(pdu[0..], &p)) return null;
    if (!writeDemandActiveBitmapCapability(pdu[0..], &p, normalizeRdpDimension(client_width, rdp_demand_default_width), normalizeRdpDimension(client_height, rdp_demand_default_height))) return null;
    if (!writeDemandActiveFontCapability(pdu[0..], &p)) return null;
    if (!writeDemandActiveOrderCapability(pdu[0..], &p)) return null;
    if (!writeDemandActiveBitmapCodecsCapability(pdu[0..], &p)) return null;
    if (!writeDemandActiveColorCacheCapability(pdu[0..], &p)) return null;
    if (!writeDemandActivePointerCapability(pdu[0..], &p)) return null;
    if (!writeDemandActiveInputCapability(pdu[0..], &p)) return null;
    if (!writeDemandActiveBitmapCacheRev3CodecIdCapability(pdu[0..], &p)) return null;
    const capability_len = p - capability_start;
    if (capability_len > 0xffff) return null;
    writeLe16(pdu[capability_len_pos .. capability_len_pos + 2], @intCast(capability_len));
    if (!putLe32(pdu[0..], &p, 0)) return null;

    writeLe16(pdu[0..2], @intCast(p));
    return buildMcsSendDataIndication(out, rdp_io_channel, pdu[0..p]);
}

fn normalizeRdpDimension(value: u32, fallback: u16) u16 {
    if (value == 0 or value > 0xffff) return fallback;
    return @intCast(value);
}

fn writeCapabilityHeader(out: []u8, p: *usize, capability_type: u16, length: u16) bool {
    return putLe16(out, p, capability_type) and putLe16(out, p, length);
}

fn writeDemandActiveGeneralCapability(out: []u8, p: *usize) bool {
    return writeCapabilityHeader(out, p, rdp_cap_general, 24) and
        putLe16(out, p, 1) and
        putLe16(out, p, 3) and
        putLe16(out, p, 0x0200) and
        putLe16(out, p, 0) and
        putLe16(out, p, 0) and
        putLe16(out, p, 0x0400) and
        putLe16(out, p, 0) and
        putLe16(out, p, 0) and
        putLe16(out, p, 0) and
        putByte(out, p, 1) and
        putByte(out, p, 1);
}

fn sessionBitsPerPixel() u16 {
    return if (g_compress_rle16) rdp_bitmap_bits_per_pixel_rle else rdp_bitmap_bits_per_pixel;
}

fn writeDemandActiveBitmapCapability(out: []u8, p: *usize, width: u16, height: u16) bool {
    return writeCapabilityHeader(out, p, rdp_cap_bitmap, 28) and
        putLe16(out, p, sessionBitsPerPixel()) and
        putLe16(out, p, 1) and
        putLe16(out, p, 1) and
        putLe16(out, p, 1) and
        putLe16(out, p, width) and
        putLe16(out, p, height) and
        putLe16(out, p, 0) and
        putLe16(out, p, 1) and
        putLe16(out, p, 1) and
        putLe16(out, p, 0) and
        putLe16(out, p, 0) and
        putLe16(out, p, 0);
}

fn writeDemandActiveOrderCapability(out: []u8, p: *usize) bool {
    if (!writeCapabilityHeader(out, p, rdp_cap_order, 88)) return false;
    const body = [_]u8{
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x42, 0x0f, 0x00,
        0x01, 0x00, 0x14, 0x00,
        0x00, 0x00, 0x01, 0x00,
        0x2f, 0x00, 0x22, 0x00,
        0x01, 0x01, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0xa1, 0x06, 0x02, 0x00,
        0x40, 0x42, 0x0f, 0x00,
        0x40, 0x42, 0x0f, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    return putBytes(out, p, body[0..]);
}

fn writeDemandActivePointerCapability(out: []u8, p: *usize) bool {
    return writeCapabilityHeader(out, p, rdp_cap_pointer, 10) and
        putLe16(out, p, 1) and
        putLe16(out, p, 25) and
        putLe16(out, p, 25);
}

fn writeDemandActiveShareCapability(out: []u8, p: *usize) bool {
    return writeCapabilityHeader(out, p, rdp_cap_share, 8) and
        putLe16(out, p, rdp_user_channel) and
        putLe16(out, p, 0xE2B5);
}

fn writeDemandActiveColorCacheCapability(out: []u8, p: *usize) bool {
    return writeCapabilityHeader(out, p, rdp_cap_color_cache, 8) and
        putLe16(out, p, 6) and
        putLe16(out, p, 0);
}

fn writeDemandActiveInputCapability(out: []u8, p: *usize) bool {
    if (!writeCapabilityHeader(out, p, rdp_cap_input, 88)) return false;
    if (!putLe16(out, p, 0x0115)) return false;
    var body: usize = 0;
    while (body < 82) : (body += 1) {
        if (!putByte(out, p, 0)) return false;
    }
    return true;
}

fn writeDemandActiveFontCapability(out: []u8, p: *usize) bool {
    return writeCapabilityHeader(out, p, rdp_cap_font, 4);
}

fn writeDemandActiveBitmapCodecsCapability(out: []u8, p: *usize) bool {
    const nscodec_guid = [_]u8{ 0xb9, 0x1b, 0x8d, 0xca, 0x0f, 0x00, 0x4f, 0x15, 0x58, 0x9f, 0xae, 0x2d, 0x1a, 0x87, 0xe2, 0xd6 };
    const jpeg_guid = [_]u8{ 0xe6, 0x4c, 0xaf, 0x1b, 0xed, 0x9e, 0x0c, 0x43, 0x86, 0x9a, 0xcb, 0x8b, 0x37, 0xb6, 0x62, 0x37 };
    return writeCapabilityHeader(out, p, rdp_cap_bitmap_codecs, 47) and
        putByte(out, p, 2) and
        putBytes(out, p, nscodec_guid[0..]) and
        putByte(out, p, 1) and
        putLe16(out, p, 3) and
        putByte(out, p, 1) and
        putByte(out, p, 1) and
        putByte(out, p, 3) and
        putBytes(out, p, jpeg_guid[0..]) and
        putByte(out, p, 0) and
        putLe16(out, p, 1) and
        putByte(out, p, 75);
}

fn writeDemandActiveBitmapCacheRev3CodecIdCapability(out: []u8, p: *usize) bool {
    return writeCapabilityHeader(out, p, rdp_cap_bitmap_cache_rev3_codec_id, 5) and
        putByte(out, p, 0);
}

fn buildShareDataPdu(out: []u8, pdu_type2: u8, body: []const u8) ?usize {
    var pdu: [96]u8 = .{0} ** 96;
    var p: usize = 0;
    if (body.len + 4 > 0xffff) return null;
    const total_len: u16 = @intCast(18 + body.len);
    if (!putLe16(pdu[0..], &p, total_len)) return null;
    if (!putLe16(pdu[0..], &p, rdp_pdu_data)) return null;
    if (!putLe16(pdu[0..], &p, rdp_user_channel)) return null;
    if (!putLe32(pdu[0..], &p, rdp_share_id)) return null;
    if (!putByte(pdu[0..], &p, 0)) return null;
    if (!putByte(pdu[0..], &p, 1)) return null;
    if (!putLe16(pdu[0..], &p, @intCast(body.len + 4))) return null;
    if (!putByte(pdu[0..], &p, pdu_type2)) return null;
    if (!putByte(pdu[0..], &p, 0)) return null;
    if (!putLe16(pdu[0..], &p, 0)) return null;
    if (!putBytes(pdu[0..], &p, body)) return null;
    return buildMcsSendDataIndication(out, rdp_io_channel, pdu[0..p]);
}

fn sendInitialBitmap(app: *const App, stream: TcpStream, transport: RdpTransport, out: []u8, stats: *ServiceStats) bool {
    return sendBitmapFrame(app, stream, transport, out, stats, 0, false, false, 0, 0, null);
}

// 0.56.35: Ein horizontaler Streifen des Vollbilds (rows y..y+h). Der
// initiale Schirm wird ueber mehrere Session-Loop-Iterationen in Streifen
// gemalt statt in EINEM blockierenden 225-PDU-Aufruf - sonst blockiert der
// Send die ganze Session (kein Input, input_pdus=0) und mstsc trennt beim
// langsamen TCG-TLS-Dekodieren nach ~11-30% (bmp=0/416..944, frames=0).
fn sendBitmapStripe(app: *const App, stream: TcpStream, transport: RdpTransport, out: []u8, stats: *ServiceStats, stripe_y: u32, stripe_h: u32) bool {
    return sendBitmapFrame(app, stream, transport, out, stats, 0, false, false, stripe_y, stripe_h, null);
}

// Update im laufenden Betrieb: nur die vom Desktop gemeldete geaenderte Region
// senden (Dirty-Rect). Cursor-/UI-Aenderungen werden so winzig und schnell, und
// der einmalige Initial-Vollframe wird nicht mehr von Vollframes ueberrannt.
fn sendBitmapUpdate(app: *const App, stream: TcpStream, transport: RdpTransport, out: []u8, stats: *ServiceStats, cursor: ?*CursorTrack) bool {
    return sendBitmapFrame(app, stream, transport, out, stats, 0, false, true, 0, 0, cursor);
}

fn sendBitmapFrame(app: *const App, stream: TcpStream, transport: RdpTransport, out: []u8, stats: *ServiceStats, last_revision: u32, require_new: bool, dirty_only: bool, stripe_y: u32, stripe_h: u32, cursor: ?*CursorTrack) bool {
    if (!app.desk.supportsRemoteFrame()) {
        stats.bitmap_errors +%= 1;
        setLastError(stats, "frame-api");
        return false;
    }

    const info = if (require_new)
        waitForRemoteFrameAfter(app, stats, last_revision) orelse return false
    else
        waitForRemoteFrame(app, stats) orelse return false;
    if (!frameMatchesSession(app, stream, stats, &info)) return false;
    const geometry = bitmap_geometry.sessionGeometry(stats.session_width, stats.session_height) orelse {
        stats.bitmap_errors +%= 1;
        setLastError(stats, "frame-geometry-limit");
        logRdpGeometryRecord(app, stream, stats, &info, "missing-session", r4os.abi.log_severity_warn);
        return false;
    };

    // Standard: ganzer Frame. Bei dirty_only nur die geaenderte Region.
    // Bei stripe_h>0: nur der horizontale Streifen rows stripe_y..+stripe_h.
    var rect = bitmap_geometry.Rect{ .x = 0, .y = 0, .width = geometry.width, .height = geometry.height };
    if (stripe_h > 0) {
        rect = bitmap_geometry.stripeRect(geometry, stripe_y, stripe_h) orelse return true;
    } else if (dirty_only and
        (info.flags & r4os.abi.remote_frame_flag_dirty_valid) != 0 and
        info.dirty_x >= 0 and info.dirty_y >= 0 and
        info.dirty_w > 0 and info.dirty_h > 0)
    {
        const dx: u32 = @intCast(info.dirty_x);
        const dy: u32 = @intCast(info.dirty_y);
        rect = bitmap_geometry.clipRect(geometry, dx, dy, info.dirty_w, info.dirty_h) orelse
            bitmap_geometry.Rect{ .x = 0, .y = 0, .width = geometry.width, .height = geometry.height };
        // 0.56.35: Dirty-Region um die Cursor-Bewegung (letzte gesendete ->
        // aktuelle Position) erweitern, damit die alte Cursor-Spur in mstsc
        // aufgeraeumt wird. Nur wenn die Box moderat bleibt (grosse Spruenge
        // raeumt der naechste Frame auf - kein Riesen-Update erzwingen).
        if (cursor) |c| {
            if (c.x >= 0 and c.y >= 0 and
                (info.flags & r4os.abi.remote_frame_flag_cursor_valid) != 0 and
                info.cursor_x >= 0 and info.cursor_y >= 0)
            {
                const cur_x: u32 = @intCast(@min(info.cursor_x, @as(i32, @intCast(geometry.width - 1))));
                const cur_y: u32 = @intCast(@min(info.cursor_y, @as(i32, @intCast(geometry.height - 1))));
                const old_x: u32 = @intCast(@min(c.x, @as(i32, @intCast(geometry.width - 1))));
                const old_y: u32 = @intCast(@min(c.y, @as(i32, @intCast(geometry.height - 1))));
                const box_x0 = (@min(cur_x, old_x)) -| rdp_cursor_margin;
                const box_y0 = (@min(cur_y, old_y)) -| rdp_cursor_margin;
                const box_x1 = @min(@max(cur_x, old_x) + rdp_cursor_margin, geometry.width - 1);
                const box_y1 = @min(@max(cur_y, old_y) + rdp_cursor_margin, geometry.height - 1);
                const span_x = box_x1 - box_x0;
                const span_y = box_y1 - box_y0;
                // Deckel gegen Datenexplosion bei schnellen Spruengen.
                if (span_x <= rdp_cursor_max_span and span_y <= rdp_cursor_max_span) {
                    const nx0 = @min(rect.x, box_x0);
                    const ny0 = @min(rect.y, box_y0);
                    const nx1 = @max(rect.x + rect.width, box_x1 + 1);
                    const ny1 = @max(rect.y + rect.height, box_y1 + 1);
                    rect = bitmap_geometry.clipRect(geometry, nx0, ny0, nx1 - nx0, ny1 - ny0) orelse return true;
                }
            }
        }
    }

    // 0.59.6: RLE-Rechtecke bleiben auf dem bewaehrten 4-Pixel-Raster.
    // Eine krumme rechte Kante wird nicht mehr als unpassendes Raw32 in eine
    // 16-bpp-Sitzung gemischt, sondern separat als gepaddetes Raw16 gesendet.
    if (g_compress_rle16) rect = bitmap_geometry.alignRectForRle(geometry, rect);

    var pixels: [rdp_bitmap_tile_pixels]u32 = .{0} ** rdp_bitmap_tile_pixels;
    var row565: [rdp_bitmap_tile_pixels]u16 = undefined;
    var comp: [rle_tile_comp_max]u8 = undefined;
    var read_info: r4os.abi.RemoteFrameInfo = .{};
    var send_state: BitmapSendState = .{};
    var metrics = bitmap_geometry.ContentMetrics{};
    // 0.56.35: Multi-Rect-Buendelung fuer den RLE-Pfad.
    var rect_body: [rdp_bitmap_body_capacity]u8 = undefined;
    var rect_body_pos: usize = 0;
    var rect_count: u16 = 0;

    // 0.56.38: Shared-Frame - pro Frame frisch mappen (billiger
    // Tabellen-Call); bei Erfolg lesen die Zeilen direkt aus dem
    // Kernel-Puffer (Doppelkopie entfaellt), sonst bleibt
    // remoteFrameRead der vollstaendige Kompat-Pfad.
    var shared_pixels: ?[*]const u32 = null;
    {
        var map_info: r4os.abi.RemoteFrameMapInfo = .{};
        if (app.desk.remoteFrameMap(&map_info) == 0 and
            map_info.pixels_addr != 0 and
            map_info.capacity_pixels >= @as(u64, info.width) * @as(u64, info.height))
        {
            shared_pixels = @ptrFromInt(map_info.pixels_addr);
        }
    }

    var y: u32 = rect.y;
    while (y < rect.y + rect.height) {
        var x: u32 = 0;
        while (x < rect.width) {
            const tile = bitmap_geometry.nextTile(rect.width - x, g_compress_rle16) orelse break;
            const tile_width = tile.width;
            const tw: usize = @intCast(tile_width);
            const offset_u64 = @as(u64, info.width) * @as(u64, y) + @as(u64, rect.x + x);
            if (offset_u64 > 0xffff_ffff) {
                stats.bitmap_errors +%= 1;
                setLastError(stats, "frame-offset");
                return false;
            }
            const row: []const u32 = if (shared_pixels) |sp| blk: {
                const offset: usize = @intCast(offset_u64);
                break :blk sp[offset .. offset + tw];
            } else blk: {
                const got = app.desk.remoteFrameRead(@intCast(offset_u64), pixels[0..tw], &read_info);
                if (got != @as(i32, @intCast(tw))) {
                    stats.bitmap_errors +%= 1;
                    setLastError(stats, "frame-read");
                    return false;
                }
                if (!validRemoteFrame(&read_info) or read_info.format != info.format or
                    !frameMatchesSession(app, stream, stats, &read_info))
                {
                    if (!bitmapFailureIsPermanent(stats)) {
                        stats.bitmap_errors +%= 1;
                        setLastError(stats, "frame-snapshot-change");
                    }
                    return false;
                }
                break :blk pixels[0..tw];
            };

            metrics = bitmap_geometry.updateContentMetrics(metrics, row, @intCast(offset_u64));

            switch (tile.encoding) {
                .rle16 => {
                    var ci: usize = 0;
                    while (ci < tw) : (ci += 1) {
                        row565[ci] = rgb565FromXrgb(row[ci]);
                    }
                    const comp_len = rleEncodeRow16(row565[0..tw], comp[0..]) orelse {
                        stats.bitmap_errors +%= 1;
                        setLastError(stats, "rle-encode");
                        return false;
                    };
                    // Body voll? Erst das bisherige Buendel als EIN PDU raus.
                    if (rect_body_pos + 18 + comp_len > rdp_bitmap_body_budget or rect_count >= rdp_bitmap_body_max_rects) {
                        if (!flushBitmapRectBody(app, stream, transport, out, stats, &send_state, rect_body[0..rect_body_pos], rect_count)) return false;
                        rect_body_pos = 0;
                        rect_count = 0;
                    }
                    if (!appendBitmapRectRle16(rect_body[0..], &rect_body_pos, rect.x + x, y, tile_width, comp[0..comp_len])) {
                        stats.bitmap_errors +%= 1;
                        setLastError(stats, "bitmap-body-append");
                        return false;
                    }
                    rect_count += 1;
                    stats.bitmap_comp_bytes +%= @intCast(comp_len);
                    stats.bitmap_raw_bytes +%= @intCast(tw * 2);
                    stats.bitmap_rle_rows +%= 1;
                    stats.bitmap_bytes +%= @intCast(comp_len);
                },
                .raw16 => {
                    const raw_len = raw16PaddedBytes(tile_width) orelse {
                        stats.bitmap_errors +%= 1;
                        setLastError(stats, "raw16-size");
                        return false;
                    };
                    if (rect_body_pos + 18 + raw_len > rdp_bitmap_body_budget or rect_count >= rdp_bitmap_body_max_rects) {
                        if (!flushBitmapRectBody(app, stream, transport, out, stats, &send_state, rect_body[0..rect_body_pos], rect_count)) return false;
                        rect_body_pos = 0;
                        rect_count = 0;
                    }
                    if (!appendBitmapRectRaw16(rect_body[0..], &rect_body_pos, rect.x + x, y, row)) {
                        stats.bitmap_errors +%= 1;
                        setLastError(stats, "bitmap-body-append");
                        return false;
                    }
                    rect_count += 1;
                    stats.bitmap_raw_bytes +%= @intCast(raw_len);
                    stats.bitmap_raw_rows +%= 1;
                    stats.bitmap_bytes +%= @intCast(raw_len);
                },
                .raw32 => {
                    const packet_len = buildBitmapUpdatePdu(out, rect.x + x, y, tile_width, 1, row) orelse {
                        stats.bitmap_errors +%= 1;
                        setLastError(stats, "bitmap-build");
                        return false;
                    };
                    if (!sendBitmapChunk(app, stream, transport, out[0..packet_len], stats, &send_state)) return false;
                    const raw_len = tw * @sizeOf(u32);
                    stats.bitmap_raw_bytes +%= @intCast(raw_len);
                    stats.bitmap_raw_rows +%= 1;
                    stats.bitmap_bytes +%= @intCast(raw_len);
                },
            }
            stats.bitmap_updates +%= 1;
            stats.bitmap_rectangles +%= 1;
            stats.bitmap_pixels +%= @intCast(tile_width);
            x += tile_width;
        }
        if (shared_pixels != null) stats.bitmap_map_rows +%= 1 else stats.bitmap_copy_rows +%= 1;
        y += 1;
    }
    if (!flushBitmapRectBody(app, stream, transport, out, stats, &send_state, rect_body[0..rect_body_pos], rect_count)) return false;
    if (!flushBitmapSend(app, stream, stats, &send_state, "bitmap-ack-final")) return false;

    stats.bitmap_frames +%= 1;
    stats.last_frame_revision = info.revision;
    stats.last_frame_width = geometry.width;
    stats.last_frame_height = geometry.height;
    stats.last_frame_region_x = rect.x;
    stats.last_frame_region_y = rect.y;
    stats.last_frame_region_w = rect.width;
    stats.last_frame_region_h = rect.height;
    stats.last_frame_dirty_x = info.dirty_x;
    stats.last_frame_dirty_y = info.dirty_y;
    stats.last_frame_dirty_w = info.dirty_w;
    stats.last_frame_dirty_h = info.dirty_h;
    stats.last_frame_checksum = metrics.checksum;
    stats.last_frame_non_black_pixels = metrics.non_black_pixels;
    // 0.56.35: gesendete Cursor-Position merken (fuer das Aufraeumen der
    // Spur beim naechsten Dirty-Update).
    if (cursor) |c| {
        if ((info.flags & r4os.abi.remote_frame_flag_cursor_valid) != 0) {
            c.x = info.cursor_x;
            c.y = info.cursor_y;
        }
    }
    setLastError(stats, "bitmap-sent");
    logRdpBitmapRecord(app, stats);

    app.sys.write("RDPSVC bitmap frame: ok size=");
    app.sys.printU64(@intCast(geometry.width));
    app.sys.write("x");
    app.sys.printU64(@intCast(geometry.height));
    app.sys.write(" region=");
    app.sys.printU64(@intCast(rect.x));
    app.sys.write(",");
    app.sys.printU64(@intCast(rect.y));
    app.sys.write(",");
    app.sys.printU64(@intCast(rect.width));
    app.sys.write(",");
    app.sys.printU64(@intCast(rect.height));
    app.sys.write(" rev=");
    app.sys.printU64(@intCast(info.revision));
    app.sys.write(" updates=");
    app.sys.printU64(@intCast(stats.bitmap_updates));
    app.sys.write(" pixels=");
    app.sys.printU64(@intCast(stats.bitmap_pixels));
    app.sys.write(" bytes=");
    app.sys.printU64(@intCast(stats.bitmap_bytes));
    app.sys.write(" checksum=");
    app.sys.printU64(@intCast(metrics.checksum));
    app.sys.write(" nonblack=");
    app.sys.printU64(@intCast(metrics.non_black_pixels));
    app.sys.write(" comp=");
    app.sys.printU64(@intCast(stats.bitmap_comp_bytes));
    app.sys.write(" rawpx=");
    app.sys.printU64(@intCast(stats.bitmap_raw_bytes));
    app.sys.write(" dirty=");
    app.sys.printI32(info.dirty_x);
    app.sys.write(",");
    app.sys.printI32(info.dirty_y);
    app.sys.write(",");
    app.sys.printU64(@intCast(info.dirty_w));
    app.sys.write(",");
    app.sys.printU64(@intCast(info.dirty_h));
    app.sys.println("");
    return true;
}

fn waitForRemoteFrame(app: *const App, stats: *ServiceStats) ?r4os.abi.RemoteFrameInfo {
    const timeout = app.sys.ticksFromMilliseconds(rdp_remote_frame_wait_ms);
    const deadline = app.sys.ticks() + timeout;
    var info: r4os.abi.RemoteFrameInfo = .{};
    while (app.sys.ticks() <= deadline) {
        const rc = app.desk.remoteFrameInfo(&info);
        if (rc == 0 and validRemoteFrame(&info)) return info;
        app.sys.sleepTicks(1);
    }
    stats.bitmap_errors +%= 1;
    setLastError(stats, "frame-wait");
    return null;
}

fn waitForRemoteFrameAfter(app: *const App, stats: *ServiceStats, last_revision: u32) ?r4os.abi.RemoteFrameInfo {
    const timeout = app.sys.ticksFromMilliseconds(rdp_remote_frame_wait_ms);
    var info: r4os.abi.RemoteFrameInfo = .{};
    const rc = app.desk.remoteFrameWait(last_revision, timeout, &info);
    if (rc > 0 and validRemoteFrame(&info) and info.revision != last_revision) return info;
    if (rc == 0 and validRemoteFrame(&info) and info.revision != last_revision) return info;
    stats.bitmap_errors +%= 1;
    setLastError(stats, "frame-wait-new");
    return null;
}

fn validRemoteFrame(info: *const r4os.abi.RemoteFrameInfo) bool {
    if (info.magic != r4os.abi.remote_frame_magic or info.version != r4os.abi.remote_frame_version) return false;
    if ((info.flags & r4os.abi.remote_frame_flag_ready) == 0) return false;
    if (info.format != r4os.abi.remote_frame_format_xrgb32 or info.bytes_per_pixel != 4) return false;
    if (info.width == 0 or info.height == 0 or info.stride_pixels != info.width) return false;
    const pixels = @as(u64, info.width) * @as(u64, info.height);
    return pixels != 0 and pixels == @as(u64, info.frame_pixels) and pixels * 4 == @as(u64, info.frame_bytes);
}

// ---------------------------------------------------------------------------
// 0.56.26: Interleaved-RLE-Codec (MS-RDPBCGR 2.2.9.1.1.3.1.2.4 / 3.1.9).
// Encoder arbeitet zeilenweise (der Sendepfad schickt 1 Zeile pro PDU, damit
// gibt es keine Vorgaenger-Scanline) und nutzt das Order-Subset COLOR_RUN
// (0x3/0xF3) und COLOR_IMAGE (0x4/0xF4) - fuer Desktop-Inhalte (Flaechen)
// bereits hochwirksam und frei von fgPel-/FirstLine-Sonderfaellen.
// Der Test-Decoder implementiert zusaetzlich BG_RUN/FG_RUN/SET_FG/WHITE/BLACK
// nach Spec-Pseudocode (First-Line-Semantik), als Roundtrip-Referenz.
// ---------------------------------------------------------------------------

fn rgb565FromXrgb(px: u32) u16 {
    const r: u16 = @intCast((px >> 16) & 0xff);
    const g: u16 = @intCast((px >> 8) & 0xff);
    const b: u16 = @intCast(px & 0xff);
    return ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3);
}

// Order-Header + Laenge: regular-Form (5-Bit-Laenge), MEGA (Folgebyte = len-32)
// oder MEGA_MEGA (LE16-Laenge im Extended-Order).
fn rleEmitHeader(out: []u8, p: *usize, code3: u8, mega_mega: u8, len: usize) bool {
    if (len == 0) return false;
    if (len <= 31) return putByte(out, p, (code3 << 5) | @as(u8, @intCast(len)));
    if (len <= 287) {
        return putByte(out, p, code3 << 5) and putByte(out, p, @intCast(len - 32));
    }
    if (len > 0xffff) return false;
    return putByte(out, p, mega_mega) and
        putByte(out, p, @intCast(len & 0xff)) and
        putByte(out, p, @intCast(len >> 8));
}

fn rleEmitColorImage(pix: []const u16, out: []u8, p: *usize) bool {
    if (!rleEmitHeader(out, p, 0x4, 0xF4, pix.len)) return false;
    for (pix) |v| {
        if (!putByte(out, p, @intCast(v & 0xff))) return false;
        if (!putByte(out, p, @intCast(v >> 8))) return false;
    }
    return true;
}

fn rleEncodeRow16(row: []const u16, out: []u8) ?usize {
    var p: usize = 0;
    var i: usize = 0;
    var lit_start: usize = 0;
    while (i < row.len) {
        var run: usize = 1;
        while (i + run < row.len and row[i + run] == row[i]) run += 1;
        if (run >= 4) {
            if (i > lit_start) {
                if (!rleEmitColorImage(row[lit_start..i], out, &p)) return null;
            }
            if (!rleEmitHeader(out, &p, 0x3, 0xF3, run)) return null;
            if (!putByte(out, &p, @intCast(row[i] & 0xff))) return null;
            if (!putByte(out, &p, @intCast(row[i] >> 8))) return null;
            i += run;
            lit_start = i;
        } else {
            i += run;
        }
    }
    if (row.len > lit_start) {
        if (!rleEmitColorImage(row[lit_start..], out, &p)) return null;
    }
    return p;
}

// Test-Decoder nach Spec-Pseudocode (3.1.9), First-Line-Semantik (rows=1).
// Deckt das Encoder-Subset plus BG/FG/SET_FG/WHITE/BLACK ab; unbekannte
// Codes (FGBG/DITHERED) => null, der Encoder erzeugt sie nicht.
fn rleDecodeRow16(src: []const u8, dst: []u16) ?usize {
    var sp: usize = 0;
    var dp: usize = 0;
    var fg: u16 = 0xffff; // initiale Foreground-Farbe: weiss
    var insert_fg = false;
    while (sp < src.len) {
        const hdr = src[sp];
        const hi3: u8 = hdr >> 5;
        const code: u8 = if (hi3 < 6) hi3 else if ((hdr >> 4) < 0xF) (hdr >> 4) else hdr;
        var run: usize = 0;
        var adv: usize = 1;
        switch (code) {
            0x0, 0x1, 0x3, 0x4 => {
                run = hdr & 0x1F;
                if (run == 0) {
                    if (sp + 1 >= src.len) return null;
                    run = @as(usize, src[sp + 1]) + 32;
                    adv = 2;
                }
            },
            0xC => {
                run = hdr & 0x0F;
                if (run == 0) {
                    if (sp + 1 >= src.len) return null;
                    run = @as(usize, src[sp + 1]) + 16;
                    adv = 2;
                }
            },
            0xF0, 0xF1, 0xF3, 0xF4, 0xF6 => {
                if (sp + 2 >= src.len) return null;
                run = @as(usize, src[sp + 1]) | (@as(usize, src[sp + 2]) << 8);
                adv = 3;
            },
            0xFD, 0xFE => run = 1,
            else => return null,
        }
        sp += adv;
        const eff: u8 = switch (code) {
            0xF0 => 0x0,
            0xF1 => 0x1,
            0xF3 => 0x3,
            0xF4 => 0x4,
            0xF6 => 0xC,
            else => code,
        };
        if (eff == 0x0) {
            // Background Run auf der ersten Zeile: schwarz; direkt
            // aufeinanderfolgende BG-Runs bekommen 1 Foreground-Pixel.
            if (run == 0 or dp + run > dst.len) return null;
            if (insert_fg) {
                dst[dp] = fg;
                dp += 1;
                run -= 1;
            }
            while (run > 0) : (run -= 1) {
                dst[dp] = 0;
                dp += 1;
            }
            insert_fg = true;
            continue;
        }
        insert_fg = false;
        switch (eff) {
            0x1 => {
                if (dp + run > dst.len) return null;
                while (run > 0) : (run -= 1) {
                    dst[dp] = fg;
                    dp += 1;
                }
            },
            0xC => {
                if (sp + 1 >= src.len) return null;
                fg = @as(u16, src[sp]) | (@as(u16, src[sp + 1]) << 8);
                sp += 2;
                if (dp + run > dst.len) return null;
                while (run > 0) : (run -= 1) {
                    dst[dp] = fg;
                    dp += 1;
                }
            },
            0x3 => {
                if (sp + 1 >= src.len) return null;
                const px = @as(u16, src[sp]) | (@as(u16, src[sp + 1]) << 8);
                sp += 2;
                if (dp + run > dst.len) return null;
                while (run > 0) : (run -= 1) {
                    dst[dp] = px;
                    dp += 1;
                }
            },
            0x4 => {
                if (sp + run * 2 > src.len or dp + run > dst.len) return null;
                while (run > 0) : (run -= 1) {
                    dst[dp] = @as(u16, src[sp]) | (@as(u16, src[sp + 1]) << 8);
                    sp += 2;
                    dp += 1;
                }
            },
            0xFD => {
                if (dp >= dst.len) return null;
                dst[dp] = 0xffff;
                dp += 1;
            },
            0xFE => {
                if (dp >= dst.len) return null;
                dst[dp] = 0x0000;
                dp += 1;
            },
            else => return null,
        }
    }
    return dp;
}

// Bitmap-Update-PDU mit Interleaved-RLE-Nutzdaten (16bpp) inkl. 8-Byte
// TS_CD_HEADER (2.2.9.1.1.3.1.2.3): cbCompFirstRowSize=0, cbCompMainBodySize,
// cbScanWidth in PIXELN (muss durch 4 teilbar sein), cbUncompressedSize.
fn buildBitmapUpdatePduRle16(out: []u8, dest_x: u32, dest_y: u32, bitmap_width: u32, rows: u32, comp: []const u8) ?usize {
    if (bitmap_width == 0 or rows == 0 or dest_x > 0xffff or bitmap_width > 0xffff or dest_y > 0xffff) return null;
    if ((bitmap_width & 3) != 0) return null;
    const dest_right = dest_x + bitmap_width - 1;
    const dest_bottom = dest_y + rows - 1;
    if (dest_right > 0xffff or dest_bottom > 0xffff) return null;

    // Kein TS_CD_HEADER: General-Caps sagen NO_BITMAP_COMPRESSION_HDR an.
    const bitmap_bytes = comp.len;
    if (bitmap_bytes > 0xffff) return null;
    const body_len = 4 + 18 + bitmap_bytes;
    const data_len = 18 + body_len;
    if (data_len > 0xffff or data_len > 0x3fff) return null;
    const total = 7 + mcs_send_data_indication_header_len + perLengthSize(data_len) + data_len;
    if (out.len < total) return null;

    var p: usize = 0;
    if (!putByte(out, &p, 3)) return null;
    if (!putByte(out, &p, 0)) return null;
    if (!putBe16(out, &p, @intCast(total))) return null;
    if (!putByte(out, &p, 2)) return null;
    if (!putByte(out, &p, x224_dt_type)) return null;
    if (!putByte(out, &p, 0x80)) return null;

    if (!writeMcsSendDataIndicationHeader(out, &p, rdp_io_channel)) return null;
    if (!putPerLength(out, &p, data_len)) return null;

    if (!putLe16(out, &p, @intCast(data_len))) return null;
    if (!putLe16(out, &p, rdp_pdu_data)) return null;
    if (!putLe16(out, &p, rdp_user_channel)) return null;
    if (!putLe32(out, &p, rdp_share_id)) return null;
    if (!putByte(out, &p, 0)) return null;
    if (!putByte(out, &p, 1)) return null;
    if (!putLe16(out, &p, @intCast(body_len + 4))) return null;
    if (!putByte(out, &p, rdp_pdu2_update)) return null;
    if (!putByte(out, &p, 0)) return null;
    if (!putLe16(out, &p, 0)) return null;

    if (!putLe16(out, &p, rdp_update_type_bitmap)) return null;
    if (!putLe16(out, &p, 1)) return null;
    if (!putLe16(out, &p, @intCast(dest_x))) return null;
    if (!putLe16(out, &p, @intCast(dest_y))) return null;
    if (!putLe16(out, &p, @intCast(dest_right))) return null;
    if (!putLe16(out, &p, @intCast(dest_bottom))) return null;
    if (!putLe16(out, &p, @intCast(bitmap_width))) return null;
    if (!putLe16(out, &p, @intCast(rows))) return null;
    if (!putLe16(out, &p, rdp_bitmap_bits_per_pixel_rle)) return null;
    if (!putLe16(out, &p, rdp_bitmap_flag_compression | rdp_bitmap_flag_no_compression_hdr)) return null;
    if (!putLe16(out, &p, @intCast(bitmap_bytes))) return null;
    if (!putBytes(out, &p, comp)) return null;
    return if (p == total) p else null;
}

// 0.56.35: Ein Update-PDU aus vorgebauten TS_BITMAP_DATA-Eintraegen (body)
// mit rect_count Rechtecken; updateType/numberRectangles schreibt der
// Builder. Buendelt viele RLE-Zeilen in EIN PDU (statt 720 Mini-PDUs pro
// Vollframe je ein eigener TLS-Dispatch + TCP-Write).
fn buildBitmapUpdateMultiPdu(out: []u8, body: []const u8, rect_count: u16) ?usize {
    if (rect_count == 0 or body.len == 0) return null;
    const body_len = 4 + body.len;
    const data_len = 18 + body_len;
    if (data_len > 0x3fff) return null;
    const total = 7 + mcs_send_data_indication_header_len + perLengthSize(data_len) + data_len;
    if (out.len < total) return null;

    var p: usize = 0;
    if (!putByte(out, &p, 3)) return null;
    if (!putByte(out, &p, 0)) return null;
    if (!putBe16(out, &p, @intCast(total))) return null;
    if (!putByte(out, &p, 2)) return null;
    if (!putByte(out, &p, x224_dt_type)) return null;
    if (!putByte(out, &p, 0x80)) return null;

    if (!writeMcsSendDataIndicationHeader(out, &p, rdp_io_channel)) return null;
    if (!putPerLength(out, &p, data_len)) return null;

    if (!putLe16(out, &p, @intCast(data_len))) return null;
    if (!putLe16(out, &p, rdp_pdu_data)) return null;
    if (!putLe16(out, &p, rdp_user_channel)) return null;
    if (!putLe32(out, &p, rdp_share_id)) return null;
    if (!putByte(out, &p, 0)) return null;
    if (!putByte(out, &p, 1)) return null;
    if (!putLe16(out, &p, @intCast(body_len + 4))) return null;
    if (!putByte(out, &p, rdp_pdu2_update)) return null;
    if (!putByte(out, &p, 0)) return null;
    if (!putLe16(out, &p, 0)) return null;

    if (!putLe16(out, &p, rdp_update_type_bitmap)) return null;
    if (!putLe16(out, &p, rect_count)) return null;
    if (!putBytes(out, &p, body)) return null;
    return if (p == total) p else null;
}

// Haengt ein 1-Zeilen-RLE16-Rechteck (18-Byte-TS_BITMAP_DATA-Header + Daten)
// an den Multi-PDU-Body an.
fn appendBitmapRectRle16(body: []u8, pos: *usize, dest_x: u32, dest_y: u32, width: u32, comp: []const u8) bool {
    if (width == 0 or dest_x > 0xffff or dest_y > 0xffff or width > 0xffff or comp.len > 0xffff) return false;
    const dest_right = dest_x + width - 1;
    if (dest_right > 0xffff) return false;
    if (!putLe16(body, pos, @intCast(dest_x))) return false;
    if (!putLe16(body, pos, @intCast(dest_y))) return false;
    if (!putLe16(body, pos, @intCast(dest_right))) return false;
    if (!putLe16(body, pos, @intCast(dest_y))) return false;
    if (!putLe16(body, pos, @intCast(width))) return false;
    if (!putLe16(body, pos, 1)) return false;
    if (!putLe16(body, pos, rdp_bitmap_bits_per_pixel_rle)) return false;
    if (!putLe16(body, pos, rdp_bitmap_flag_compression | rdp_bitmap_flag_no_compression_hdr)) return false;
    if (!putLe16(body, pos, @intCast(comp.len))) return false;
    if (!putBytes(body, pos, comp)) return false;
    return true;
}

fn raw16PaddedBytes(width: u32) ?usize {
    if (width == 0 or width > 0xffff) return null;
    const raw = @as(usize, @intCast(width)) * @sizeOf(u16);
    const padded = (raw + 3) & ~@as(usize, 3);
    if (padded > 0xffff) return null;
    return padded;
}

// Unkomprimierter 16-bpp-Restreifen fuer Framebreiten, die nicht auf dem
// 4-Pixel-RLE-Raster enden. TS_BITMAP_DATA erlaubt die Kodierung pro
// Rechteck; jede Scanline wird auf ein Vielfaches von vier Bytes gepaddet.
fn appendBitmapRectRaw16(body: []u8, pos: *usize, dest_x: u32, dest_y: u32, pixels: []const u32) bool {
    if (pixels.len == 0 or pixels.len > 0xffff or dest_x > 0xffff or dest_y > 0xffff) return false;
    const width: u32 = @intCast(pixels.len);
    const dest_right = dest_x + width - 1;
    if (dest_right > 0xffff) return false;
    const bitmap_bytes = raw16PaddedBytes(width) orelse return false;

    if (!putLe16(body, pos, @intCast(dest_x))) return false;
    if (!putLe16(body, pos, @intCast(dest_y))) return false;
    if (!putLe16(body, pos, @intCast(dest_right))) return false;
    if (!putLe16(body, pos, @intCast(dest_y))) return false;
    if (!putLe16(body, pos, @intCast(width))) return false;
    if (!putLe16(body, pos, 1)) return false;
    if (!putLe16(body, pos, rdp_bitmap_bits_per_pixel_rle)) return false;
    if (!putLe16(body, pos, 0)) return false;
    if (!putLe16(body, pos, @intCast(bitmap_bytes))) return false;

    for (pixels) |pixel| {
        if (!putLe16(body, pos, rgb565FromXrgb(pixel))) return false;
    }
    var padding = bitmap_bytes - pixels.len * @sizeOf(u16);
    while (padding != 0) : (padding -= 1) {
        if (!putByte(body, pos, 0)) return false;
    }
    return true;
}

fn flushBitmapRectBody(app: *const App, stream: TcpStream, transport: RdpTransport, out: []u8, stats: *ServiceStats, send_state: *BitmapSendState, body: []const u8, rect_count: u16) bool {
    if (rect_count == 0) return true;
    const packet_len = buildBitmapUpdateMultiPdu(out, body, rect_count) orelse {
        stats.bitmap_errors +%= 1;
        setLastError(stats, "bitmap-build-multi");
        return false;
    };
    return sendBitmapChunk(app, stream, transport, out[0..packet_len], stats, send_state);
}

fn buildBitmapUpdatePdu(out: []u8, dest_x: u32, dest_y: u32, bitmap_width: u32, rows: u32, pixels: []const u32) ?usize {
    if (bitmap_width == 0 or rows == 0 or dest_x > 0xffff or bitmap_width > 0xffff or dest_y > 0xffff) return null;
    const dest_right = dest_x + bitmap_width - 1;
    const dest_bottom = dest_y + rows - 1;
    if (dest_right > 0xffff or dest_bottom > 0xffff) return null;
    const width: usize = @intCast(bitmap_width);
    const height: usize = @intCast(rows);
    if (pixels.len != width * height) return null;

    const bitmap_bytes = pixels.len * @sizeOf(u32);
    if (bitmap_bytes > 0xffff) return null;
    const body_len = 4 + 18 + bitmap_bytes;
    const data_len = 18 + body_len;
    if (data_len > 0xffff or data_len > 0x3fff) return null;
    const total = 7 + mcs_send_data_indication_header_len + perLengthSize(data_len) + data_len;
    if (out.len < total) return null;

    var p: usize = 0;
    if (!putByte(out, &p, 3)) return null;
    if (!putByte(out, &p, 0)) return null;
    if (!putBe16(out, &p, @intCast(total))) return null;
    if (!putByte(out, &p, 2)) return null;
    if (!putByte(out, &p, x224_dt_type)) return null;
    if (!putByte(out, &p, 0x80)) return null;

    if (!writeMcsSendDataIndicationHeader(out, &p, rdp_io_channel)) return null;
    if (!putPerLength(out, &p, data_len)) return null;

    if (!putLe16(out, &p, @intCast(data_len))) return null;
    if (!putLe16(out, &p, rdp_pdu_data)) return null;
    if (!putLe16(out, &p, rdp_user_channel)) return null;
    if (!putLe32(out, &p, rdp_share_id)) return null;
    if (!putByte(out, &p, 0)) return null;
    if (!putByte(out, &p, 1)) return null;
    if (!putLe16(out, &p, @intCast(body_len + 4))) return null;
    if (!putByte(out, &p, rdp_pdu2_update)) return null;
    if (!putByte(out, &p, 0)) return null;
    if (!putLe16(out, &p, 0)) return null;

    if (!putLe16(out, &p, rdp_update_type_bitmap)) return null;
    if (!putLe16(out, &p, 1)) return null;
    if (!putLe16(out, &p, @intCast(dest_x))) return null;
    if (!putLe16(out, &p, @intCast(dest_y))) return null;
    if (!putLe16(out, &p, @intCast(dest_right))) return null;
    if (!putLe16(out, &p, @intCast(dest_bottom))) return null;
    if (!putLe16(out, &p, @intCast(bitmap_width))) return null;
    if (!putLe16(out, &p, @intCast(rows))) return null;
    if (!putLe16(out, &p, rdp_bitmap_bits_per_pixel)) return null;
    if (!putLe16(out, &p, 0)) return null;
    if (!putLe16(out, &p, @intCast(bitmap_bytes))) return null;

    var row = height;
    while (row > 0) {
        row -= 1;
        const base = row * width;
        var x: usize = 0;
        while (x < width) : (x += 1) {
            // Rohpixel wie XRDP (out_uint32_le): das X-/High-Byte bleibt wie im
            // Framebuffer (i.d.R. 0x00); mstsc rendert die unteren 24 RGB-Bit.
            if (!putLe32(out, &p, pixels[base + x])) return null;
        }
    }
    return if (p == total) p else null;
}

fn buildMcsSendDataIndication(out: []u8, channel_id: u16, data: []const u8) ?usize {
    var mcs: [768]u8 = .{0} ** 768;
    var p: usize = 0;
    if (!writeMcsSendDataIndicationHeader(mcs[0..], &p, channel_id)) return null;
    if (!putPerLength(mcs[0..], &p, data.len)) return null;
    if (!putBytes(mcs[0..], &p, data)) return null;
    return buildTpktX224Data(out, mcs[0..p]);
}

fn writeMcsSendDataIndicationHeader(out: []u8, p: *usize, channel_id: u16) bool {
    return putByte(out, p, 0x68) and
        putBe16(out, p, rdp_user_channel_offset) and
        putBe16(out, p, channel_id) and
        putByte(out, p, 0x70);
}

fn buildTpktX224Data(out: []u8, payload: []const u8) ?usize {
    const total = 7 + payload.len;
    if (total > 0xFFFF or out.len < total) return null;
    out[0] = 3;
    out[1] = 0;
    writeBe16(out[2..4], @intCast(total));
    out[4] = 2;
    out[5] = x224_dt_type;
    out[6] = 0x80;
    if (payload.len != 0) @memcpy(out[7..total], payload);
    return total;
}

fn pollTcpState(app: *const App, stream: TcpStream, stats: *ServiceStats, stage: []const u8) ?r4os.abi.NetServiceTcpResult {
    var poll: r4os.abi.NetServiceTcpResult = .{};
    const rc = app.net.tcpPollServiceWait(stream.service_handle, &poll, tcpServiceWaitTicks(app));
    if (rc != 0) {
        stats.tcp_errors +%= 1;
        stats.last_tcp_result = rc;
        setLastError(stats, stage);
        return null;
    }
    stats.last_tcp_result = @intCast(@min(poll.tx_ack, @as(u32, 0x7fff_ffff)));
    return poll;
}

fn sendAll(app: *const App, stream: TcpStream, data: []const u8, stats: *ServiceStats, stage: []const u8) bool {
    // 0.56.35: Schreib-Stau ist beim Initial-Vollframe (720 Zeilen-PDUs)
    // NORMAL - mstsc ackt verzoegert, das 64K-Clientfenster laeuft voll und
    // der Paced-Write liefert 0 (nichts platziert). Vorher brach JEDER
    // Kurz-/Null-Write die Session ab (session result=protocol-error
    // last=bitmap-update tcpr=0, Abbruchzeile nicht-deterministisch 20/51/
    // 89/174) - der Kern des mstsc-Schwarzbilds. Jetzt: Rest nachschieben,
    // bei 0-Writes aufs TX-Fenster warten; harter Abbruch erst nach
    // rdp_tcp_write_timeout_ms insgesamt.
    const start = app.sys.ticks();
    const total_ticks = app.sys.ticksFromMilliseconds(rdp_tcp_write_timeout_ms);
    const chunk_ticks = app.sys.ticksFromMilliseconds(rdp_tcp_write_chunk_ms);
    var offset: usize = 0;
    while (offset < data.len) {
        if (app.sys.ticks() -% start >= total_ticks) {
            stats.tcp_errors +%= 1;
            stats.last_tcp_result = 0;
            setLastError(stats, stage);
            return false;
        }
        const written = app.net.tcpWritePacedServiceBounded(stream.service_handle, data[offset..], chunk_ticks, tcpServiceWaitTicks(app));
        if (written < 0) {
            stats.tcp_errors +%= 1;
            stats.last_tcp_result = written;
            setLastError(stats, stage);
            return false;
        }
        if (written == 0) {
            // 0.56.35: Rueckstau. mstsc dekodiert den TLS-Strom im TCG-Gast
            // langsam, das TX-Fenster ist zeitweise zu. NICHT nach dem
            // 10s-Fensterwait aufgeben (das riss den Vollframe frueher
            // nicht-deterministisch bei ~11% ab, trace=font-map last=
            // bitmap-update tcpr=0) - solange die Verbindung LEBT weiter
            // warten; nur der 60s-Gesamt-Timeout oben und ein toter Client
            // brechen ab.
            if (waitForTcpTxWindow(app, stream, 1, stats, stage) != null) continue;
            const state = tcpConnectionState(app, stream.conn_id);
            if (state == null or state.? == 0) {
                setLastError(stats, stage);
                return false;
            }
            app.sys.sleepTicks(1);
            continue;
        }
        offset += @intCast(written);
    }
    stats.bytes_tx +%= @intCast(data.len);
    return true;
}

fn writeRdpPacket(app: *const App, stream: TcpStream, transport: RdpTransport, data: []const u8, stats: *ServiceStats, stage: []const u8) bool {
    if (transport.tls) |tls| {
        return tlsWireWrite(app, stream, tls, data, stats, stage);
    }
    return sendAll(app, stream, data, stats, stage);
}

fn sendBitmapChunk(app: *const App, stream: TcpStream, transport: RdpTransport, data: []const u8, stats: *ServiceStats, send_state: *BitmapSendState) bool {
    if (data.len > 0xffff_ffff) return false;
    const data_window: u32 = @intCast(data.len);
    if (send_state.pending_bytes == 0) {
        send_state.batch_start_seq = 0;
    }
    if (!writeRdpPacket(app, stream, transport, data, stats, "bitmap-update")) return false;
    send_state.pending_bytes +%= data_window;
    if (send_state.pending_bytes >= rdp_tcp_ack_batch_bytes) {
        if (!flushBitmapSend(app, stream, stats, send_state, "bitmap-ack")) return false;
    }
    return true;
}

fn flushBitmapSend(app: *const App, stream: TcpStream, stats: *ServiceStats, send_state: *BitmapSendState, stage: []const u8) bool {
    if (send_state.pending_bytes == 0) return true;
    const poll = pollTcpState(app, stream, stats, stage) orelse return false;
    if (poll.tx_seq != 0) {
        _ = waitForTcpAck(app, stream, poll.tx_seq, stats, stage) orelse return false;
    }
    send_state.pending_bytes = 0;
    return true;
}

fn waitForTcpTxWindow(app: *const App, stream: TcpStream, target_window: u32, stats: *ServiceStats, stage: []const u8) ?r4os.abi.NetServiceTcpResult {
    const wait_ticks = app.sys.ticksFromMilliseconds(rdp_tcp_window_wait_ms);
    const retransmit_ticks = app.sys.ticksFromMilliseconds(rdp_tcp_retransmit_wait_ms);
    const start = app.sys.ticks();
    var last_retransmit = start;
    while (app.sys.ticks() - start < wait_ticks) {
        var poll: r4os.abi.NetServiceTcpResult = .{};
        const rc = app.net.tcpPollServiceWait(stream.service_handle, &poll, tcpServiceWaitTicks(app));
        if (rc != 0) {
            stats.tcp_errors +%= 1;
            stats.last_tcp_result = rc;
            setLastError(stats, stage);
            return null;
        }
        stats.last_tcp_result = @intCast(@min(poll.tx_window, @as(u32, 0x7fff_ffff)));
        if (poll.tx_window >= target_window) return poll;
        const now = app.sys.ticks();
        if (retransmit_ticks != 0 and now - last_retransmit >= retransmit_ticks) {
            var retry: r4os.abi.NetServiceTcpResult = .{};
            const retry_rc = tcpRetransmitServiceResultWait(app, stream.service_handle, &retry, tcpServiceWaitTicks(app));
            if (retry_rc == 0 and retry.result == 0) {
                stats.last_tcp_result = @intCast(@min(retry.retransmits, @as(u32, 0x7fff_ffff)));
            } else {
                stats.last_tcp_result = if (retry_rc != 0) retry_rc else retry.result;
            }
            last_retransmit = now;
        }
        app.sys.sleepTicks(1);
    }
    stats.tcp_errors +%= 1;
    stats.last_tcp_result = 0;
    setLastError(stats, stage);
    return null;
}

fn waitForTcpAck(app: *const App, stream: TcpStream, target_ack: u32, stats: *ServiceStats, stage: []const u8) ?r4os.abi.NetServiceTcpResult {
    const wait_ticks = app.sys.ticksFromMilliseconds(rdp_tcp_window_wait_ms);
    const retransmit_ticks = app.sys.ticksFromMilliseconds(rdp_tcp_retransmit_wait_ms);
    const start = app.sys.ticks();
    var last_retransmit = start;
    while (app.sys.ticks() - start < wait_ticks) {
        var poll: r4os.abi.NetServiceTcpResult = .{};
        const rc = app.net.tcpPollServiceWait(stream.service_handle, &poll, tcpServiceWaitTicks(app));
        if (rc != 0) {
            stats.tcp_errors +%= 1;
            stats.last_tcp_result = rc;
            setLastError(stats, stage);
            return null;
        }
        stats.last_tcp_result = @intCast(@min(poll.tx_ack, @as(u32, 0x7fff_ffff)));
        if (tcpSeqReached(poll.tx_ack, target_ack)) return poll;
        const now = app.sys.ticks();
        if (retransmit_ticks != 0 and now - last_retransmit >= retransmit_ticks) {
            var retry: r4os.abi.NetServiceTcpResult = .{};
            const retry_rc = tcpRetransmitServiceResultWait(app, stream.service_handle, &retry, tcpServiceWaitTicks(app));
            if (retry_rc == 0 and retry.result == 0) {
                stats.last_tcp_result = @intCast(@min(retry.retransmits, @as(u32, 0x7fff_ffff)));
            } else {
                stats.last_tcp_result = if (retry_rc != 0) retry_rc else retry.result;
            }
            last_retransmit = now;
        }
        app.sys.sleepTicks(1);
    }
    stats.tcp_errors +%= 1;
    stats.last_tcp_result = @intCast(@min(target_ack, @as(u32, 0x7fff_ffff)));
    setLastError(stats, stage);
    return null;
}

fn tcpSeqReached(current: u32, target: u32) bool {
    const diff: i32 = @bitCast(current -% target);
    return diff >= 0;
}

fn tcpRetransmitServiceResultWait(app: *const App, handle: u32, result: *r4os.abi.NetServiceTcpResult, wait_ticks: u64) i32 {
    return app.net.tcpRetransmitServiceResultWait(handle, result, wait_ticks);
}

fn x224DataPayload(packet: []const u8, stats: *ServiceStats, label: []const u8) ?[]const u8 {
    const payload = x224DataPayloadView(packet) orelse {
        _ = protocolBool(stats, label);
        return null;
    };
    stats.last_x224_type = packet[5] & 0xF0;
    return payload;
}

fn x224DataPayloadView(packet: []const u8) ?[]const u8 {
    if (packet.len < 8 or packet[4] != 2 or (packet[5] & 0xF0) != x224_dt_type or packet[6] != 0x80) return null;
    return packet[7..];
}

fn mcsUserData(packet: []const u8, stats: *ServiceStats, label: []const u8) ?[]const u8 {
    const mcs = x224DataPayload(packet, stats, label) orelse return null;
    const payload = mcsUserDataFromMcs(mcs) orelse {
        _ = protocolBool(stats, label);
        return null;
    };
    return payload;
}

fn mcsUserDataView(packet: []const u8) ?[]const u8 {
    const mcs = x224DataPayloadView(packet) orelse return null;
    return mcsUserDataFromMcs(mcs);
}

fn mcsUserDataFromMcs(mcs: []const u8) ?[]const u8 {
    if (mcs[0] != 0x64 and mcs[0] != 0x68) return null;
    // SendDataRequest (0x64, Client) und SendDataIndication (0x68, Server) haben
    // in T.125 dieselbe Struktur und damit denselben 6-Byte-Header:
    // choice(1) + initiator(2) + channelId(2) + dataPriority/segmentation(1).
    var p: usize = mcs_send_data_indication_header_len;
    if (mcs.len < p + 1) return null;
    const len = readPerLength(mcs, &p) orelse return null;
    if (p + len > mcs.len) return null;
    return mcs[p .. p + len];
}

fn rdpSecurityFlags(payload: []const u8) ?u16 {
    if (payload.len < 4) return null;
    return readLe16(payload[0..2]);
}

fn rdpPacketHasSecurityFlag(packet: []const u8, flag: u16) bool {
    const payload = mcsUserDataView(packet) orelse return false;
    const flags = rdpSecurityFlags(payload) orelse return false;
    return (flags & flag) != 0;
}

fn parseInfoPacketStrings(data: []const u8, out: *RdpClientInfo) bool {
    if (data.len < 18) return false;
    const cb_domain = readLe16(data[8..10]);
    const cb_user = readLe16(data[10..12]);
    const cb_password = readLe16(data[12..14]);
    const cb_shell = readLe16(data[14..16]);
    const cb_workdir = readLe16(data[16..18]);
    var p: usize = 18;
    if (!skipUtf16LeField(data, &p, cb_domain)) return false;
    if (!copyUtf16LeField(out.user_name[0..], data, &p, cb_user)) return false;
    if (!copyUtf16LeField(out.password[0..], data, &p, cb_password)) return false;
    if (!skipUtf16LeField(data, &p, cb_shell)) return false;
    if (!skipUtf16LeField(data, &p, cb_workdir)) return false;
    return p <= data.len;
}

fn copyUtf16LeField(dest: []u8, data: []const u8, pos: *usize, byte_len: u16) bool {
    const start = pos.*;
    const len: usize = @intCast(byte_len);
    if (start + len > data.len) return false;
    @memset(dest, 0);
    var in_pos = start;
    var out_pos: usize = 0;
    const end = start + len;
    while (in_pos + 1 < end and out_pos + 1 < dest.len) : (in_pos += 2) {
        const ch = data[in_pos];
        const hi = data[in_pos + 1];
        if (ch == 0 and hi == 0) break;
        dest[out_pos] = if (hi == 0 and ch >= 0x20 and ch < 0x7F) ch else '?';
        out_pos += 1;
    }
    pos.* = end;
    return consumeOptionalUtf16Terminator(data, pos);
}

fn skipUtf16LeField(data: []const u8, pos: *usize, byte_len: u16) bool {
    const start = pos.*;
    const len: usize = @intCast(byte_len);
    if (start + len > data.len) return false;
    pos.* = start + len;
    return consumeOptionalUtf16Terminator(data, pos);
}

fn consumeOptionalUtf16Terminator(data: []const u8, pos: *usize) bool {
    if (pos.* + 2 <= data.len and data[pos.*] == 0 and data[pos.* + 1] == 0) {
        pos.* += 2;
    }
    return pos.* <= data.len;
}

fn logAuth(app: *const App, severity: u8, label: []const u8, user: []const u8, password: []const u8, log_passwords: bool) void {
    var message: [r4os.abi.log_service_text_bytes]u8 = .{0} ** r4os.abi.log_service_text_bytes;
    var pos: usize = 0;
    appendText(message[0..], &pos, "rdp ");
    appendText(message[0..], &pos, label);
    appendText(message[0..], &pos, " user=");
    appendText(message[0..], &pos, user);
    if (log_passwords) {
        appendText(message[0..], &pos, " password=");
        appendText(message[0..], &pos, password);
    }
    _ = app.sys.logServiceWriteRecord(r4os.abi.log_service_source_service, r4os.abi.log_record_type_event, severity, log_origin, message[0..pos]);
}

fn protocolBool(stats: *ServiceStats, label: []const u8) bool {
    stats.protocol_errors +%= 1;
    setLastError(stats, label);
    return false;
}

fn protocolNull(stats: *ServiceStats, label: []const u8) ?[]const u8 {
    stats.protocol_errors +%= 1;
    setLastError(stats, label);
    return null;
}

fn waitForListen(app: *const App, port: u16, stats: *ServiceStats) bool {
    var waited: u32 = 0;
    while (waited < listen_wait_ticks) : (waited += 1) {
        var result: r4os.abi.NetServiceTcpResult = .{};
        const rc = app.net.tcpListenServiceResultWait(port, &result, tcpServiceWaitTicks(app));
        stats.last_tcp_result = if (rc == 0) result.result else rc;
        if (rc == 0 and result.result == r4os.abi.tcp_result_ok) {
            stats.listen_ready = 1;
            setLastError(stats, "listen-ready");
            app.sys.write("RDPSVC listen ");
            app.sys.printU64(@intCast(port));
            app.sys.println(": ready");
            return true;
        }
        if (waited == 0) {
            app.sys.write("RDPSVC waiting for TCPSVC/network on port ");
            app.sys.printU64(@intCast(port));
            app.sys.println("");
        }
        app.sys.sleepTicks(1);
    }
    stats.tcp_errors +%= 1;
    setLastError(stats, "listen-timeout");
    return false;
}

fn closeListener(app: *const App, port: u16, stats: *ServiceStats) void {
    var result: r4os.abi.NetServiceTcpResult = .{};
    const rc = app.net.tcpCloseListenServiceResultWait(port, &result, tcpServiceCleanupWaitTicks(app));
    stats.last_tcp_result = if (rc == 0) result.result else rc;
    if (rc == 0 and result.result == r4os.abi.tcp_result_ok) {
        stats.listener_closed +%= 1;
        setLastError(stats, "listener-closed");
    } else {
        stats.tcp_errors +%= 1;
        stats.listener_close_errors +%= 1;
        setLastError(stats, "listener-close");
    }
}

fn tcpServiceWaitTicks(app: *const App) u64 {
    return app.sys.ticksFromMilliseconds(tcp_service_wait_ms);
}

fn tcpServiceCleanupWaitTicks(app: *const App) u64 {
    return app.sys.ticksFromMilliseconds(tcp_service_cleanup_wait_ms);
}

fn logLifecycle(app: *const App, stats: *const ServiceStats, stream: TcpStream, result: SessionResult, close_ok: bool) void {
    app.sys.write("RDPSVC lifecycle: session=");
    app.sys.printU64(@intCast(stats.last_session_id));
    app.sys.write(" result=");
    app.sys.write(sessionResultName(result));
    app.sys.write(" active=");
    app.sys.printU64(@intCast(stats.active_sessions));
    app.sys.write(" accepted=");
    app.sys.printU64(@intCast(stats.accepted));
    app.sys.write(" closed=");
    app.sys.printU64(@intCast(stats.closed));
    app.sys.write(" completed=");
    app.sys.printU64(@intCast(stats.completed_sessions));
    app.sys.write(" disconnects=");
    app.sys.printU64(@intCast(stats.disconnects));
    app.sys.write(" reconnects=");
    app.sys.printU64(@intCast(stats.reconnects));
    app.sys.write(" cleanup=");
    app.sys.printU64(@intCast(stats.cleanup_ok));
    app.sys.write(" cleanup_errors=");
    app.sys.printU64(@intCast(stats.cleanup_errors));
    app.sys.write(" close_errors=");
    app.sys.printU64(@intCast(stats.close_errors));
    app.sys.write(" close_ok=");
    app.sys.write(if (close_ok) "yes" else "no");
    app.sys.write(" conn=");
    app.sys.printU64(@intCast(stream.conn_id));
    app.sys.write(" handle=");
    app.sys.printU64(@intCast(stream.service_handle));
    app.sys.write(" state=");
    app.sys.printU64(@intCast(stats.last_disconnect_state));
    app.sys.println("");
    logRdpSessionRecord(app, stats, stream, result);
}

fn traceActivationStage(app: *const App, stream: TcpStream, stats: *ServiceStats, stage: []const u8) void {
    copyFixedZ(stats.last_activation_trace[0..], stage);
    app.sys.write("RDPSVC trace conn=");
    app.sys.printU64(@intCast(stream.conn_id));
    app.sys.write(" stage=");
    app.sys.write(stage);
    app.sys.write(" mcs=");
    app.sys.printU64(@intCast(stats.mcs_connect_initial));
    app.sys.write("/");
    app.sys.printU64(@intCast(stats.mcs_connect_response));
    app.sys.write(" joins=");
    app.sys.printU64(@intCast(stats.mcs_channel_joins));
    app.sys.write("/");
    app.sys.printU64(@intCast(stats.mcs_expected_channel_joins));
    app.sys.write(" static_ch=");
    app.sys.printU64(@intCast(stats.mcs_static_channels));
    app.sys.write(" sec_exchange=");
    app.sys.printU64(@intCast(stats.security_exchange));
    app.sys.write(" client_info=");
    app.sys.printU64(@intCast(stats.client_info));
    app.sys.write(" license=");
    app.sys.printU64(@intCast(stats.license_valid_client));
    app.sys.write(" demand=");
    app.sys.printU64(@intCast(stats.demand_active));
    app.sys.write(" confirm=");
    app.sys.printU64(@intCast(stats.confirm_active));
    app.sys.write(" sync=");
    app.sys.printU64(@intCast(stats.client_sync));
    app.sys.write(" control=");
    app.sys.printU64(@intCast(stats.client_control));
    app.sys.write(" font=");
    app.sys.printU64(@intCast(stats.font_list));
    app.sys.write("/");
    app.sys.printU64(@intCast(stats.font_map));
    app.sys.write(" bitmap=");
    app.sys.printU64(@intCast(stats.bitmap_frames));
    app.sys.write(" last=");
    app.sys.write(spanZ(stats.last_error[0..]));
    app.sys.println("");
    logRdpTraceRecord(app, stats, stream, stage);
}

fn logRdpTraceRecord(app: *const App, stats: *const ServiceStats, stream: TcpStream, stage: []const u8) void {
    var message: [r4os.abi.log_service_text_bytes]u8 = .{0} ** r4os.abi.log_service_text_bytes;
    var pos: usize = 0;
    appendText(message[0..], &pos, "trace stage=");
    appendText(message[0..], &pos, stage);
    appendText(message[0..], &pos, " conn=");
    appendU64(message[0..], &pos, @intCast(stream.conn_id));
    appendText(message[0..], &pos, " last=");
    appendText(message[0..], &pos, spanZ(stats.last_error[0..]));
    appendText(message[0..], &pos, " mcs=");
    appendU64(message[0..], &pos, @intCast(stats.mcs_connect_initial));
    appendText(message[0..], &pos, "/");
    appendU64(message[0..], &pos, @intCast(stats.mcs_connect_response));
    appendText(message[0..], &pos, " joins=");
    appendU64(message[0..], &pos, @intCast(stats.mcs_channel_joins));
    appendText(message[0..], &pos, "/");
    appendU64(message[0..], &pos, @intCast(stats.mcs_expected_channel_joins));
    appendText(message[0..], &pos, " static_ch=");
    appendU64(message[0..], &pos, @intCast(stats.mcs_static_channels));
    appendText(message[0..], &pos, " sec_exchange=");
    appendU64(message[0..], &pos, @intCast(stats.security_exchange));
    appendText(message[0..], &pos, " client_info=");
    appendU64(message[0..], &pos, @intCast(stats.client_info));
    appendText(message[0..], &pos, " license=");
    appendU64(message[0..], &pos, @intCast(stats.license_valid_client));
    appendText(message[0..], &pos, " demand=");
    appendU64(message[0..], &pos, @intCast(stats.demand_active));
    appendText(message[0..], &pos, " confirm=");
    appendU64(message[0..], &pos, @intCast(stats.confirm_active));
    appendText(message[0..], &pos, " sync=");
    appendU64(message[0..], &pos, @intCast(stats.client_sync));
    appendText(message[0..], &pos, " control=");
    appendU64(message[0..], &pos, @intCast(stats.client_control));
    appendText(message[0..], &pos, " font=");
    appendU64(message[0..], &pos, @intCast(stats.font_list));
    appendText(message[0..], &pos, "/");
    appendU64(message[0..], &pos, @intCast(stats.font_map));
    appendText(message[0..], &pos, " bitmap=");
    appendU64(message[0..], &pos, @intCast(stats.bitmap_frames));
    _ = app.sys.logServiceWriteRecord(r4os.abi.log_service_source_service, r4os.abi.log_record_type_event, r4os.abi.log_severity_info, log_origin, message[0..pos]);
}

fn logRdpSessionRecord(app: *const App, stats: *const ServiceStats, stream: TcpStream, result: SessionResult) void {
    var message: [r4os.abi.log_service_text_bytes]u8 = .{0} ** r4os.abi.log_service_text_bytes;
    var pos: usize = 0;
    appendText(message[0..], &pos, "session result=");
    appendText(message[0..], &pos, sessionResultName(result));
    appendText(message[0..], &pos, " conn=");
    appendU64(message[0..], &pos, @intCast(stream.conn_id));
    appendText(message[0..], &pos, " trace=");
    appendText(message[0..], &pos, spanZ(stats.last_activation_trace[0..]));
    appendText(message[0..], &pos, " last=");
    const end_reason = spanZ(stats.session_end_error[0..]);
    appendText(message[0..], &pos, if (end_reason.len != 0) end_reason else spanZ(stats.last_error[0..]));
    // 0.56.35: Schwarzbild-Diagnose - die drei Werte trennen die Ursachen:
    // clientsize=0x0 => Client-Aufloesung nie geparst; bmp=frames/updates/errors
    // zeigt ob Frames rausgingen; tcpr = letzter TCP-Fehlercode am Abbruch.
    appendText(message[0..], &pos, " clientsize=");
    appendU64(message[0..], &pos, @intCast(stats.last_client_width));
    appendText(message[0..], &pos, "x");
    appendU64(message[0..], &pos, @intCast(stats.last_client_height));
    appendText(message[0..], &pos, " bmp=");
    appendU64(message[0..], &pos, @intCast(stats.bitmap_frames));
    appendText(message[0..], &pos, "/");
    appendU64(message[0..], &pos, @intCast(stats.bitmap_updates));
    appendText(message[0..], &pos, "/");
    appendU64(message[0..], &pos, @intCast(stats.bitmap_errors));
    appendText(message[0..], &pos, " bpp=");
    appendU64(message[0..], &pos, @intCast(sessionBitsPerPixel()));
    appendText(message[0..], &pos, " tcpr=");
    appendI32(message[0..], &pos, stats.last_tcp_result);
    appendText(message[0..], &pos, " joins=");
    appendU64(message[0..], &pos, @intCast(stats.mcs_channel_joins));
    appendText(message[0..], &pos, "/");
    appendU64(message[0..], &pos, @intCast(stats.mcs_expected_channel_joins));
    appendText(message[0..], &pos, " sec_exchange=");
    appendU64(message[0..], &pos, @intCast(stats.security_exchange));
    appendText(message[0..], &pos, " license=");
    appendU64(message[0..], &pos, @intCast(stats.license_valid_client));
    appendText(message[0..], &pos, " demand=");
    appendU64(message[0..], &pos, @intCast(stats.demand_active));
    appendText(message[0..], &pos, " confirm=");
    appendU64(message[0..], &pos, @intCast(stats.confirm_active));
    appendText(message[0..], &pos, " sync=");
    appendU64(message[0..], &pos, @intCast(stats.client_sync));
    appendText(message[0..], &pos, " control=");
    appendU64(message[0..], &pos, @intCast(stats.client_control));
    appendText(message[0..], &pos, " font=");
    appendU64(message[0..], &pos, @intCast(stats.font_list));
    appendText(message[0..], &pos, "/");
    appendU64(message[0..], &pos, @intCast(stats.font_map));
    _ = app.sys.logServiceWriteRecord(r4os.abi.log_service_source_service, r4os.abi.log_record_type_event, lifecycleLogSeverity(result), log_origin, message[0..pos]);
}

fn logRdpGeometryRecord(app: *const App, stream: TcpStream, stats: *const ServiceStats, info: ?*const r4os.abi.RemoteFrameInfo, reason: []const u8, severity: u8) void {
    var message: [r4os.abi.log_service_text_bytes]u8 = .{0} ** r4os.abi.log_service_text_bytes;
    var pos: usize = 0;
    appendText(message[0..], &pos, "rdp geometry reason=");
    appendText(message[0..], &pos, reason);
    appendText(message[0..], &pos, " conn=");
    appendU64(message[0..], &pos, @intCast(stream.conn_id));
    appendText(message[0..], &pos, " source=");
    appendU64(message[0..], &pos, if (info) |value| @intCast(value.width) else 0);
    appendText(message[0..], &pos, "x");
    appendU64(message[0..], &pos, if (info) |value| @intCast(value.height) else 0);
    appendText(message[0..], &pos, " client=");
    appendU64(message[0..], &pos, @intCast(stats.last_client_width));
    appendText(message[0..], &pos, "x");
    appendU64(message[0..], &pos, @intCast(stats.last_client_height));
    appendText(message[0..], &pos, " session=");
    appendU64(message[0..], &pos, @intCast(stats.session_width));
    appendText(message[0..], &pos, "x");
    appendU64(message[0..], &pos, @intCast(stats.session_height));
    appendText(message[0..], &pos, " bpp=");
    appendU64(message[0..], &pos, @intCast(sessionBitsPerPixel()));
    _ = app.sys.logServiceWriteRecord(r4os.abi.log_service_source_service, r4os.abi.log_record_type_event, severity, log_origin, message[0..pos]);

    app.sys.write("RDPSVC geometry: ");
    app.sys.write(message[0..pos]);
    app.sys.println("");
}

// Kompakte, vollstaendig sichtbare LOGSVC-Zeile pro gesendetem Bitmap-Frame.
// Per LOGCENTER /RDPTRACE abgreifbar. nonblack ist die eindeutige
// Inhaltsmetrik; der positionssensitive checksum dient nur der Aenderungsspur.
fn logRdpBitmapRecord(app: *const App, stats: *const ServiceStats) void {
    var message: [r4os.abi.log_service_text_bytes]u8 = .{0} ** r4os.abi.log_service_text_bytes;
    var pos: usize = 0;
    appendText(message[0..], &pos, "rdp bitmap frame=");
    appendU64(message[0..], &pos, @intCast(stats.last_frame_width));
    appendText(message[0..], &pos, "x");
    appendU64(message[0..], &pos, @intCast(stats.last_frame_height));
    appendText(message[0..], &pos, " region=");
    appendU64(message[0..], &pos, @intCast(stats.last_frame_region_x));
    appendText(message[0..], &pos, ",");
    appendU64(message[0..], &pos, @intCast(stats.last_frame_region_y));
    appendText(message[0..], &pos, ",");
    appendU64(message[0..], &pos, @intCast(stats.last_frame_region_w));
    appendText(message[0..], &pos, ",");
    appendU64(message[0..], &pos, @intCast(stats.last_frame_region_h));
    appendText(message[0..], &pos, " rev=");
    appendU64(message[0..], &pos, @intCast(stats.last_frame_revision));
    appendText(message[0..], &pos, " nonblack=");
    appendU64(message[0..], &pos, @intCast(stats.last_frame_non_black_pixels));
    appendText(message[0..], &pos, " updates=");
    appendU64(message[0..], &pos, @intCast(stats.bitmap_updates));
    appendText(message[0..], &pos, " bytes=");
    appendU64(message[0..], &pos, @intCast(stats.bitmap_bytes));
    appendText(message[0..], &pos, " comp=");
    appendU64(message[0..], &pos, @intCast(stats.bitmap_comp_bytes));
    appendText(message[0..], &pos, " raw=");
    appendU64(message[0..], &pos, @intCast(stats.bitmap_raw_bytes));
    appendText(message[0..], &pos, " rle_rows=");
    appendU64(message[0..], &pos, @intCast(stats.bitmap_rle_rows));
    appendText(message[0..], &pos, " checksum=");
    appendU64(message[0..], &pos, @intCast(stats.last_frame_checksum));
    _ = app.sys.logServiceWriteRecord(r4os.abi.log_service_source_service, r4os.abi.log_record_type_event, r4os.abi.log_severity_info, log_origin, message[0..pos]);
}

fn lifecycleLogSeverity(result: SessionResult) u8 {
    return switch (result) {
        .input_ok, .modern_activation_ok, .client_disconnect, .tls_wire_ok, .credssp_live_ok => r4os.abi.log_severity_info,
        else => r4os.abi.log_severity_warn,
    };
}

fn logStopSummary(app: *const App, stats: *const ServiceStats, reason: []const u8) void {
    app.sys.write("RDPSVC stop: reason=");
    app.sys.write(reason);
    app.sys.write(" active=");
    app.sys.printU64(@intCast(stats.active_sessions));
    app.sys.write(" accepted=");
    app.sys.printU64(@intCast(stats.accepted));
    app.sys.write(" closed=");
    app.sys.printU64(@intCast(stats.closed));
    app.sys.write(" cleanup=");
    app.sys.printU64(@intCast(stats.cleanup_ok));
    app.sys.write(" close_errors=");
    app.sys.printU64(@intCast(stats.close_errors));
    app.sys.write(" listener_closed=");
    app.sys.printU64(@intCast(stats.listener_closed));
    app.sys.write(" listener_close_errors=");
    app.sys.printU64(@intCast(stats.listener_close_errors));
    app.sys.write(" last=");
    app.sys.write(spanZ(stats.last_error[0..]));
    app.sys.println("");
}

fn runPingClient(app: *const App) i32 {
    app.sys.println("RDPSVC ping");
    var info: r4os.abi.ServiceInfo = .{};
    const handle = waitServiceOpen(app, &info, 100) orelse {
        app.sys.println("RDPSVC ping failed: service not open");
        return 1;
    };
    defer _ = app.sys.serviceClose(handle);

    var header: r4os.abi.ServiceMessageHeader = .{};
    var response: [32]u8 = undefined;
    const got = app.sys.serviceCall(handle, op_ping, "PING", &header, response[0..], 100);
    if (got != 11 or header.status != r4os.abi.service_api_result_ok or !bytesEq(response[0..11], "RDPSVC PONG")) {
        app.sys.println("RDPSVC ping failed");
        return 1;
    }
    app.sys.println("RDPSVC ping: OK");
    return 0;
}

fn runStatusClient(app: *const App) i32 {
    app.sys.println("RDPSVC status");
    var info: r4os.abi.ServiceInfo = .{};
    const handle = waitServiceOpen(app, &info, 100) orelse {
        app.sys.println("RDPSVC status failed: service not open");
        return 1;
    };
    defer _ = app.sys.serviceClose(handle);

    var header: r4os.abi.ServiceMessageHeader = .{};
    var response: [r4os.abi.service_api_max_payload]u8 = undefined;
    const got = app.sys.serviceCall(handle, op_status, "STATUS", &header, response[0..], 100);
    if (got <= 0 or header.status != r4os.abi.service_api_result_ok) {
        app.sys.println("RDPSVC status failed");
        return 1;
    }
    app.sys.write(response[0..@intCast(got)]);
    app.sys.println("");
    return 0;
}

// 0.56.26: Encoder->Decoder-Roundtrip ueber Referenzmuster (Flaechen,
// Verlaeufe, Rauschen, Alternierung, kurze Zeilen, MEGA-/MEGA_MEGA-Laengen).
// Bitidentitaet ist Pflicht; die Kompressionsrate wird ausgegeben.
fn selfTestRleCodec(app: *const App) bool {
    var raw_total: u64 = 0;
    var comp_total: u64 = 0;
    var case_idx: u32 = 0;
    while (case_idx < 7) : (case_idx += 1) {
        var row: [rdp_selftest_max_pixels]u16 = .{0} ** rdp_selftest_max_pixels;
        var width: usize = rdp_selftest_max_pixels;
        var seed: u32 = 0x1234_5678;
        switch (case_idx) {
            0 => {
                var i: usize = 0;
                while (i < width) : (i += 1) row[i] = 0x2104;
            },
            1 => {
                var i: usize = 0;
                while (i < width) : (i += 1) row[i] = if (i < width / 2) 0xF800 else 0x001F;
            },
            2 => {
                var i: usize = 0;
                while (i < width) : (i += 1) row[i] = @truncate(i);
            },
            3 => {
                var i: usize = 0;
                while (i < width) : (i += 1) {
                    seed = seed *% 1664525 +% 1013904223;
                    row[i] = @truncate(seed >> 16);
                }
            },
            4 => {
                var i: usize = 0;
                while (i < width) : (i += 1) row[i] = if ((i & 1) == 0) 0xAAAA else 0x5555;
            },
            5 => {
                width = 4;
                var i: usize = 0;
                while (i < width) : (i += 1) row[i] = 0x07E0;
            },
            6 => {
                width = 316;
                var i: usize = 0;
                while (i < 40) : (i += 1) row[i] = 0x8410;
                while (i < width) : (i += 1) {
                    seed = seed *% 1664525 +% 1013904223;
                    row[i] = @truncate(seed >> 16);
                }
            },
            else => {},
        }
        var comp: [rle_row_comp_max]u8 = undefined;
        var back: [rdp_selftest_max_pixels]u16 = undefined;
        const comp_len = rleEncodeRow16(row[0..width], comp[0..]) orelse {
            app.sys.write("RDPSVC rle selftest: encode failed case=");
            app.sys.printU64(@intCast(case_idx));
            app.sys.println("");
            return false;
        };
        const back_len = rleDecodeRow16(comp[0..comp_len], back[0..width]) orelse {
            app.sys.write("RDPSVC rle selftest: decode failed case=");
            app.sys.printU64(@intCast(case_idx));
            app.sys.println("");
            return false;
        };
        var ok = back_len == width;
        var i: usize = 0;
        while (ok and i < width) : (i += 1) ok = back[i] == row[i];
        if (!ok) {
            app.sys.write("RDPSVC rle selftest: mismatch case=");
            app.sys.printU64(@intCast(case_idx));
            app.sys.println("");
            return false;
        }
        raw_total += @as(u64, @intCast(width)) * 2;
        comp_total += @as(u64, @intCast(comp_len));
    }
    app.sys.write("RDPSVC rle selftest: ok cases=7 comp=");
    app.sys.printU64(comp_total);
    app.sys.write(" raw=");
    app.sys.printU64(raw_total);
    app.sys.println("");
    return true;
}

fn selfTestBitmapGeometry(app: *const App) bool {
    const geometry = bitmap_geometry.sessionGeometry(1920, 1080) orelse return false;
    if (geometry.width != 1920 or geometry.height != 1080) return false;
    if (bitmap_geometry.sessionGeometry(bitmap_geometry.max_session_width + 1, 1080) != null) return false;

    var remaining: u32 = 1366;
    var rle_tiles: u32 = 0;
    var raw16_pixels: u32 = 0;
    while (bitmap_geometry.nextTile(remaining, true)) |tile| {
        if (tile.width == 0 or tile.width > bitmap_geometry.tile_pixels) return false;
        switch (tile.encoding) {
            .rle16 => {
                if ((tile.width & (bitmap_geometry.rle_alignment_pixels - 1)) != 0) return false;
                rle_tiles += 1;
            },
            .raw16 => raw16_pixels += tile.width,
            .raw32 => return false,
        }
        remaining -= tile.width;
    }
    if (rle_tiles != 6 or raw16_pixels != 2) return false;

    const source = [_]u32{ 0x00ff_0000, 0x0000_ff00, 0x0000_00ff };
    const expected_lengths = [_]u16{ 4, 4, 8 };
    var width: usize = 1;
    while (width <= source.len) : (width += 1) {
        var body: [64]u8 = .{0} ** 64;
        var pos: usize = 0;
        if (!appendBitmapRectRaw16(body[0..], &pos, 1364, 767, source[0..width])) return false;
        const expected_len: usize = expected_lengths[width - 1];
        if (pos != 18 + expected_len) return false;
        if (readLe16(body[8..10]) != width or readLe16(body[10..12]) != 1) return false;
        if (readLe16(body[12..14]) != rdp_bitmap_bits_per_pixel_rle or readLe16(body[14..16]) != 0) return false;
        if (readLe16(body[16..18]) != expected_len) return false;
        if (readLe16(body[18..20]) != 0xf800) return false;
        if (width >= 2 and readLe16(body[20..22]) != 0x07e0) return false;
        if (width >= 3 and readLe16(body[22..24]) != 0x001f) return false;
        var padding = 18 + width * @sizeOf(u16);
        while (padding < pos) : (padding += 1) {
            if (body[padding] != 0) return false;
        }
    }

    const black = [_]u32{ 0, 0xff00_0000 };
    const colored = [_]u32{ 0, 0x0012_3456 };
    const black_metrics = bitmap_geometry.updateContentMetrics(.{}, black[0..], 0);
    const color_metrics = bitmap_geometry.updateContentMetrics(.{}, colored[0..], 0);
    if (black_metrics.checksum != 0 or black_metrics.non_black_pixels != 0) return false;
    if (color_metrics.checksum == 0 or color_metrics.non_black_pixels != 1) return false;

    app.sys.println("RDPSVC bitmap geometry selftest: ok modes=1280/1366/1920/3840/8192 raw16-tail=2 nonblack=1");
    return true;
}

fn runSelfTest(app: *const App) i32 {
    app.sys.println("RDPSVC selftest");
    if (!app.sys.hasFn("service_call")) return fail(app, "service-api");
    const repairs = ensureRegistryDefaults(app);
    const config = loadConfig(app);
    if (config.listen_port != default_listen_port) return fail(app, "listen-port");
    if (config.max_sessions != default_max_sessions) return fail(app, "max-sessions");
    if (!bytesEq(spanZ(config.user_name[0..]), default_user_name)) return fail(app, "user");
    if (!bytesEq(spanZ(config.password[0..]), default_password)) return fail(app, "password");
    if (!bytesEq(spanZ(config.client_target[0..]), default_client_target)) return fail(app, "client-target");
    if (!selfTestRleCodec(app)) return fail(app, "rle-codec");
    if (!selfTestBitmapGeometry(app)) return fail(app, "bitmap-geometry");
    if (!selfTestNegotiationCompatibility(app)) return fail(app, "negotiation-compat");
    var modern_stats: ServiceStats = .{};
    if (!selfTestModernProtocolContracts(app, &modern_stats, &config)) {
        app.sys.write("RDPSVC selftest modern-contract failed: ");
        app.sys.write(spanZ(modern_stats.last_error[0..]));
        app.sys.println("");
        return fail(app, "modern-contract");
    }
    setLastError(&modern_stats, "selftest");
    traceActivationStage(app, .{ .service_handle = 0, .conn_id = 0 }, &modern_stats, "selftest");
    app.sys.write("RDPSVC selftest: OK repairs=");
    app.sys.printU64(@intCast(repairs));
    app.sys.println("");
    return 0;
}

fn selfTestModernProtocolContracts(app: *const App, stats: *ServiceStats, config: *const Config) bool {
    if (!app.dev.hasFn("protocol_dispatch")) return modernSecurityBlocker(stats, "protocol-dispatch");

    var out: [1280]u8 = .{0} ** 1280;
    const tls_contract = dispatchProtocolText(app, r4tls_role, r4tls_op_stream_contract, "", out[0..], stats, "r4tls-contract") orelse return false;
    if (findBytes(tls_contract, "stream-contract") == null) return modernSecurityBlocker(stats, "r4tls-contract-text");
    if (!preflightR4TlsStreamAdapter(app, stats, tls_contract, out[0..])) return false;
    const tls_session_contract = dispatchProtocolText(app, r4tls_role, r4tls_op_tls12_session_contract, "", out[0..], stats, "r4tls-session-contract") orelse return false;
    if (findBytes(tls_session_contract, "tls12-session-contract") == null or findBytes(tls_session_contract, "rdpsvc=consumer-only") == null) return modernSecurityBlocker(stats, "r4tls-session-contract-text");
    const tls_session = dispatchProtocolText(app, r4tls_role, r4tls_op_tls12_session_harness, "", out[0..], stats, "r4tls-session") orelse return false;
    if (findBytes(tls_session, "client_finished=ok") == null or findBytes(tls_session, "server_finished=ok") == null or findBytes(tls_session, "next=credssp") == null) return modernSecurityBlocker(stats, "r4tls-session-text");
    stats.r4tls_session_ok +%= 1;

    const auth_state = dispatchProtocolText(app, r4auth_role, r4auth_op_credssp_state_contract, "", out[0..], stats, "r4auth-state") orelse return false;
    if (findBytes(auth_state, "credssp-state-machine") == null) return modernSecurityBlocker(stats, "r4auth-state-text");
    const windows_contract = dispatchProtocolText(app, r4auth_role, r4auth_op_credssp_windows_contract, "", out[0..], stats, "r4auth-windows-contract") orelse return false;
    if (findBytes(windows_contract, "credssp-windows-contract") == null or findBytes(windows_contract, "rdpsvc=consumer-only") == null) return modernSecurityBlocker(stats, "r4auth-windows-contract-text");
    const windows_harness = dispatchProtocolText(app, r4auth_role, r4auth_op_credssp_windows_harness, "", out[0..], stats, "r4auth-windows-harness") orelse return false;
    if (findBytes(windows_harness, "credssp-windows-harness") == null or findBytes(windows_harness, "tls_pubkey_binding=ok") == null or findBytes(windows_harness, "next=rdpsvc-stream") == null) return modernSecurityBlocker(stats, "r4auth-windows-harness-text");
    if (findBytes(windows_harness, "mixed_offer=ntlm") == null) return modernSecurityBlocker(stats, "r4auth-windows-mixed-offer");
    stats.r4auth_windows_ok +%= 1;
    if (!preflightR4AuthLiveCredssp(app, stats, out[0..])) return false;

    var request: [160]u8 = .{0} ** 160;
    const request_text = buildFixedCredentialRequest(request[0..], config);
    const auth = dispatchProtocolBytesNoBlocker(app, r4auth_role, r4auth_op_validate_fixed_credentials, request_text, out[0..], stats, "r4auth-validate") orelse return false;
    if (findBytes(auth, "result=ok") == null or findBytes(auth, "user=r4os") == null or findBytes(auth, "auth_model=fixed-single-user") == null) return modernSecurityBlocker(stats, "r4auth-validate-text");
    stats.auth_successes +%= 1;
    stats.security_auth_ok +%= 1;
    return true;
}

fn preflightR4AuthLiveCredssp(app: *const App, stats: *ServiceStats, out: []u8) bool {
    if (r4auth_op_credssp_live_contract != 18 or r4auth_op_credssp_process_live_state != 19 or r4auth_op_credssp_live_harness != 20) return modernSecurityBlocker(stats, "r4auth-live-op-map");

    const live_contract = dispatchProtocolText(app, r4auth_role, r4auth_op_credssp_live_contract, "", out, stats, "r4auth-live-contract") orelse return false;
    if (findBytes(live_contract, "credssp-live-contract") == null) return modernSecurityBlocker(stats, "r4auth-live-contract-text");
    if (findBytes(live_contract, "ops=op18:contract,op19:process,op20:harness") == null) return modernSecurityBlocker(stats, "r4auth-live-op-contract");
    if (findBytes(live_contract, "tls_required=yes") == null) return modernSecurityBlocker(stats, "r4auth-live-tls-contract");
    if (findBytes(live_contract, "tls_pubkey_hash=R4LK[-32]") == null) return modernSecurityBlocker(stats, "r4auth-live-pubkey-contract");
    if (findBytes(live_contract, "bad_password=-20") == null) return modernSecurityBlocker(stats, "r4auth-live-password-contract");
    if (findBytes(live_contract, "kerberos=blocked:-21") == null or findBytes(live_contract, "domain=blocked:-22") == null) return modernSecurityBlocker(stats, "r4auth-live-boundary-contract");
    if (findBytes(live_contract, "user=r4os;password=rosebud;permissions=none") == null) return modernSecurityBlocker(stats, "r4auth-live-fixed-creds-contract");
    if (findBytes(live_contract, "rdpsvc=consumer-only;next=rdpsvc-credssp-loop") == null) return modernSecurityBlocker(stats, "r4auth-live-consumer-contract");

    const live_harness = dispatchProtocolText(app, r4auth_role, r4auth_op_credssp_live_harness, "", out, stats, "r4auth-live-harness") orelse return false;
    if (findBytes(live_harness, "credssp-live-harness") == null) return modernSecurityBlocker(stats, "r4auth-live-harness-text");
    if (findBytes(live_harness, "negotiate=ok;challenge=ok;authenticate=ok;pubkeyauth=ok") == null) return modernSecurityBlocker(stats, "r4auth-live-flow-harness");
    if (findBytes(live_harness, "resume=ok") == null) return modernSecurityBlocker(stats, "r4auth-live-resume-harness");
    if (findBytes(live_harness, "tls_pubkey_binding=from-r4lk") == null) return modernSecurityBlocker(stats, "r4auth-live-binding-harness");
    if (findBytes(live_harness, "mixed_offer=ntlm") == null) return modernSecurityBlocker(stats, "r4auth-live-mixed-offer");
    if (findBytes(live_harness, "bad_password=blocked") == null or findBytes(live_harness, "kerberos=blocked") == null or findBytes(live_harness, "domain=blocked") == null or findBytes(live_harness, "missing_tls=blocked") == null) return modernSecurityBlocker(stats, "r4auth-live-negative-harness");
    if (findBytes(live_harness, "user=r4os;password=rosebud;next=rdpsvc-credssp-loop") == null) return modernSecurityBlocker(stats, "r4auth-live-fixed-creds-harness");

    stats.r4auth_live_ok +%= 1;
    stats.r4auth_loop_ok +%= 1;
    return true;
}

fn preflightR4TlsStreamAdapter(app: *const App, stats: *ServiceStats, stream_contract: []const u8, out: []u8) bool {
    if (r4tls_op_tls12_live_begin != 22 or r4tls_op_tls12_live_finish != 23 or r4tls_op_tls12_app_write != 24 or r4tls_op_tls12_app_read != 25) return modernSecurityBlocker(stats, "r4tls-op-map");
    if (findBytes(stream_contract, "r4lk_app_write=op24:R4AW->R4WX") == null) return modernSecurityBlocker(stats, "r4tls-app-write-contract");
    if (findBytes(stream_contract, "r4lk_app_read=op25:R4AR->R4RX") == null) return modernSecurityBlocker(stats, "r4tls-app-read-contract");
    if (findBytes(stream_contract, "would_block=net_service_status_would_block") == null) return modernSecurityBlocker(stats, "r4tls-wouldblock-contract");
    if (findBytes(stream_contract, "flush=consumer-waits-for-tcpsvc") == null) return modernSecurityBlocker(stats, "r4tls-flush-contract");
    if (findBytes(stream_contract, "close=close_notify+tcpsvc-close") == null) return modernSecurityBlocker(stats, "r4tls-close-contract");

    const productive = dispatchProtocolText(app, r4tls_role, r4tls_op_productive_contract, "", out, stats, "r4tls-productive-contract") orelse return false;
    if (findBytes(productive, "live_begin=op22:R4LB") == null) return modernSecurityBlocker(stats, "r4tls-live-begin-contract");
    if (findBytes(productive, "live_finish=op23:R4LF") == null) return modernSecurityBlocker(stats, "r4tls-live-finish-contract");
    if (findBytes(productive, "app_write=op24:R4AW->R4WX") == null) return modernSecurityBlocker(stats, "r4tls-app-write-productive");
    if (findBytes(productive, "app_read=op25:R4AR->R4RX") == null) return modernSecurityBlocker(stats, "r4tls-app-read-productive");

    const selftest = dispatchProtocolText(app, r4tls_role, r4tls_op_selftest, "", out, stats, "r4tls-selftest") orelse return false;
    if (findBytes(selftest, "R4TLS selftest OK") == null) return modernSecurityBlocker(stats, "r4tls-selftest-text");
    if (findBytes(selftest, "live=ok") == null) return modernSecurityBlocker(stats, "r4tls-live-selftest");
    if (findBytes(selftest, "app_write=ok") == null or findBytes(selftest, "app_read=ok") == null) return modernSecurityBlocker(stats, "r4tls-app-selftest");
    stats.r4tls_live_ok +%= 1;
    stats.r4tls_stream_ok +%= 1;
    return true;
}

fn negotiationCompatFail(app: *const App, step: u32) bool {
    app.sys.write("RDPSVC negotiation-compat fail step=");
    app.sys.printU64(@intCast(step));
    app.sys.println("");
    return false;
}

fn selfTestNegotiationCompatibility(app: *const App) bool {
    var classic_stats: ServiceStats = .{};
    const classic_initial = RdpInitial{};
    recordNegotiationCompatibility(&classic_stats, &classic_initial);
    if (classic_stats.compat_classic_selected != 1) return negotiationCompatFail(app, 1);
    if (classic_stats.compat_modern_requests != 0) return negotiationCompatFail(app, 2);
    if (classic_stats.security_classic != 1) return negotiationCompatFail(app, 3);
    if (classic_stats.last_selected_protocol != rdp_protocol_rdp) return negotiationCompatFail(app, 4);
    if (!bytesEq(spanZ(classic_stats.last_security_state[0..]), security_state_classic)) return negotiationCompatFail(app, 5);
    if (!bytesEq(spanZ(classic_stats.last_compat_blocker[0..]), "none")) return negotiationCompatFail(app, 6);

    var mstsc_stats: ServiceStats = .{};
    const mstsc_initial = RdpInitial{
        .source_ref = 0,
        .requested_protocols = rdp_protocol_ssl | rdp_protocol_hybrid | rdp_protocol_hybrid_ex,
        .has_negotiation = true,
    };
    recordNegotiationCompatibility(&mstsc_stats, &mstsc_initial);
    if (mstsc_stats.compat_classic_selected != 0) return negotiationCompatFail(app, 7);
    if (mstsc_stats.compat_modern_requests != 1) return negotiationCompatFail(app, 8);
    if (mstsc_stats.compat_tls_requests != 1) return negotiationCompatFail(app, 9);
    if (mstsc_stats.compat_nla_requests != 1) return negotiationCompatFail(app, 10);
    if (mstsc_stats.compat_hybrid_ex_requests != 1) return negotiationCompatFail(app, 11);
    if (mstsc_stats.compat_classic_downgrades != 0) return negotiationCompatFail(app, 12);
    if (mstsc_stats.last_selected_protocol != rdp_protocol_hybrid_ex) return negotiationCompatFail(app, 13);
    if (mstsc_stats.security_tls != 1) return negotiationCompatFail(app, 14);
    if (mstsc_stats.security_credssp != 1) return negotiationCompatFail(app, 15);
    if (mstsc_stats.last_compat_mask != (rdp_protocol_ssl | rdp_protocol_hybrid | rdp_protocol_hybrid_ex)) return negotiationCompatFail(app, 16);
    if (!bytesEq(spanZ(mstsc_stats.last_security_state[0..]), security_state_credssp)) return negotiationCompatFail(app, 17);
    if (!bytesEq(spanZ(mstsc_stats.last_compat_blocker[0..]), "none")) return negotiationCompatFail(app, 18);

    var ssl_stats: ServiceStats = .{};
    const ssl_initial = RdpInitial{
        .source_ref = 0,
        .requested_protocols = rdp_protocol_ssl,
        .has_negotiation = true,
    };
    recordNegotiationCompatibility(&ssl_stats, &ssl_initial);
    if (ssl_stats.last_selected_protocol != rdp_protocol_ssl) return negotiationCompatFail(app, 19);
    if (ssl_stats.security_tls != 1) return negotiationCompatFail(app, 20);
    if (ssl_stats.security_credssp != 0) return negotiationCompatFail(app, 21);
    if (!bytesEq(spanZ(ssl_stats.last_security_state[0..]), security_state_tls)) return negotiationCompatFail(app, 22);
    if (!bytesEq(spanZ(ssl_stats.last_compat_blocker[0..]), "none")) return negotiationCompatFail(app, 23);

    var rdstls_stats: ServiceStats = .{};
    const rdstls_initial = RdpInitial{
        .source_ref = 0,
        .requested_protocols = rdp_protocol_rdstls,
        .has_negotiation = true,
    };
    recordNegotiationCompatibility(&rdstls_stats, &rdstls_initial);
    if (rdstls_stats.last_selected_protocol != rdp_protocol_rdstls) return negotiationCompatFail(app, 24);
    if (rdstls_stats.security_blockers != 1) return negotiationCompatFail(app, 25);
    if (!bytesEq(spanZ(rdstls_stats.last_security_state[0..]), security_state_blocker)) return negotiationCompatFail(app, 26);
    if (!bytesEq(spanZ(rdstls_stats.last_compat_blocker[0..]), "rdstls-not-supported")) return negotiationCompatFail(app, 99);
    return true;
}

fn waitServiceOpen(app: *const App, info: *r4os.abi.ServiceInfo, max_ticks: u32) ?u32 {
    var tick: u32 = 0;
    while (tick < max_ticks) : (tick += 1) {
        const rc = app.sys.serviceOpen(service_name, info);
        if (rc == r4os.abi.service_api_result_ok and info.handle != 0) return info.handle;
        app.sys.sleepTicks(1);
    }
    const rc = app.sys.serviceOpen(service_name, info);
    if (rc == r4os.abi.service_api_result_ok and info.handle != 0) return info.handle;
    return null;
}

fn ensureRegistryDefaults(app: *const App) u32 {
    if (!app.sys.hasFn("registry_get_value") or !app.sys.hasFn("registry_set_value")) return 0;
    var changed: u32 = 0;
    changed += ensureBool(app, "Enabled", default_enabled);
    changed += ensureString(app, "ClientTarget", default_client_target);
    changed += ensureString(app, "UserName", default_user_name);
    changed += ensureString(app, "Password", default_password);
    changed += ensureU32(app, "ListenPort", @intCast(default_listen_port));
    changed += ensureU32(app, "MaxSessions", default_max_sessions);
    changed += ensureBool(app, "LogPasswords", default_log_passwords);
    changed += ensureBool(app, "CompressRle16", default_compress_rle16);
    if (changed != 0) {
        app.sys.write("RDPSVC Registry defaults repaired=");
        app.sys.printU64(@intCast(changed));
        app.sys.println("");
    }
    return changed;
}

fn ensureString(app: *const App, name: [*:0]const u8, value: []const u8) u32 {
    if (registryValueExists(app, name)) return 0;
    return if (app.sys.registrySetString(registry_key, name, value) == r4os.abi.registry_api_result_ok) 1 else 0;
}

fn ensureU32(app: *const App, name: [*:0]const u8, value: u32) u32 {
    if (registryValueExists(app, name)) return 0;
    return if (app.sys.registrySetU32(registry_key, name, value) == r4os.abi.registry_api_result_ok) 1 else 0;
}

fn ensureBool(app: *const App, name: [*:0]const u8, value: bool) u32 {
    if (registryValueExists(app, name)) return 0;
    return if (app.sys.registrySetBool(registry_key, name, value) == r4os.abi.registry_api_result_ok) 1 else 0;
}

fn registryValueExists(app: *const App, name: [*:0]const u8) bool {
    var info: r4os.abi.RegistryValueInfo = .{};
    var data: [256]u8 = .{0} ** 256;
    const rc = app.sys.registryGetValue(registry_key, name, &info, data[0..]);
    return rc >= 0 or rc == r4os.abi.registry_api_result_buffer_too_small;
}

fn loadConfig(app: *const App) Config {
    var config = Config{};
    copyFixedZ(config.client_target[0..], default_client_target);
    copyFixedZ(config.user_name[0..], default_user_name);
    copyFixedZ(config.password[0..], default_password);

    if (!app.sys.hasFn("registry_get_value")) return config;
    config.enabled = readRegistryBool(app, "Enabled") orelse config.enabled;
    if (readRegistryU32(app, "ListenPort")) |port_raw| {
        if (port_raw > 0 and port_raw <= 65535) config.listen_port = @intCast(port_raw);
    }
    config.max_sessions = readRegistryU32(app, "MaxSessions") orelse config.max_sessions;
    if (config.max_sessions == 0) config.max_sessions = 1;
    config.log_passwords = readRegistryBool(app, "LogPasswords") orelse config.log_passwords;
    config.compress_rle16 = readRegistryBool(app, "CompressRle16") orelse config.compress_rle16;
    _ = readRegistryString(app, "ClientTarget", config.client_target[0..]);
    _ = readRegistryString(app, "UserName", config.user_name[0..]);
    _ = readRegistryString(app, "Password", config.password[0..]);
    return config;
}

fn readRegistryString(app: *const App, name: [*:0]const u8, out: []u8) bool {
    var info: r4os.abi.RegistryValueInfo = .{};
    var data: [96]u8 = .{0} ** 96;
    const rc = app.sys.registryGetValue(registry_key, name, &info, data[0..]);
    if (rc < 0) return false;
    if (info.value_type != r4os.abi.registry_value_type_string) return false;
    const got: usize = @intCast(rc);
    const available = @min(@min(got, @as(usize, @intCast(info.data_len))), data.len);
    copyFixedZ(out, data[0..available]);
    return true;
}

fn readRegistryU32(app: *const App, name: [*:0]const u8) ?u32 {
    var info: r4os.abi.RegistryValueInfo = .{};
    var data: [4]u8 = .{0} ** 4;
    const rc = app.sys.registryGetValue(registry_key, name, &info, data[0..]);
    if (rc < 0) return null;
    if (info.value_type != r4os.abi.registry_value_type_u32 or info.data_len != 4) return null;
    return @as(u32, data[0]) |
        (@as(u32, data[1]) << 8) |
        (@as(u32, data[2]) << 16) |
        (@as(u32, data[3]) << 24);
}

fn readRegistryBool(app: *const App, name: [*:0]const u8) ?bool {
    var info: r4os.abi.RegistryValueInfo = .{};
    var data: [1]u8 = .{0};
    const rc = app.sys.registryGetValue(registry_key, name, &info, data[0..]);
    if (rc < 0) return null;
    if (info.value_type != r4os.abi.registry_value_type_bool or info.data_len != 1) return null;
    return data[0] != 0;
}

fn fail(app: *const App, label: []const u8) i32 {
    app.sys.write("RDPSVC selftest FAILED: ");
    app.sys.println(label);
    return 1;
}

fn hasArg(args: [*:0]const u8, wanted: []const u8) bool {
    var offset: usize = 0;
    while (offset < 256 and args[offset] != 0) {
        while (offset < 256 and (args[offset] == ' ' or args[offset] == '\t')) : (offset += 1) {}
        const start = offset;
        while (offset < 256 and args[offset] != 0 and args[offset] != ' ' and args[offset] != '\t') : (offset += 1) {}
        if (equalsIgnoreCase(args[start..offset], wanted)) return true;
    }
    return false;
}

fn copyFixedZ(dest: []u8, src: []const u8) void {
    if (dest.len == 0) return;
    @memset(dest, 0);
    const len = @min(dest.len - 1, src.len);
    if (len != 0) @memcpy(dest[0..len], src[0..len]);
}

fn spanZ(value: []const u8) []const u8 {
    var len: usize = 0;
    while (len < value.len and value[len] != 0) : (len += 1) {}
    return value[0..len];
}

fn bytesEq(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

fn appendText(dest: []u8, pos: *usize, value: []const u8) void {
    if (pos.* >= dest.len) return;
    const len = @min(value.len, dest.len - pos.*);
    if (len != 0) @memcpy(dest[pos.* .. pos.* + len], value[0..len]);
    pos.* += len;
}

fn appendU64(dest: []u8, pos: *usize, value: u64) void {
    var tmp: [20]u8 = undefined;
    var n = value;
    var out_pos = tmp.len;
    if (n == 0) {
        out_pos -= 1;
        tmp[out_pos] = '0';
    } else {
        while (n > 0 and out_pos > 0) {
            out_pos -= 1;
            tmp[out_pos] = '0' + @as(u8, @intCast(n % 10));
            n /= 10;
        }
    }
    appendText(dest, pos, tmp[out_pos..]);
}

fn appendI32(dest: []u8, pos: *usize, value: i32) void {
    if (value < 0) {
        appendText(dest, pos, "-");
        appendU64(dest, pos, @intCast(-value));
    } else {
        appendU64(dest, pos, @intCast(value));
    }
}

fn putByte(dest: []u8, pos: *usize, value: u8) bool {
    if (pos.* >= dest.len) return false;
    dest[pos.*] = value;
    pos.* += 1;
    return true;
}

fn putBytes(dest: []u8, pos: *usize, value: []const u8) bool {
    if (pos.* + value.len > dest.len) return false;
    if (value.len != 0) @memcpy(dest[pos.* .. pos.* + value.len], value);
    pos.* += value.len;
    return true;
}

fn putBe16(dest: []u8, pos: *usize, value: u16) bool {
    if (pos.* + 2 > dest.len) return false;
    writeBe16(dest[pos.* .. pos.* + 2], value);
    pos.* += 2;
    return true;
}

fn putLe16(dest: []u8, pos: *usize, value: u16) bool {
    if (pos.* + 2 > dest.len) return false;
    writeLe16(dest[pos.* .. pos.* + 2], value);
    pos.* += 2;
    return true;
}

fn putLe32(dest: []u8, pos: *usize, value: u32) bool {
    if (pos.* + 4 > dest.len) return false;
    writeLe32(dest[pos.* .. pos.* + 4], value);
    pos.* += 4;
    return true;
}

fn putBerLength(dest: []u8, pos: *usize, value: usize) bool {
    if (value < 0x80) return putByte(dest, pos, @intCast(value));
    if (value <= 0xFF) {
        return putByte(dest, pos, 0x81) and putByte(dest, pos, @intCast(value));
    }
    if (value <= 0xFFFF) {
        return putByte(dest, pos, 0x82) and
            putByte(dest, pos, @intCast((value >> 8) & 0xFF)) and
            putByte(dest, pos, @intCast(value & 0xFF));
    }
    return false;
}

fn perLengthSize(value: usize) usize {
    return if (value <= 0x7F) 1 else 2;
}

fn putPerLength(dest: []u8, pos: *usize, value: usize) bool {
    if (value <= 0x7F) return putByte(dest, pos, @intCast(value));
    if (value <= 0x3FFF) {
        return putByte(dest, pos, 0x80 | @as(u8, @intCast((value >> 8) & 0x3F))) and
            putByte(dest, pos, @intCast(value & 0xFF));
    }
    return false;
}

fn readPerLength(data: []const u8, pos: *usize) ?usize {
    if (pos.* >= data.len) return null;
    const first = data[pos.*];
    pos.* += 1;
    if ((first & 0x80) == 0) return first;
    if (pos.* >= data.len) return null;
    const second = data[pos.*];
    pos.* += 1;
    return (@as(usize, first & 0x3F) << 8) | @as(usize, second);
}

fn findBytes(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0 or needle.len > haystack.len) return null;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (bytesEq(haystack[i .. i + needle.len], needle)) return i;
    }
    return null;
}

fn readBe16(data: []const u8) u16 {
    return (@as(u16, data[0]) << 8) | @as(u16, data[1]);
}

fn readBe32(data: []const u8) u32 {
    return (@as(u32, data[0]) << 24) |
        (@as(u32, data[1]) << 16) |
        (@as(u32, data[2]) << 8) |
        @as(u32, data[3]);
}

fn readLe16(data: []const u8) u16 {
    return @as(u16, data[0]) | (@as(u16, data[1]) << 8);
}

fn readLe32(data: []const u8) u32 {
    return @as(u32, data[0]) |
        (@as(u32, data[1]) << 8) |
        (@as(u32, data[2]) << 16) |
        (@as(u32, data[3]) << 24);
}

fn writeBe16(dest: []u8, value: u16) void {
    dest[0] = @intCast((value >> 8) & 0xFF);
    dest[1] = @intCast(value & 0xFF);
}

fn writeLe16(dest: []u8, value: u16) void {
    dest[0] = @intCast(value & 0xFF);
    dest[1] = @intCast((value >> 8) & 0xFF);
}

fn writeLe32(dest: []u8, value: u32) void {
    dest[0] = @intCast(value & 0xFF);
    dest[1] = @intCast((value >> 8) & 0xFF);
    dest[2] = @intCast((value >> 16) & 0xFF);
    dest[3] = @intCast((value >> 24) & 0xFF);
}

fn setLastError(stats: *ServiceStats, value: []const u8) void {
    copyFixedZ(stats.last_error[0..], value);
}

fn equalsIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (upper(a[i]) != upper(b[i])) return false;
    }
    return true;
}

fn upper(ch: u8) u8 {
    if (ch >= 'a' and ch <= 'z') return ch - ('a' - 'A');
    return ch;
}
