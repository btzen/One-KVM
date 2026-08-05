#[cfg(unix)]
use axum::{
    extract::DefaultBodyLimit,
    routing::{delete, put},
};
use axum::{
    middleware,
    routing::{any, delete, get, patch, post, put},
    Router,
};
#[cfg(unix)]
use axum::extract::DefaultBodyLimit;
use std::sync::Arc;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use super::audio_ws::audio_ws_handler;
use super::handlers;
#[cfg(unix)]
use super::uac_ws::uac_audio_ws_handler;
use super::ws::ws_handler;
use crate::auth::auth_middleware;
use crate::auth::middleware::{console_middleware, manager_middleware};
use crate::hid::websocket::ws_hid_handler;
use crate::state::AppState;

pub fn create_router(state: Arc<AppState>) -> Router {
    let redfish_router = {
        let config = state.config.get();
        if config.redfish.enabled {
            Some(crate::redfish::routes::create_redfish_router(state.clone()))
        } else {
            None
        }
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/health", get(handlers::health_check))
        .route("/auth/login", post(handlers::login))
        .route("/auth/login/totp", post(handlers::login_totp))
        .route("/setup", get(handlers::setup_status))
        .route("/setup/init", post(handlers::setup_init));

    // Viewer routes (all authenticated users)
    // Streaming, self-service, and read-only config/status queries
    let user_routes = Router::new()
        .route("/info", get(handlers::system_info))
        .route("/auth/logout", post(handlers::logout))
        .route("/auth/check", get(handlers::auth_check))
        .route("/auth/password", post(handlers::change_password))
        .route("/auth/username", post(handlers::change_username))
        .route("/auth/totp", get(handlers::totp_status))
        .route(
            "/auth/totp/enrollment",
            post(handlers::begin_totp_enrollment),
        )
        .route(
            "/auth/totp/enrollment/confirm",
            post(handlers::confirm_totp_enrollment),
        )
        .route("/auth/totp/disable", post(handlers::disable_totp))
        .route("/devices", get(handlers::list_devices))
        .route("/video/input-status", get(handlers::video_input_status))
        .route("/ws", any(ws_handler))
        // Stream control (read + start for viewing; stop requires Operate)
        .route("/stream/status", get(handlers::stream_state))
        .route("/stream/start", post(handlers::stream_start))
        .route("/stream/mode", get(handlers::stream_mode_get))
        .route("/stream/codecs", get(handlers::stream_codecs_list))
        .route("/video/codecs", get(handlers::stream_codecs_list))
        .route("/stream/constraints", get(handlers::stream_constraints_get))
        // WebRTC endpoints
        .route("/webrtc/session", post(handlers::webrtc_create_session))
        .route("/webrtc/offer", post(handlers::webrtc_offer))
        .route("/webrtc/ice", post(handlers::webrtc_ice_candidate))
        .route("/webrtc/ice-servers", get(handlers::webrtc_ice_servers))
        .route("/webrtc/status", get(handlers::webrtc_status))
        .route("/webrtc/close", post(handlers::webrtc_close_session))
        // HID status (read-only)
        .route("/hid/status", get(handlers::hid_status))
        .route(
            "/hid/ch9329/descriptor",
            get(handlers::hid_ch9329_descriptor),
        )
        // Audio status and stream start (stop requires Operate)
        .route("/audio/status", get(handlers::audio_status))
        .route("/audio/start", post(handlers::start_audio_streaming))
        .route("/audio/devices", get(handlers::list_audio_devices))
        // Audio WebSocket endpoints
        .route("/ws/audio", any(audio_ws_handler))
        .route("/ws/uac-audio", any(uac_audio_ws_handler))
        // Config reads (accessible to all authenticated users)
        .route("/config", get(handlers::config::get_all_config))
        .route("/config/video", get(handlers::config::get_video_config))
        .route("/config/stream", get(handlers::config::get_stream_config))
        .route("/config/hid", get(handlers::config::get_hid_config))
        .route("/config/atx", get(handlers::config::get_atx_config))
        .route("/config/audio", get(handlers::config::get_audio_config))
        .route(
            "/config/rustdesk",
            get(handlers::config::get_rustdesk_config),
        )
        .route(
            "/config/rustdesk/status",
            get(handlers::config::get_rustdesk_status),
        )
        .route("/config/rtsp", get(handlers::config::get_rtsp_config))
        .route(
            "/config/rtsp/status",
            get(handlers::config::get_rtsp_status),
        )
        // VNC config read
        .route("/config/vnc", get(handlers::config::get_vnc_config))
        .route("/config/vnc/status", get(handlers::config::get_vnc_status))
        // Computer Use config read
        .route("/config/computer-use", get(handlers::computer_use_config))
        .route("/computer-use/session", get(handlers::computer_use_session))
        // ATX status and history (read-only)
        .route("/atx/status", get(handlers::atx_status))
        .route("/atx/wol/history", get(handlers::atx_wol_history))
        // Device discovery (read-only)
        .route("/devices/atx", get(handlers::devices::list_atx_devices))
        .route(
            "/devices/network",
            get(handlers::devices::list_network_interfaces),
        )
        .route("/devices/usb", get(handlers::devices::list_usb_devices))
        // Video encoder self-check (read-only)
        .route(
            "/video/encoder/self-check",
            get(handlers::video_encoder_self_check),
        );

    // Unix-only viewer routes (read-only OTG/MSD status)
    #[cfg(unix)]
    let user_routes = {
        user_routes
            .route("/hid/otg/self-check", get(handlers::hid_otg_self_check))
            .route(
                "/otg/network/status",
                get(handlers::config::get_otg_network_status),
            )
            .route("/config/msd", get(handlers::config::get_msd_config))
            .route(
                "/config/otg-network",
                get(handlers::config::get_otg_network_config),
            )
            .route("/config/uac", get(handlers::config::get_uac_config))
            // MSD status reads
            .route("/msd/status", get(handlers::msd_status))
            .route("/msd/images", get(handlers::msd_images_list))
            .route("/msd/images/{id}", get(handlers::msd_image_get))
            .route("/msd/drive", get(handlers::msd_drive_info))
            .route("/msd/drive/files", get(handlers::msd_drive_files))
            .route(
                "/msd/drive/files/{*path}",
                get(handlers::msd_drive_download),
            )
    };

    // Operator routes (Operate privilege: keyboard/mouse input + power control)
    let console_routes = Router::new()
        .route("/ws/hid", any(ws_hid_handler))
        .route("/hid/reset", post(handlers::hid_reset))
        .route("/stream/stop", post(handlers::stream_stop))
        .route("/audio/stop", post(handlers::stop_audio_streaming))
        .route("/atx/power", post(handlers::atx_power))
        .route("/atx/wol", post(handlers::atx_wol));

    // Administrator routes (Configure privilege: writes, management, user CRUD)
    let manager_routes = Router::new()
        // Config writes (Configure privilege required)
        .route(
            "/config/video",
            patch(handlers::config::update_video_config),
        )
        .route(
            "/config/stream",
            patch(handlers::config::update_stream_config),
        )
        .route("/config/hid", patch(handlers::config::update_hid_config))
        .route("/config/atx", patch(handlers::config::update_atx_config))
        .route(
            "/config/audio",
            patch(handlers::config::update_audio_config),
        )
        // Audio device/quality control
        .route("/audio/quality", post(handlers::set_audio_quality))
        .route("/audio/device", post(handlers::select_audio_device))
        // Stream mode/bitrate (write)
        .route("/stream/mode", post(handlers::stream_mode_set))
        .route("/stream/bitrate", post(handlers::stream_set_bitrate))
        // RustDesk config writes + sensitive reads
        .route(
            "/config/rustdesk",
            patch(handlers::config::update_rustdesk_config),
        )
        .route(
            "/config/rustdesk/password",
            get(handlers::config::get_device_password),
        )
        .route(
            "/config/rustdesk/regenerate-id",
            post(handlers::config::regenerate_device_id),
        )
        .route(
            "/config/rustdesk/regenerate-password",
            post(handlers::config::regenerate_device_password),
        )
        .route(
            "/config/rustdesk/start",
            post(handlers::config::start_rustdesk_service),
        )
        .route(
            "/config/rustdesk/stop",
            post(handlers::config::stop_rustdesk_service),
        )
        // VNC config writes
        .route("/config/vnc", patch(handlers::config::update_vnc_config))
        .route(
            "/config/vnc/start",
            post(handlers::config::start_vnc_service),
        )
        .route("/config/vnc/stop", post(handlers::config::stop_vnc_service))
        // RTSP config writes
        .route("/config/rtsp", patch(handlers::config::update_rtsp_config))
        .route(
            "/config/rtsp/start",
            post(handlers::config::start_rtsp_service),
        )
        .route(
            "/config/rtsp/stop",
            post(handlers::config::stop_rtsp_service),
        )
        // Auth / Redfish config (sensitive: reads + writes require Configure)
        .route("/config/auth", get(handlers::config::get_auth_config))
        .route("/config/auth", patch(handlers::config::update_auth_config))
        .route(
            "/config/redfish",
            get(handlers::config::get_redfish_config),
        )
        .route(
            "/config/redfish",
            patch(handlers::config::update_redfish_config),
        )
        // Web server config (sensitive: exposes TLS/port settings)
        .route("/config/web", get(handlers::config::get_web_config))
        .route("/config/web", patch(handlers::config::update_web_config))
        // Watchdog config
        .route(
            "/config/watchdog",
            get(handlers::config::get_watchdog_config),
        )
        .route(
            "/config/watchdog",
            patch(handlers::config::update_watchdog_config),
        )
        // Computer Use writes
        .route(
            "/config/computer-use",
            patch(handlers::computer_use_update_config),
        )
        .route("/computer-use/session", post(handlers::computer_use_start))
        .route(
            "/computer-use/session/stop",
            post(handlers::computer_use_stop),
        )
        .route("/ws/computer-use", any(handlers::computer_use_ws))
        // System control
        .route("/system/restart", post(handlers::system_restart))
        .route("/update/overview", get(handlers::update_overview))
        .route("/update/upgrade", post(handlers::update_upgrade))
        .route("/update/status", get(handlers::update_status))
        // USB device reset
        .route(
            "/devices/usb/reset",
            post(handlers::devices::reset_usb_device),
        )
        // Extension management
        .route("/extensions", get(handlers::extensions::list_extensions))
        .route("/extensions/{id}", get(handlers::extensions::get_extension))
        .route(
            "/extensions/{id}/start",
            post(handlers::extensions::start_extension),
        )
        .route(
            "/extensions/{id}/stop",
            post(handlers::extensions::stop_extension),
        )
        .route(
            "/extensions/{id}/logs",
            get(handlers::extensions::get_extension_logs),
        )
        .route(
            "/extensions/ttyd/config",
            patch(handlers::extensions::update_ttyd_config),
        )
        .route(
            "/extensions/gostc/config",
            patch(handlers::extensions::update_gostc_config),
        )
        .route(
            "/extensions/easytier/config",
            patch(handlers::extensions::update_easytier_config),
        )
        .route(
            "/extensions/frpc/config",
            patch(handlers::extensions::update_frpc_config),
        )
        // User management (RBAC CRUD)
        .route("/users", get(handlers::list_users))
        .route("/users", post(handlers::create_user))
        .route("/users/{user_id}", patch(handlers::update_user))
        .route("/users/{user_id}", delete(handlers::delete_user))
        // Terminal (ttyd) reverse proxy - WebSocket and HTTP
        .route("/terminal", get(handlers::terminal::terminal_index))
        .route("/terminal/", get(handlers::terminal::terminal_index))
        .route("/terminal/ws", get(handlers::terminal::terminal_ws))
        .route("/terminal/{*path}", get(handlers::terminal::terminal_proxy));

    // Unix-only administrator routes (MSD/OTG writes)
    #[cfg(unix)]
    let manager_routes = {
        manager_routes
            .route("/config/msd", patch(handlers::config::update_msd_config))
            .route("/config/otg", patch(handlers::config::update_otg_config))
            .route(
                "/config/otg-network",
                patch(handlers::config::update_otg_network_config),
            )
            .route(
                "/config/uac",
                patch(handlers::config::update_uac_config),
            )
            // MSD write operations
            .route("/msd/images/download", post(handlers::msd_image_download))
            .route(
                "/msd/images/download/cancel",
                post(handlers::msd_image_download_cancel),
            )
            .route("/msd/images/{id}", delete(handlers::msd_image_delete))
            .route("/msd/disk-mode", put(handlers::msd_disk_mode_put))
            .route("/msd/images/{id}/mount", post(handlers::msd_image_mount))
            .route(
                "/msd/images/{id}/mount",
                delete(handlers::msd_image_unmount),
            )
            .route("/msd/drive", delete(handlers::msd_drive_delete))
            .route("/msd/drive/mount", post(handlers::msd_drive_mount))
            .route("/msd/drive/mount", delete(handlers::msd_drive_unmount))
            .route("/msd/drive/init", post(handlers::msd_drive_init))
            .route(
                "/msd/drive/files/{*path}",
                delete(handlers::msd_drive_file_delete),
            )
            .route("/msd/drive/mkdir/{*path}", post(handlers::msd_drive_mkdir))
    };

    // Stream endpoints (accessible with auth, but typically embedded in pages)
    let stream_routes = Router::new()
        .route("/stream", get(handlers::mjpeg_stream))
        .route("/stream/mjpeg", get(handlers::mjpeg_stream))
        .route("/snapshot", get(handlers::snapshot));

    // Large file upload routes (MSD images and drive files)
    // Require Configure privilege (Administrator)
    #[cfg(unix)]
    let upload_routes = Router::new()
        .route("/msd/images", post(handlers::msd_image_upload))
        .route("/msd/drive/files", post(handlers::msd_drive_upload))
        .layer(DefaultBodyLimit::disable())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            manager_middleware,
        ));
    #[cfg(not(unix))]
    let upload_routes = Router::new();

    // Combine API routes with privilege layers
    let api_routes = Router::new()
        .merge(public_routes)
        .merge(user_routes)
        .merge(stream_routes)
        .merge(upload_routes)
        // Console routes: Operate privilege required (Operator+)
        .merge(console_routes.layer(middleware::from_fn_with_state(
            state.clone(),
            console_middleware,
        )))
        // Manager routes: Configure privilege required (Administrator only)
        .merge(manager_routes.layer(middleware::from_fn_with_state(
            state.clone(),
            manager_middleware,
        )))
        // All above routes require authentication (valid session)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // Static file serving
    let static_routes = super::static_files::static_file_router();

    // Main router
    let main_router = Router::new()
        .nest("/api", api_routes)
        .merge(static_routes)
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state);

    match redfish_router {
        Some(rf) => main_router.merge(rf),
        None => main_router,
    }
}
