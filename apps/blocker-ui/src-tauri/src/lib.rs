use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use std::sync::Mutex;
use tauri::{Manager, RunEvent};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;

struct BackendSidecar {
    child: Mutex<Option<CommandChild>>,
}

use tauri::{
    menu::MenuBuilder,
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    WindowEvent,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(BackendSidecar {
            child: Mutex::new(None),
        })
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            start_backend_sidecar(app)?;

            let menu = MenuBuilder::new(app)
                .text("open", "Open The Blocker")
                .separator()
                .text("enable_protection", "Enable Protection")
                .text("disable_protection", "Disable Protection")
                .separator()
                .text("quit", "Quit")
                .build()?;

            let _tray = TrayIconBuilder::new()
                .tooltip("The Blocker")
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_main_window(tray.app_handle());
                    }
                })
                .build(app)?;

            app.on_menu_event(|app_handle, event| match event.id().0.as_str() {
                "open" => {
                    show_main_window(app_handle);
                }
                "enable_protection" => {
                    if let Err(error) = post_api("/protection/enable") {
                        eprintln!("Failed to enable protection: {error}");
                    }

                    show_main_window(app_handle);
                }
                "disable_protection" => {
                    if let Err(error) = post_api("/protection/disable") {
                        eprintln!("Failed to disable protection: {error}");
                    }

                    show_main_window(app_handle);
                }
                "quit" => {
                    app_handle.exit(0);
                }
                _ => {}
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();

                if let Err(error) = window.hide() {
                    eprintln!("Failed to hide window: {error}");
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            if let RunEvent::ExitRequested { .. } = event {
                let state = app_handle.state::<BackendSidecar>();
                let mut guard = state.child.lock().expect("backend sidecar lock poisoned");

                if let Some(child) = guard.take() {
                    let _ = child.kill();
                }
            }
        });
}

fn show_main_window(app_handle: &tauri::AppHandle) {
    let Some(window) = app_handle.get_webview_window("main") else {
        return;
    };

    if let Err(error) = window.show() {
        eprintln!("Failed to show window: {error}");
    }

    if let Err(error) = window.set_focus() {
        eprintln!("Failed to focus window: {error}");
    }
}

fn post_api(path: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect("127.0.0.1:4780")?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;

    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: 127.0.0.1:4780\r\n\
         Connection: close\r\n\
         Content-Length: 0\r\n\
         \r\n"
    );

    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    Ok(response)
}

fn start_backend_sidecar(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let app_data_dir = app.path().app_data_dir()?;
    std::fs::create_dir_all(&app_data_dir)?;

    let db_path = app_data_dir.join("blocker.db");
    let db_path_string = db_path.to_string_lossy().to_string();

    let sidecar_command = app
        .shell()
        .sidecar("blocker-cli")?
        .args(["dev-run", "--db", db_path_string.as_str()]);

    let (mut rx, child) = sidecar_command.spawn()?;

    {
        let state = app.state::<BackendSidecar>();
        let mut guard = state.child.lock().expect("backend sidecar lock poisoned");
        *guard = Some(child);
    }

    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(line) => {
                    println!(
                        "[blocker-backend] {}",
                        String::from_utf8_lossy(&line).trim()
                    );
                }
                CommandEvent::Stderr(line) => {
                    eprintln!(
                        "[blocker-backend] {}",
                        String::from_utf8_lossy(&line).trim()
                    );
                }
                CommandEvent::Terminated(payload) => {
                    eprintln!("[blocker-backend] terminated: {:?}", payload);
                }
                _ => {}
            }
        }
    });

    Ok(())
}
