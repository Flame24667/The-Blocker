use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use tauri::{
    menu::MenuBuilder,
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager, WindowEvent,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
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
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
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