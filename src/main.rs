use tun_tap::{Iface, Mode::Tun};

fn main() {
    const BUF_SIZE: usize = 1500;
    let interface = Iface::new("", Tun).expect("Failed to create interface");
   
    let mut buf = vec![0; BUF_SIZE];
    loop {
        println!("Starting to get data");

        let result = interface.recv(&mut buf);
        match result {
            Ok(bytes) => {
                println!("Successfully recieved {} bytes", bytes);
            },
            Err(e) => {
                println!("Error recieving data: {}", e);
            }
        }
    }
}
