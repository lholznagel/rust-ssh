use failure::Error;
use std::net::TcpListener;

fn main() -> Result<(), Error> {
    let listener = TcpListener::bind("127.0.0.1:1337")?;
    for stream in listener.incoming() {
        let ssh_transport = ::ssh_transport::SSHTransport::new(stream?);
        ssh_transport.accept();
    }

    Ok(())
}
