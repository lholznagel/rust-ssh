use failure::Error;
use std::net::TcpStream;

fn main() -> Result<(), Error> {
    let stream = TcpStream::connect("127.0.0.1:22")?;
    let ssh_transport = ::rssh::client::SSHClient::new(stream);
    ssh_transport.connect();

    Ok(())
}
