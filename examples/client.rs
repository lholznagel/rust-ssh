use failure::Error;
use std::net::TcpStream;

fn main() -> Result<(), Error> {
    let stream = TcpStream::connect("127.0.0.1:1337")?;
    let ssh_transport = ::ssh_transport::client::SSHClient::new(stream);
    ssh_transport.connect();

    Ok(())
}
