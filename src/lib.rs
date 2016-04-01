#[macro_use]
extern crate bitflags;
extern crate mio;
extern crate nom;
extern crate openssl;

use mio::{EventLoop, Handler, Sender};
use openssl::ssl::SslContext;
use openssl::ssl::SslMethod;
use openssl::x509::X509FileType;
use std::path::Path;

bitflags! {
    flags AuthMode: u32 {
        const PLAIN = 1,
        const LOGIN = 1 << 1,
        const GSSAPI = 1 << 2,
        const CRAMMD5 = 1 << 3
    }
}

struct Server <'ssl> {
    hostname: &'static [u8],
    tls: &'ssl mut SslContext
}

impl<'ssl> Server<'ssl> {
    pub fn new<'s>(hostname: &'static str, tls: &'s mut SslContext) -> Result<Server<'s>, String> {
        match tls.check_private_key() {
            Ok(_) => {},
            Err(e) => return Err(format!("{}", e))
        };

        match tls.set_ecdh_auto(true) {
            Ok(_) => {},
            Err(e) => return Err(format!("{}", e))
        };

        Ok(Server {
            hostname: hostname.as_bytes(),
            tls: tls
        })
    }

    pub fn start(&mut self) -> Result <(), &'static str> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ::Server;
    use std::path::Path;
    use openssl::ssl::{SslContext, SslMethod};
    use openssl::x509::X509FileType;

    #[test]
    fn hermes_normal() {
        let mut ssl: SslContext = SslContext::new(SslMethod::Tlsv1_2).unwrap();
        ssl.set_private_key_file(Path::new("material/ca.noenckey.pem"), X509FileType::PEM).unwrap();
        ssl.set_certificate_chain_file(Path::new("material/ca.cert.pem"), X509FileType::PEM).unwrap();

        let mut server: Server = match Server::new("localhost", &mut ssl) {
            Ok(s) => s,
            Err(e) => panic!("{}", e)
        };

        assert!(server.start().is_ok());
    }

    #[test]
    fn hermes_invalid_paths() {
        let mut ssl: SslContext = SslContext::new(SslMethod::Tlsv1_2).unwrap();

        assert!(ssl.set_private_key_file(Path::new("doesnotexist"), X509FileType::PEM).is_err());
        assert!(ssl.set_certificate_chain_file(Path::new("doesnotexist"), X509FileType::PEM).is_err());
        assert!(Server::new("localhost", &mut ssl).is_err());
    }
}
