#[macro_use]
extern crate bitflags;
extern crate lettre;
extern crate mio;
extern crate nom;
extern crate num_cpus;
extern crate openssl;
extern crate threadpool;

use nom::{digit, alpha, alphanumeric,
          line_ending, space, multispace,
          IResult};

use openssl::ssl::SslContext;
use openssl::ssl::SslMethod;
use openssl::x509::X509FileType;
use std::path::Path;
use threadpool::ThreadPool;

bitflags! {
    flags AuthMode: u32 {
        const PLAIN = 0b00000001,
        const LOGIN = 0b00000010,
        const GSSAPI = 0b00000100,
        const CRAMMD5 = 0b00001000
    }
}

struct Hermes {
    hostname: &'static [u8],
    tls: SslContext
}

impl Hermes {
    pub fn new() -> Hermes {
        let tls: SslContext = match SslContext::new(SslMethod::Tlsv1_2) {
            Ok(t) => t,
            Err(_) => panic!("Could not create a context.")
        };

        Hermes {
            hostname: "".as_bytes(),
            tls: tls
        }
    }

    pub fn hostname(&mut self, host: &'static [u8]) -> &mut Self {
        self.hostname = host;



        self
    }

    pub fn tls_key <P: AsRef<Path>> (&mut self, key: P) -> &mut Self {
        match self.tls.set_private_key_file(key, X509FileType::PEM) {
            Ok(_) => return self,
            Err(e) => panic!("{}", e)
        };
    }

    pub fn tls_chain <P: AsRef<Path>>(&mut self, ca: P) -> &mut Self {
        match self.tls.set_certificate_chain_file(ca, X509FileType::PEM) {
            Ok(_) => return self,
            Err(e) => panic!("{}", e)
        };
    }

    pub fn start(&mut self) -> Result <(), &'static str> {
        match self.tls.check_private_key() {
            Ok(_) => {},
            Err(e) => panic!("{}", e)
        };

        match self.tls.set_ecdh_auto(true) {
            Ok(_) => {},
            Err(e) => panic!("{}", e)
        };

        let workers = ThreadPool::new(num_cpus::get());
    }
}

#[cfg(test)]
mod tests {
    use ::Hermes;
    use std::path::Path;

    #[test]
    fn hermes() {
        let mut server: Hermes = Hermes::new();
        server.hostname("localhost".as_bytes())
              .tls_key(Path::new("material/ca.noenckey.pem"))
              .tls_chain(Path::new("material/ca.cert.pem"))
              .start();
    }
}
