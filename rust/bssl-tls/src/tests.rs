// Copyright 2026 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::mem::MaybeUninit;

use crate::{
    ReceiveBuffer,
    connection::{
        Client,
        Server,
        TlsConnection, //
    },
    context::TlsContextBuilder,
    credentials::{
        Certificate,
        TlsCredentialBuilder, //
    },
    errors::Error,
    io::IoStatus, //
};

use bssl_x509::{
    certificates::X509Certificate,
    keys::PrivateKey,
    params::Trust,
    store::X509StoreBuilder, //
};

const CA: &[u8] = include_bytes!("../../test-data/BoringSSLCATest.crt");
const RSA_SERVER_CERT: &[u8] = include_bytes!("../../test-data/BoringSSLServerTest-RSA.crt");
const RSA_SERVER_KEY: &[u8] = include_bytes!("../../test-data/BoringSSLServerTest-RSA.key");

mod datagram;
mod handshake;
mod transport;

/// Dumb server-client pair that does no certificate verification.
fn dumb_server_client() -> Result<(TlsConnection<Server>, TlsConnection<Client>), Error> {
    let ca = Certificate::parse_one_from_pem(CA, None)?;
    let server_cert = Certificate::parse_one_from_pem(RSA_SERVER_CERT, None)?;
    let server_key = PrivateKey::from_pem(RSA_SERVER_KEY, || unreachable!())?;

    let mut server_ctx_builder = TlsContextBuilder::new_tls();
    let server_cred = {
        let mut builder = TlsCredentialBuilder::new();
        builder
            .with_certificate_chain(&[server_cert, ca])?
            .with_private_key(server_key)?;
        builder.build()
    };
    server_ctx_builder.with_credential(server_cred.unwrap())?;
    let server_ctx = server_ctx_builder.build();
    let server_conn = server_ctx.new_server_connection(None)?.build();

    let mut client_ctx_builder = TlsContextBuilder::new_tls();
    let mut cert_store = X509StoreBuilder::new();
    cert_store
        .set_trust(Trust::SslServer)?
        .add_cert(X509Certificate::parse_one_from_pem(CA)?)?;
    let cert_store = cert_store.build();
    client_ctx_builder.with_certificate_store(&cert_store);
    let client_ctx = client_ctx_builder.build();
    let client_conn = client_ctx.new_client_connection(None)?.build();

    Ok((server_conn, client_conn))
}

fn sync_ping_pong<
    M: crate::connection::methods::HasTlsConnectionMethod
        + crate::context::SupportedMode
        + crate::context::HasBasicIo
        + 'static,
>(
    mut server_conn: TlsConnection<Server, M>,
    mut client_conn: TlsConnection<Client, M>,
) -> Result<(), Error> {
    let thread = std::thread::spawn(move || {
        server_conn.in_handshake().unwrap().accept()?;
        assert!(!server_conn.is_in_handshake());
        // TODO: switch to `From` impls when Rust compiler is bumped to 1.95.0.
        let mut message = [MaybeUninit::uninit(); 21];
        let mut message = ReceiveBuffer::new_uninit(&mut message);
        assert!(matches!(
            server_conn.sync_read(&mut message)?,
            IoStatus::Ok(21)
        ));
        assert_eq!(*message, *b"BoringSSL is awesome!");
        server_conn.sync_write(b"Oh yeah definitely!")?;
        server_conn.established().unwrap().sync_shutdown()?;
        // Second shutdown poll.
        server_conn.established().unwrap().sync_shutdown()?;
        Ok::<_, Error>(())
    });

    client_conn.in_handshake().unwrap().connect()?;
    assert!(!client_conn.is_in_handshake());
    client_conn.sync_write(b"BoringSSL is awesome!")?;
    let mut message = [MaybeUninit::uninit(); 19];
    let mut message = ReceiveBuffer::new_uninit(&mut message);
    assert!(matches!(
        client_conn.sync_read(&mut message)?,
        IoStatus::Ok(19)
    ));
    assert_eq!(*message, *b"Oh yeah definitely!");
    client_conn.established().unwrap().sync_shutdown()?;
    thread.join().unwrap()?;

    Ok(())
}

#[cfg(feature = "tokio_io")]
async fn async_ping_pong<
    M: crate::connection::methods::HasTlsConnectionMethod
        + crate::context::SupportedMode
        + crate::context::HasBasicIo
        + 'static,
>(
    mut server_conn: TlsConnection<Server, M>,
    mut client_conn: TlsConnection<Client, M>,
) -> Result<(), Error> {
    use std::time::Duration;

    let task = tokio::spawn(async move {
        server_conn
            .in_handshake()
            .unwrap()
            .async_handshake()
            .await?;

        let mut message = [0; 21];
        assert!(matches!(
            server_conn.as_pin_mut().async_read(&mut message).await?,
            IoStatus::Ok(21)
        ));
        assert_eq!(message, *b"BoringSSL is awesome!");
        tokio::time::sleep(Duration::from_secs(2)).await;
        server_conn
            .as_pin_mut()
            .async_write(b"Oh yeah definitely!")
            .await?;
        server_conn.as_pin_mut().async_shutdown().await?;
        Ok::<_, Error>(())
    });

    client_conn
        .in_handshake()
        .unwrap()
        .async_handshake()
        .await?;
    client_conn
        .as_pin_mut()
        .async_write(b"BoringSSL is awesome!")
        .await?;
    let mut message = [0; 19];
    assert!(matches!(
        client_conn.as_pin_mut().async_read(&mut message).await?,
        IoStatus::Ok(19)
    ));
    assert_eq!(message, *b"Oh yeah definitely!");
    assert!(matches!(
        client_conn.as_pin_mut().async_shutdown().await,
        Ok(_) | Err(Error::Io(crate::errors::IoError::EndOfStream))
    ));
    task.await.unwrap()?;
    Ok(())
}
