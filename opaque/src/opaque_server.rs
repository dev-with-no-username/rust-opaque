use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::keypair::KeyPair;
// use opaque_ke::keypair::SecretKey; needed when we want the library generates a valid private key
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginStartParameters, ServerRegistration, ServerSetup, Identifiers,
};
use argon2::Argon2;

// The ciphersuite trait allows to specify the underlying primitives that will
// be used in the OPAQUE protocol
#[allow(dead_code)]
struct DefaultCipherSuite;

#[cfg(feature = "ristretto255")]
impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;

    type Ksf = Argon2<'static>;
}

#[cfg(not(feature = "ristretto255"))]
impl CipherSuite for DefaultCipherSuite {
    // with p256::NistP256 (in every 2 lines below) we obtain a byte array with 1 byte more than opaque_ke::Ristretto255
    // and this will cause errors when interoperating with libopaque, because the latter needs 32 bytes (for example)
    // and obtains 33, returning error
    type OprfCs = p256::NistP256;
    type KeGroup = p256::NistP256;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;

    type Ksf = Argon2<'static>;
}

pub struct ServerResponseWithSetup {
    pub response: Vec<u8>,
    pub setup: Vec<u8>,
}

pub struct ServerResponseWithState {
    pub response: Vec<u8>,
    pub state: Vec<u8>,
}

pub fn server_registration_start(
    username: String,
    registration_request_bytes: &[u8],
    private_key: &[u8],
) -> ServerResponseWithSetup {
    // let priv_key = &[221, 127, 195, 24, 108, 27, 107, 254, 165, 103, 174, 90, 147, 31, 101, 144, 125, 219, 51, 171, 178, 193, 60, 21, 56, 156, 211, 69, 14, 192, 114, 12];
    // let hex_priv_key = "dd7fc3186c1b6bfea567ae5a931f65907ddb33abb2c13c15389cd3450ec0720c";

    let server_setup;
    if private_key.len() > 0 {
        let keypair;

        // check if private key is valid
        match KeyPair::from_private_key_slice(private_key) {
            Ok(val) => {
                keypair = val;
            }
            Err(err) => {
                println!("RUST - LOG: Invalid private key: {}", err);
                return ServerResponseWithSetup{
                    response: vec![],
                    setup: vec![],
                }
            }
        }

        server_setup = ServerSetup::<DefaultCipherSuite>::new_with_key(&mut OsRng, keypair);
    } else {
        server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut OsRng);
    }

    // Per ottenere una private key valida, eseguire i seguenti comandi
    // let ser_setup = ServerSetup::<DefaultCipherSuite>::new(&mut OsRng);
    // let keys = ser_setup.keypair();
    // let pr_key = keys.private();
    // println!("RUST - LOG: Private key bytes: {:?}", pr_key.serialize());
    // println!("RUST - LOG: Hex string: {}", hex::encode(pr_key.serialize()));

    let reg_start_result = ServerRegistration::<DefaultCipherSuite>::start(
        &server_setup,
        RegistrationRequest::deserialize(registration_request_bytes).unwrap(),
        username.as_bytes(),
    )
    .unwrap();

    // serialize server_setup to allow return it as Vec<u8>
    let serv_setup = server_setup.serialize();
    let registration_response_bytes = reg_start_result.message.serialize();

    ServerResponseWithSetup {
        response: registration_response_bytes.as_slice().to_owned(),
        setup: serv_setup.as_slice().to_owned(),
    }
}

pub fn server_registration_finish(message_bytes: &[u8]) -> Vec<u8> {
    let password_file = ServerRegistration::finish(
        RegistrationUpload::<DefaultCipherSuite>::deserialize(message_bytes).unwrap(),
    );
    let pass = password_file.serialize();
    pass.as_slice().to_owned()
}

pub fn server_login_start(
    username: String,
    password_file_bytes: &[u8],
    credential_request_bytes: &[u8],
    serv_setup: &[u8],
    servername: String,
    context: String,
) -> ServerResponseWithState {
    let password_file =
        ServerRegistration::<DefaultCipherSuite>::deserialize(password_file_bytes).unwrap();

    // retrieve server setup to allow start login correctly
    let server_setup = ServerSetup::<DefaultCipherSuite>::deserialize(serv_setup).unwrap();

    let login_start_result = ServerLogin::start(
        &mut OsRng,
        &server_setup,
        Some(password_file),
        CredentialRequest::deserialize(credential_request_bytes).unwrap(),
        username.as_bytes(),
        ServerLoginStartParameters {
            context: Some(context.as_bytes()),
            identifiers: Identifiers {
                client: Some(username.as_bytes()),
                server: Some(servername.as_bytes()),
            },
        }
    )
    .unwrap();

    // serialize login server state, so I can use it later
    let login_start_result_state = login_start_result.state.serialize();
    let credential_response_bytes = login_start_result.message.serialize();

    ServerResponseWithState {
        response: credential_response_bytes.as_slice().to_owned(),
        state: login_start_result_state.as_slice().to_owned(),
    }
}

pub fn server_login_finish(
    credential_finalization_bytes: &[u8],
    login_start_result: &[u8],
) -> bool {
    // retrieve server login state to allow finish procedure correctly
    let state = ServerLogin::<DefaultCipherSuite>::deserialize(login_start_result).unwrap();

    let login_finish_result = state
        .finish(CredentialFinalization::deserialize(credential_finalization_bytes).unwrap());

    // check if login successful
    match login_finish_result {
        Ok(_) => {
            return true
        }
        Err(err) => {
            println!("RUST - LOG: Server detected login failure {}", err);
            return false
        }
    }
}
