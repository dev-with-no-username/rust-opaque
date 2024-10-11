use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse, Identifiers,
};

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

    type Ksf = opaque_ke::ksf::Identity;
}

pub struct ClientResponseWithState {
    pub response: Vec<u8>,
    pub state: Vec<u8>,
}

pub struct ClientResponse {
    pub response: Vec<u8>,
}

// init changes
pub fn client_registration_start(password: String) -> ClientResponseWithState {
    let reg_start_result =
        ClientRegistration::<DefaultCipherSuite>::start(&mut OsRng, password.as_bytes()).unwrap();

    // serialize registration state value, so I can use it later
    let reg_start_result_state = reg_start_result.state.serialize();
    let registration_request_bytes = reg_start_result.message.serialize();

    ClientResponseWithState {
        response: registration_request_bytes.as_slice().to_owned(),
        state: reg_start_result_state.as_slice().to_owned(),
    }
}

pub fn client_registration_finish(
    password: String,
    registration_response_bytes: &[u8],
    reg_start_result: &[u8],
    username: String,
    servername: String,
) -> Vec<u8> {
    // retrieve client registration state to allow finish procedure correctly
    let state =
        ClientRegistration::<DefaultCipherSuite>::deserialize(reg_start_result)
            .unwrap();

    let finish_reg_result = state
        .finish(
            &mut OsRng,
            password.as_bytes(),
            RegistrationResponse::deserialize(registration_response_bytes).unwrap(),
            ClientRegistrationFinishParameters::new(
                Identifiers {
                    client: Some(username.as_bytes()),
                    server: Some(servername.as_bytes()),
                },
                None,
            ),
        )
        .unwrap();

    let message_bytes = finish_reg_result.message.serialize();
    message_bytes.as_slice().to_owned()
}

pub fn client_login_start(password: String) -> ClientResponseWithState {
    let login_start_result =
        ClientLogin::<DefaultCipherSuite>::start(&mut OsRng, password.as_bytes()).unwrap();

    // serialize login state value, so I can use it later
    let login_start_result_state = login_start_result.state.serialize();
    let credential_request_bytes = login_start_result.message.serialize();

    ClientResponseWithState {
        response: credential_request_bytes.as_slice().to_owned(),
        state: login_start_result_state.as_slice().to_owned(),
    }
}

pub fn client_login_finish(
    password: String,
    credential_response_bytes: &[u8],
    login_start_result: &[u8],
    username: String,
    servername: String,
    context: String,
) -> ClientResponse {
    // retrieve client login state to allow finish procedure correctly
    let state = ClientLogin::<DefaultCipherSuite>::deserialize(login_start_result).unwrap();

    let result = state.finish(
        password.as_bytes(),
        CredentialResponse::deserialize(credential_response_bytes).unwrap(),
        ClientLoginFinishParameters::new(
            Some(context.as_bytes()),
            Identifiers {
                client: Some(username.as_bytes()),
                server: Some(servername.as_bytes()),
            },
            None,
        ),
    );

    // check if login successful
    match result {
        Ok(_) => {}
        Err(err) => {
            println!("RUST - LOG: Client detected login failure: {}", err);
            
            println!("TIPO ERRORE {}", type_of(err));
            return ClientResponse{
                response: vec![],
            }
        }
    }
    let login_finish_result = result.unwrap();
    let credential_finalization_bytes = login_finish_result.message.serialize();

    ClientResponse {
        response: credential_finalization_bytes.as_slice().to_owned(),
    }
}

use std::any::type_name;

fn type_of<T>(_: T) -> &'static str {
    type_name::<T>()
}