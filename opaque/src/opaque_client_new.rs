use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
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
    type OprfCs = p256::NistP256;
    type KeGroup = p256::NistP256;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;

    type Ksf = opaque_ke::ksf::Identity;
}

pub struct ClientResponseWithState {
    pub response: Vec<u8>,
    pub state: Vec<u8>,
}

pub struct ClientResponseWithKey {
    pub response: Vec<u8>,
    pub session_key: Vec<u8>,
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
) -> Vec<u8> {
    // retrieve client registration state to allow finish procedure correctly
    let client_state = ClientRegistration::<DefaultCipherSuite>::deserialize(reg_start_result);
    if client_state.is_err() {
        println!("Client registration start error while deserialize client start result");
        return vec![]
    }
    let state = client_state.unwrap();

    let reg_response = RegistrationResponse::deserialize(registration_response_bytes);
    if reg_response.is_err() {
        println!("Client registration start error while deserialize server registration response");
        return vec![]
    }
    let registration_response = reg_response.unwrap();

    let finish_reg = state
        .finish(
            &mut OsRng,
            password.as_bytes(),
            registration_response,
            ClientRegistrationFinishParameters::default(),
        );
    if finish_reg.is_err() {
        println!("Client registration start error while deserialize server registration response");
        return vec![]
    }
    let finish_reg_result = finish_reg.unwrap();

    let message_bytes = finish_reg_result.message.serialize();
    message_bytes.as_slice().to_owned()
}

pub fn client_login_start(password: String) -> ClientResponseWithState {
    let login_start =
        ClientLogin::<DefaultCipherSuite>::start(&mut OsRng, password.as_bytes());

    if login_start.is_err() {
        println!("Client login start error");
        return ClientResponseWithState{
            response: vec![],
            state: vec![],
        }
    }
    let login_start_result = login_start.unwrap();

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
) -> ClientResponseWithKey {
    // retrieve client login state to allow finish procedure correctly
    let client_state = ClientLogin::<DefaultCipherSuite>::deserialize(login_start_result);
    if client_state.is_err() {
        println!("Client login finish error while deserialize client login start result");
        return ClientResponseWithKey{
            response: vec![],
            session_key: vec![],
        }
    }
    let state = client_state.unwrap();

    let cred_response = CredentialResponse::deserialize(credential_response_bytes);
    if cred_response.is_err() {
        println!("Client login finish error while deserialize server login start response");
        return ClientResponseWithKey{
            response: vec![],
            session_key: vec![],
        }
    }
    let credential_response = cred_response.unwrap();

    let result = state.finish(
        password.as_bytes(),
        credential_response,
        ClientLoginFinishParameters::default(),
    );
    if result.is_err() {
        println!("Client detected login failure");
        return ClientResponseWithKey{
            response: vec![],
            session_key: vec![],
        }
    }
    let login_finish_result = result.unwrap();
    let credential_finalization_bytes = login_finish_result.message.serialize();

    ClientResponseWithKey {
        response: credential_finalization_bytes.as_slice().to_owned(),
        session_key: login_finish_result.session_key.as_slice().to_owned(),
    }
}
