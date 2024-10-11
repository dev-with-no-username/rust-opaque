use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginStartParameters, ServerRegistration, ServerSetup,
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
) -> ServerResponseWithSetup {
    let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut OsRng);

    let reg_request = RegistrationRequest::deserialize(registration_request_bytes);
    if reg_request.is_err() {
        println!("Server registration start error while deserialize client registration request");
        return ServerResponseWithSetup{
            response: vec![],
            setup: vec![],
        }
    }
    let registration_request = reg_request.unwrap();

    let reg_start = ServerRegistration::<DefaultCipherSuite>::start(
        &server_setup,
        registration_request,
        username.as_bytes(),
    );
    if reg_start.is_err() {
        println!("Server registration start error while generating server response");
        return ServerResponseWithSetup{
            response: vec![],
            setup: vec![],
        }
    }
    let reg_start_result = reg_start.unwrap();

    // serialize server_setup to allow return it as Vec<u8>
    let serv_setup = server_setup.serialize();
    let registration_response_bytes = reg_start_result.message.serialize();

    ServerResponseWithSetup {
        response: registration_response_bytes.as_slice().to_owned(),
        setup: serv_setup.as_slice().to_owned(),
    }
}

pub fn server_registration_finish(message_bytes: &[u8]) -> Vec<u8> {
    let msg = RegistrationUpload::<DefaultCipherSuite>::deserialize(message_bytes);
    if msg.is_err() {
        println!("Server registration finish error");
        return vec![]
    }
    let message = msg.unwrap();

    let password_file = ServerRegistration::finish(
        message,
    );
    let pass = password_file.serialize();
    pass.as_slice().to_owned()
}

pub fn server_login_start(
    username: String,
    password_file_bytes: &[u8],
    credential_request_bytes: &[u8],
    serv_setup: &[u8],
) -> ServerResponseWithState {
    let pass_file = ServerRegistration::<DefaultCipherSuite>::deserialize(password_file_bytes);
    if pass_file.is_err() {
        println!("Server login start error while deserialize data");
        return ServerResponseWithState{
            response: vec![],
            state: vec![],
        }
    }
    let password_file = pass_file.unwrap();

    // retrieve server setup to allow start login correctly
    let setup = ServerSetup::<DefaultCipherSuite>::deserialize(serv_setup);
    if setup.is_err() {
        println!("Server registration finish error while deserialize server setup");
        return ServerResponseWithState{
            response: vec![],
            state: vec![],
        }
    }
    let server_setup = setup.unwrap();

    let cred_req = CredentialRequest::deserialize(credential_request_bytes);
    if cred_req.is_err() {
        println!("Server registration finish error while deserialize credential request");
        return ServerResponseWithState{
            response: vec![],
            state: vec![],
        }
    }
    let credential_request = cred_req.unwrap();

    let login_start = ServerLogin::start(
        &mut OsRng,
        &server_setup,
        Some(password_file),
        credential_request,
        username.as_bytes(),
        ServerLoginStartParameters::default(),
    );
    if login_start.is_err() {
        println!("Server login start error while generating server login response");
        return ServerResponseWithState{
            response: vec![],
            state: vec![],
        }
    }
    let login_start_result = login_start.unwrap();

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
    client_session_key: &[u8],
    login_start_result: &[u8],
) -> bool {
    // retrieve server login state to allow finish procedure correctly
    let setup = ServerLogin::<DefaultCipherSuite>::deserialize(login_start_result);
    if setup.is_err() {
        println!("Server login finish error while deserialize server login start result");
        return false
    }
    let state = setup.unwrap();

    let cred_finalization = CredentialFinalization::deserialize(credential_finalization_bytes);
    if cred_finalization.is_err() {
        println!("Server login finish error while deserialize client credentials");
        return false
    }
    let credential_finalization = cred_finalization.unwrap();

    let login_finish = state.finish(credential_finalization);
    if login_finish.is_err() {
        println!("Server login finish error while generating server session key");
        return false
    }
    let login_finish_result = login_finish.unwrap();

    // check if login successfull
    login_finish_result.session_key.as_slice() == client_session_key
}
