use lazy_static::lazy_static;
use std::env;
use std::ffi::CStr;
use std::os::raw::c_char;

use opaque_client::{
    client_login_finish, client_login_start, client_registration_finish, client_registration_start,
};
use opaque_server::{
    server_login_finish, server_login_start, server_registration_finish, server_registration_start,
};

mod opaque_client;
mod opaque_server;

// const RUST_LOG: &str = "RUST::";

// evaluate a const at runtime, even if Rust evaluates const at buildtime
lazy_static! {
    static ref ENABLE_LOGS: bool = match env::var("ENABLE_LOGS") {
        Ok(val) => val.parse::<bool>().unwrap(),
        Err(_) => false,
    };
}

/// struct needed to pass byte array to C
/// without loosing data and handling 'null
/// bytes in the middle of a string' error
#[repr(C)]
pub struct Opaque {
    data: *const u8,
    size: usize,
}

/// struct needed to return the client or server
/// state allowing remove of redis usage
#[repr(C)]
pub struct OpaqueWithState {
    data: *const u8,
    size_data: usize,
    state: *const u8,
    size_state: usize,
}

/// struct needed to return the server setup
/// allowing remove of redis usage
#[repr(C)]
pub struct OpaqueWithSetup {
    data: *const u8,
    size_data: usize,
    setup: *const u8,
    size_setup: usize,
}

/// struct needed to pass client registration
/// start result as input of second registration step
#[repr(C)]
pub struct ClientRegStartResult {
    data: *const u8,
    size_data: usize,
}

/// struct needed to pass client registration
/// state as input of third registration step
#[repr(C)]
pub struct ClientRegState {
    state: *const u8,
    size_state: usize,
}

/// struct needed to pass client login
/// start result as input of second login step
#[repr(C)]
pub struct ClientLogStartResult {
    data: *const u8,
    size_data: usize,
}

/// struct needed to pass client login
/// state as input of third login step
#[repr(C)]
pub struct ClientLogState {
    state: *const u8,
    size_state: usize,
}

/// struct needed to pass server private key
/// as input of third registration step
#[repr(C)]
pub struct ServerRegPrivateKey {
    data: *const u8,
    size_data: usize,
}

/// struct needed to pass server registration
/// start result as input of third registration step
#[repr(C)]
pub struct ServerRegStartResult {
    data: *const u8,
    size_data: usize,
}

/// struct needed to pass server registration
/// setup as input of second login step
#[repr(C)]
pub struct ServerSetup {
    setup: *const u8,
    size_setup: usize,
}

/// struct needed to pass server login
/// start result as input of third login step
#[repr(C)]
pub struct ServerLogStartResult {
    data: *const u8,
    size_data: usize,
}

/// struct needed to pass server login
/// state as input of last login step
#[repr(C)]
pub struct ServerLogState {
    state: *const u8,
    size_state: usize,
}

/// function to deallocate Box pointers previously passed to C:
/// MUST be called after used the pointed value in C
#[no_mangle]
pub extern "C" fn free_memlib(ptr: *const u8) {
    unsafe {
        let _ = Box::from_raw(ptr as *mut u8);
    }
}

/// first step of opaque registration: client registration start
/// password: password typed by client
#[no_mangle]
pub extern "C" fn opaque_client_registration_start(password: *const c_char) -> OpaqueWithState {
    let password_client;
    unsafe {
        password_client = CStr::from_ptr(password).to_str().unwrap();
    }
    let reg = client_registration_start(password_client.to_string());
    // println!("CLIENT REG START {:?}", reg);

    // The Box pointer in Rust is used to allocate memory on the heap and store data in it.
    // When the Box is created, ownership of the memory is transferred to the Box, which becomes
    // responsible for managing the memory.
    // When the Box pointer is passed to C code, ownership of the memory is also passed along with it.
    // This means that the C code now becomes responsible for managing the memory allocated by the Box.
    let size_d = reg.response.len();
    let data_ptr = Box::into_raw(reg.response.into_boxed_slice()) as *const u8;
    let size_s = reg.state.len();
    let state_ptr = Box::into_raw(reg.state.into_boxed_slice()) as *const u8;
    OpaqueWithState {
        data: data_ptr,
        size_data: size_d,
        state: state_ptr,
        size_state: size_s,
    }
}

/// second step of opaque registration: server registration start
/// registration_request: result of client registration start
/// private_key: hexadecimal value of a 32 bytes private key
#[no_mangle]
pub extern "C" fn opaque_server_registration_start(
    username: *const c_char,
    registration_request: ClientRegStartResult,
    private_key: ServerRegPrivateKey,
) -> OpaqueWithSetup {
    let username_client;
    let request;
    let priv_key;
    unsafe {
        username_client = CStr::from_ptr(username).to_str().unwrap();
        request =
            std::slice::from_raw_parts(registration_request.data, registration_request.size_data);
        priv_key = std::slice::from_raw_parts(private_key.data, private_key.size_data);
    }
    // println!("VEC SERVER REG START {:?}, {:?}", private_key.data, priv_key);

    let reg = server_registration_start(
        username_client.to_string(), 
        request,
        priv_key,
    );
    // println!("SERVER REG START {:?}", reg);

    let size_d = reg.response.len();
    let data_ptr = Box::into_raw(reg.response.into_boxed_slice()) as *const u8;
    let size_s = reg.setup.len();
    let setup_ptr = Box::into_raw(reg.setup.into_boxed_slice()) as *const u8;
    OpaqueWithSetup {
        data: data_ptr,
        size_data: size_d,
        setup: setup_ptr,
        size_setup: size_s,
    }
}

/// third step of opaque registration: client registration finish
/// server_registration_start: result of server registration start
/// client_reg_start_state: result of client registration start
#[no_mangle]
pub extern "C" fn opaque_client_registration_finish(
    password: *const c_char,
    server_registration_start: ServerRegStartResult,
    client_reg_start_state: ClientRegState,
    username: *const c_char,
    servername: *const c_char,
) -> Opaque {
    let password_client;
    let reg_response;
    let client_state;
    let user;
    let server;
    unsafe {
        password_client = CStr::from_ptr(password).to_str().unwrap();
        reg_response =
            std::slice::from_raw_parts(
                server_registration_start.data, 
                server_registration_start.size_data,
            );
        client_state = std::slice::from_raw_parts(
            client_reg_start_state.state,
            client_reg_start_state.size_state,
        );
        user = CStr::from_ptr(username).to_str().unwrap();
        server = CStr::from_ptr(servername).to_str().unwrap();
    }
    // println!("VEC CLIENT REG FINISH {:?}", reg_response);

    let reg = client_registration_finish(
        password_client.to_string(), 
        reg_response, 
        client_state,
        user.to_string(),
        server.to_string(),
    );
    // println!("CLIENT REG FINISH {:?}", reg);

    let s = reg.len();
    let ptr = Box::into_raw(reg.into_boxed_slice()) as *const u8;
    Opaque { data: ptr, size: s }
}

/// fourth step of opaque registration: server registration finish
/// message: result of client registration finish
#[no_mangle]
pub extern "C" fn opaque_server_registration_finish(message: Opaque) -> Opaque {
    let message_client;
    unsafe {
        message_client = std::slice::from_raw_parts(message.data, message.size);
    }
    // println!("VEC SERVER REG FINISH {:?}", message_client);

    let reg = server_registration_finish(message_client);
    // println!("SERVER REG FINISH {:?}", reg);

    let s = reg.len();
    let ptr = Box::into_raw(reg.into_boxed_slice()) as *const u8;
    Opaque { data: ptr, size: s }
}

/// first step of opaque login: client login start
/// password: password typed by client
#[no_mangle]
pub extern "C" fn opaque_client_login_start(password: *const c_char) -> OpaqueWithState {
    let password_client;
    unsafe {
        password_client = CStr::from_ptr(password).to_str().unwrap();
    }
    let login_start = client_login_start(password_client.to_string());
    // println!("CLIENT LOGIN START {:?}", login_start);

    let size_d = login_start.response.len();
    let data_ptr = Box::into_raw(login_start.response.into_boxed_slice()) as *const u8;
    let size_s = login_start.state.len();
    let state_ptr = Box::into_raw(login_start.state.into_boxed_slice()) as *const u8;
    OpaqueWithState {
        data: data_ptr,
        size_data: size_d,
        state: state_ptr,
        size_state: size_s,
    }
}

/// second step of opaque login: server login start
/// password_file: result of server registration finish
/// credential_request: result of client login start
/// serv_setup: result of server registration start
#[no_mangle]
pub extern "C" fn opaque_server_login_start(
    username: *const c_char,
    password_file: Opaque,
    credential_request: ClientLogStartResult,
    serv_setup: ServerSetup,
    servername: *const c_char,
    context: *const c_char,
) -> OpaqueWithState {
    let username_client;
    let password_client;
    let credential;
    let server_setup;
    let server;
    let ctx;
    unsafe {
        username_client = CStr::from_ptr(username).to_str().unwrap();
        password_client = std::slice::from_raw_parts(password_file.data, password_file.size);
        credential =
            std::slice::from_raw_parts(credential_request.data, credential_request.size_data);
        server_setup =
            std::slice::from_raw_parts(serv_setup.setup, serv_setup.size_setup);
        server = CStr::from_ptr(servername).to_str().unwrap();
        ctx = CStr::from_ptr(context).to_str().unwrap();
    }

    let login_start = server_login_start(
        username_client.to_string(),
        password_client,
        credential,
        server_setup,
        server.to_string(),
        ctx.to_string(),
    );
    // println!("SERVER LOGIN START {:?}", login_start);

    let size_d = login_start.response.len();
    let data_ptr = Box::into_raw(login_start.response.into_boxed_slice()) as *const u8;
    let size_s = login_start.state.len();
    let state_ptr = Box::into_raw(login_start.state.into_boxed_slice()) as *const u8;
    OpaqueWithState {
        data: data_ptr,
        size_data: size_d,
        state: state_ptr,
        size_state: size_s,
    }
}

/// third step of opaque login: client login finish
/// login_response: result of server login start
/// client_login_state: result of client login start
#[no_mangle]
pub extern "C" fn opaque_client_login_finish(
    password: *const c_char,
    login_response: ServerLogStartResult,
    client_login_state: ClientLogState,
    username: *const c_char,
    servername: *const c_char,
    context: *const c_char,
) -> Opaque {
    let password_client;
    let log_response;
    let client_state;
    let user;
    let server;
    let ctx;
    unsafe {
        password_client = CStr::from_ptr(password).to_str().unwrap();
        log_response = std::slice::from_raw_parts(login_response.data, login_response.size_data);
        client_state = std::slice::from_raw_parts(client_login_state.state, client_login_state.size_state);
        user = CStr::from_ptr(username).to_str().unwrap();
        server = CStr::from_ptr(servername).to_str().unwrap();
        ctx = CStr::from_ptr(context).to_str().unwrap();
    }
    let login_finish = client_login_finish(
        password_client.to_string(), 
        log_response, 
        client_state,
        user.to_string(),
        server.to_string(),
        ctx.to_string(),
    );
    // println!("CLIENT LOGIN FINISH {:?}", login_finish);

    let size_d = login_finish.response.len();
    let data_ptr = Box::into_raw(login_finish.response.into_boxed_slice()) as *const u8;
    Opaque {
        data: data_ptr,
        size: size_d,
    }
}

/// fourth step of opaque login: server login finish
/// server_login_state: result of server login start
#[no_mangle]
pub extern "C" fn opaque_server_login_finish(
    credential_finalization: Opaque,
    server_login_state: ServerLogState,
) -> bool {
    let credential;
    let server_state;
    unsafe {
        credential =
            std::slice::from_raw_parts(credential_finalization.data, credential_finalization.size);
        server_state = std::slice::from_raw_parts(server_login_state.state, server_login_state.size_state);
    }
    // println!("CLIENT LOGIN FINISH RESULT {:?}", credential);

    server_login_finish(
        credential,
        server_state
    )
}
