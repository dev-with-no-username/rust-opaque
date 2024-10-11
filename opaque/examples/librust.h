#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * struct needed to return the client or server
 * state allowing remove of redis usage
 */
typedef struct OpaqueWithState {
  const uint8_t *data;
  uintptr_t size_data;
  const uint8_t *state;
  uintptr_t size_state;
} OpaqueWithState;

/**
 * struct needed to return the server setup
 * allowing remove of redis usage
 */
typedef struct OpaqueWithSetup {
  const uint8_t *data;
  uintptr_t size_data;
  const uint8_t *setup;
  uintptr_t size_setup;
} OpaqueWithSetup;

/**
 * struct needed to pass client registration
 * start result as input of second registration step
 */
typedef struct ClientRegStartResult {
  const uint8_t *data;
  uintptr_t size_data;
} ClientRegStartResult;

/**
 * struct needed to pass server private key
 * as input of third registration step
 */
typedef struct ServerRegPrivateKey {
  const uint8_t *data;
  uintptr_t size_data;
} ServerRegPrivateKey;

/**
 * struct needed to pass byte array to C
 * without loosing data and handling 'null
 * bytes in the middle of a string' error
 */
typedef struct Opaque {
  const uint8_t *data;
  uintptr_t size;
} Opaque;

/**
 * struct needed to pass server registration
 * start result as input of third registration step
 */
typedef struct ServerRegStartResult {
  const uint8_t *data;
  uintptr_t size_data;
} ServerRegStartResult;

/**
 * struct needed to pass client registration
 * state as input of third registration step
 */
typedef struct ClientRegState {
  const uint8_t *state;
  uintptr_t size_state;
} ClientRegState;

/**
 * struct needed to pass client login
 * start result as input of second login step
 */
typedef struct ClientLogStartResult {
  const uint8_t *data;
  uintptr_t size_data;
} ClientLogStartResult;

/**
 * struct needed to pass server registration
 * setup as input of second login step
 */
typedef struct ServerSetup {
  const uint8_t *setup;
  uintptr_t size_setup;
} ServerSetup;

/**
 * struct needed to pass server login
 * start result as input of third login step
 */
typedef struct ServerLogStartResult {
  const uint8_t *data;
  uintptr_t size_data;
} ServerLogStartResult;

/**
 * struct needed to pass client login
 * state as input of third login step
 */
typedef struct ClientLogState {
  const uint8_t *state;
  uintptr_t size_state;
} ClientLogState;

/**
 * struct needed to pass server login
 * state as input of last login step
 */
typedef struct ServerLogState {
  const uint8_t *state;
  uintptr_t size_state;
} ServerLogState;

/**
 * function to deallocate Box pointers previously passed to C:
 * MUST be called after used the pointed value in C
 */
void free_memlib(const uint8_t *ptr);

/**
 * first step of opaque registration: client registration start
 * password: password typed by client
 */
struct OpaqueWithState opaque_client_registration_start(const char *password);

/**
 * second step of opaque registration: server registration start
 * registration_request: result of client registration start
 * private_key: hexadecimal value of a 32 bytes private key
 */
struct OpaqueWithSetup opaque_server_registration_start(const char *username,
                                                        struct ClientRegStartResult registration_request,
                                                        struct ServerRegPrivateKey private_key);

/**
 * third step of opaque registration: client registration finish
 * server_registration_start: result of server registration start
 * client_reg_start_state: result of client registration start
 */
struct Opaque opaque_client_registration_finish(const char *password,
                                                struct ServerRegStartResult server_registration_start,
                                                struct ClientRegState client_reg_start_state,
                                                const char *username,
                                                const char *servername);

/**
 * fourth step of opaque registration: server registration finish
 * message: result of client registration finish
 */
struct Opaque opaque_server_registration_finish(struct Opaque message);

/**
 * first step of opaque login: client login start
 * password: password typed by client
 */
struct OpaqueWithState opaque_client_login_start(const char *password);

/**
 * second step of opaque login: server login start
 * password_file: result of server registration finish
 * credential_request: result of client login start
 * serv_setup: result of server registration start
 */
struct OpaqueWithState opaque_server_login_start(const char *username,
                                                 struct Opaque password_file,
                                                 struct ClientLogStartResult credential_request,
                                                 struct ServerSetup serv_setup,
                                                 const char *servername,
                                                 const char *context);

/**
 * third step of opaque login: client login finish
 * login_response: result of server login start
 * client_login_state: result of client login start
 */
struct Opaque opaque_client_login_finish(const char *password,
                                         struct ServerLogStartResult login_response,
                                         struct ClientLogState client_login_state,
                                         const char *username,
                                         const char *servername,
                                         const char *context);

/**
 * fourth step of opaque login: server login finish
 * server_login_state: result of server login start
 */
bool opaque_server_login_finish(struct Opaque credential_finalization,
                                struct ServerLogState server_login_state);
