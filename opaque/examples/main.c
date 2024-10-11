#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "librust.h"
#include "print.c"

int happyPath() {
    const char* c_prefix = "C - LOG: ";
    const char* servername = "servername";
    const char* context = "context";
    const uint8_t privKey[] = {221, 127, 195, 24, 108, 27, 107, 254, 165, 103, 174, 90, 147, 31, 101, 144, 125, 219, 51, 171, 178, 193, 60, 21, 56, 156, 211, 69, 14, 192, 114, 12};

    ServerRegPrivateKey privateKey = {
        .data = privKey,
        .size_data = 32,
    };

    printf("\n--------------------------------------------------\n");
    printf("%s HAPPYPATH TEST\n", c_prefix);

    /////////////////////////////////////////////////
    ////////////// REGISTRATION STEPS //////////////
    ///////////////////////////////////////////////
    
    OpaqueWithState registration_client_start = opaque_client_registration_start("ciao");
    printf("%s Client reg start %s \n", c_prefix, registration_client_start.data);

    // prepare input structs for second registration step
    ClientRegStartResult client_reg_start_result = {
        .data = registration_client_start.data,
        .size_data = registration_client_start.size_data
    };
    OpaqueWithSetup registration_server_start = opaque_server_registration_start(
        "pippo", 
        client_reg_start_result,
        privateKey
    );
    printf("%s Server reg start %s \n", c_prefix, registration_server_start.data);

    // prepare input structs for third registration step
    ServerRegStartResult server_reg_start_result = { 
        .data = registration_server_start.data, 
        .size_data = registration_server_start.size_data 
    };
    ClientRegState client_reg_state = { 
        .state = registration_client_start.state, 
        .size_state = registration_client_start.size_state 
    };
    Opaque registration_client_finish = opaque_client_registration_finish(
        "ciao", 
        server_reg_start_result, 
        client_reg_state,
        "pippo",
        "servername"
    );
    printf("%s Client reg finish %s \n", c_prefix, registration_client_finish.data);

    Opaque registration_server_finish = opaque_server_registration_finish(registration_client_finish);
    printf("%s Server reg finish %s \n", c_prefix, registration_server_finish.data);

    //////////////////////////////////////////
    ////////////// LOGIN STEPS //////////////
    ////////////////////////////////////////

    OpaqueWithState login_client_start = opaque_client_login_start("ciao");
    printf("%s Client login start %s \n", c_prefix, login_client_start.data);

    // prepare input structs for second login step
    ClientLogStartResult client_log_start_result = {
        .data = login_client_start.data,
        .size_data = login_client_start.size_data
    };
    ServerSetup server_setup = { 
        .setup = registration_server_start.setup, 
        .size_setup = registration_server_start.size_setup 
    };
    OpaqueWithState login_server_start = opaque_server_login_start(
        "pippo", 
        registration_server_finish, 
        client_log_start_result, 
        server_setup,
        servername,
        context
    );
    printf("%s Server login start %s \n", c_prefix, login_server_start.data);

    // prepare input structs for third login step
    ServerLogStartResult server_log_start_result = {
        .data = login_server_start.data,
        .size_data = login_server_start.size_data
    };
    ClientLogState client_log_state = { 
        .state = login_client_start.state, 
        .size_state = login_client_start.size_state 
    };
    Opaque login_client_finish = opaque_client_login_finish(
        "ciao", 
        server_log_start_result, 
        client_log_state,
        "pippo",
        servername,
        context
    );
    printf("%s Client login finish %s \n", c_prefix, login_client_finish.data);

    // prepare struct for last login step
    ServerLogState server_log_state = { 
        .state = login_server_start.state, 
        .size_state = login_server_start.size_state 
    };
    bool check = opaque_server_login_finish(login_client_finish, server_log_state);
    if (check == true) {
        printf("%s HAPPYPATH LOGIN SUCCESSFUL \n", c_prefix);
    } else {
        printf("%s HAPPYPATH LOGIN FAILED \n", c_prefix);
    }

    free_memlib(registration_client_start.data);
    free_memlib(registration_client_start.state);
    free_memlib(registration_server_start.data);
    free_memlib(registration_server_start.setup);
    free_memlib(registration_client_finish.data);
    free_memlib(registration_server_finish.data);
    free_memlib(login_client_start.data);
    free_memlib(login_client_start.state);
    free_memlib(login_server_start.data);
    free_memlib(login_server_start.state);
    free_memlib(login_client_finish.data);

    return 0;
}

// to test an error path, is sufficient to use below 'incorrect' variables
int errorPath() {
    const char* c_prefix = "C - LOG: ";
    const char* correct_password = "ciao";
    const char* incorrect_password = "ciaoSbagliato";
    const char* correct_username = "pippo";
    const char* incorrect_username = "pippoSbagliato";
    const char* servername = "server";
    const char* context = "context";
    const uint8_t privKey[] = {221, 127, 195, 24, 108, 27, 107, 254, 165, 103, 174, 90, 147, 31, 101, 144, 125, 219, 51, 171, 178, 193, 60, 21, 56, 156, 211, 69, 14, 192, 114, 12};

    ServerRegPrivateKey privateKey = {
        .data = privKey,
        .size_data = 32,
    };

    printf("\n--------------------------------------------------\n");
    printf("%s ERRORPATH TEST\n", c_prefix);

    /////////////////////////////////////////////////
    ////////////// REGISTRATION STEPS //////////////
    ///////////////////////////////////////////////
    
    OpaqueWithState registration_client_start = opaque_client_registration_start(correct_password);
    printOpaqueWithState(&registration_client_start, "C - LOG: Client reg start");

    // prepare input structs for second registration step
    ClientRegStartResult client_reg_start_result = {
        .data = registration_client_start.data,
        .size_data = registration_client_start.size_data
    };
    OpaqueWithSetup registration_server_start = opaque_server_registration_start(
        correct_username, 
        client_reg_start_result,
        privateKey
    );
    printOpaqueWithSetup(&registration_server_start, "C - LOG: Server reg start");

    if (registration_server_start.size_data == 0 && registration_server_start.size_setup == 0) {
        printf("C - LOG: Server reg start ERROR \n");
        free_memlib(registration_client_start.data);
        free_memlib(registration_client_start.state);
        return 1;
    }

    // prepare input structs for third registration step
    ServerRegStartResult server_reg_start_result = { 
        .data = registration_server_start.data, 
        .size_data = registration_server_start.size_data 
    };
    ClientRegState client_reg_state = { 
        .state = registration_client_start.state, 
        .size_state = registration_client_start.size_state 
    };
    Opaque registration_client_finish = opaque_client_registration_finish(
        correct_password, 
        server_reg_start_result, 
        client_reg_state,
        correct_username,
        servername
    );
    printOpaque(&registration_client_finish, "C - LOG: Client reg finish");

    if (registration_client_finish.data == 0 && registration_client_finish.size == 0) {
        printf("C - LOG: Client reg finish ERROR \n");
        free_memlib(registration_client_start.data);
        free_memlib(registration_client_start.state);
        free_memlib(registration_server_start.data);
        free_memlib(registration_server_start.setup);
        return 1;
    }

    Opaque registration_server_finish = opaque_server_registration_finish(registration_client_finish);
    printOpaque(&registration_server_finish, "C - LOG: Server reg finish");

    if (registration_server_finish.data == 0 && registration_server_finish.size == 0) {
        printf("C - LOG: Server reg finish ERROR \n");
        free_memlib(registration_client_start.data);
        free_memlib(registration_client_start.state);
        free_memlib(registration_server_start.data);
        free_memlib(registration_server_start.setup);
        free_memlib(registration_client_finish.data);
        free_memlib(registration_server_finish.data);
        return 1;
    }

    //////////////////////////////////////////
    ////////////// LOGIN STEPS //////////////
    ////////////////////////////////////////

    OpaqueWithState login_client_start = opaque_client_login_start(incorrect_password);
    printOpaqueWithState(&login_client_start, "C - LOG: Client login start");

    if (login_client_start.size_data == 0 && login_client_start.size_state == 0) {
        printf("C - LOG: Client login start ERROR \n");
        free_memlib(registration_client_start.data);
        free_memlib(registration_client_start.state);
        free_memlib(registration_server_start.data);
        free_memlib(registration_server_start.setup);
        free_memlib(registration_client_finish.data);
        free_memlib(registration_server_finish.data);
        free_memlib(login_client_start.data);
        free_memlib(login_client_start.state);
        return 1;
    }

    // prepare input structs for second login step
    ClientLogStartResult client_log_start_result = {
        .data = login_client_start.data,
        .size_data = login_client_start.size_data
    };
    ServerSetup server_setup = { 
        .setup = registration_server_start.setup, 
        .size_setup = registration_server_start.size_setup 
    };
    OpaqueWithState login_server_start = opaque_server_login_start(
        correct_username, 
        registration_server_finish, 
        client_log_start_result, 
        server_setup,
        servername,
        context
    );
    printOpaqueWithState(&login_server_start, "C - LOG: Server login start");

    if (login_server_start.size_data == 0 && login_server_start.size_state == 0) {
        printf("C - LOG: Server login start ERROR \n");
        free_memlib(registration_client_start.data);
        free_memlib(registration_client_start.state);
        free_memlib(registration_server_start.data);
        free_memlib(registration_server_start.setup);
        free_memlib(registration_client_finish.data);
        free_memlib(registration_server_finish.data);
        free_memlib(login_client_start.data);
        free_memlib(login_client_start.state);
        return 1;
    }

    // prepare input structs for third login step
    ServerLogStartResult server_log_start_result = {
        .data = login_server_start.data,
        .size_data = login_server_start.size_data
    };
    ClientLogState client_log_state = { 
        .state = login_client_start.state, 
        .size_state = login_client_start.size_state 
    };
    Opaque login_client_finish = opaque_client_login_finish(
        correct_password, 
        server_log_start_result, 
        client_log_state,
        correct_username,
        servername,
        context
    );
    // la 'printf' seguente dà errore in caso di 'login_client_finish' con campi vuoti, perché sembra che
    // accedere ad un'array vuota non piaccia al linguaggio C

    // printf("%s Client login finish %s \n", c_prefix, login_client_finish.data);
    printOpaque(&login_client_finish, "C - LOG: Client login finish");

    // check if opaque_client_login_finish gives error
    if (login_client_finish.size == 0) {
        printf("C - LOG: Client login finish ERROR \n");
        free_memlib(registration_client_start.data);
        free_memlib(registration_client_start.state);
        free_memlib(registration_server_start.data);
        free_memlib(registration_server_start.setup);
        free_memlib(registration_client_finish.data);
        free_memlib(registration_server_finish.data);
        free_memlib(login_client_start.data);
        free_memlib(login_client_start.state);
        free_memlib(login_server_start.data);
        free_memlib(login_server_start.state);
        return 1;
    }

    // prepare struct for last login step
    ServerLogState server_log_state = { 
        .state = login_server_start.state, 
        .size_state = login_server_start.size_state 
    };
    bool check = opaque_server_login_finish(login_client_finish, server_log_state);
    if (check == true) {
        printf("%s ERRORPATH LOGIN SUCCESSFUL \n", c_prefix);
    } else {
        printf("%s ERRORPATH LOGIN FAILED \n", c_prefix);
        free_memlib(registration_client_start.data);
        free_memlib(registration_client_start.state);
        free_memlib(registration_server_start.data);
        free_memlib(registration_server_start.setup);
        free_memlib(registration_client_finish.data);
        free_memlib(registration_server_finish.data);
        free_memlib(login_client_start.data);
        free_memlib(login_client_start.state);
        free_memlib(login_server_start.data);
        free_memlib(login_server_start.state);
        free_memlib(login_client_finish.data);
        return 1;
    }

    return 0;
}

int main() {
    int happy = happyPath();
    if (happy != 0) {
        return 1;
    }

    int error = errorPath();
    if (error == 0) {
        return 1;
    }

    return 0;
}