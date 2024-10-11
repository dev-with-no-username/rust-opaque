# Build Rust code as a library (static or dynamic) and execute it with C compiler

Questo progetto consente di buildare codice Rust come una libreria statica (.a) o dinamica (.so) da poter eseguire col compilatore C.
Tale libreria mette a disposizione funzioni relative al protocollo opaque, sia per quanto riguarda la registrazione che per quanto
riguarda il login. Tutte queste funzioni sono consultabili all'interno del file [librust.h](/opaque/examples/librust.h)

Se è la prima volta che si lavora in Rust, si possono installare tutte le componenti necessarie, lanciando il seguente comando:

```code
cd opaque

task install-requirements
```

Per testare tutte le funzioni di cui sopra, emulando la registrazione con conseguente login di un utente, sarà sufficiente
buildare ed eseguire il progetto lanciando i seguenti comandi:

```code
cd opaque (se non ci si trova già dentro la directory 'opaque')

task run
```

Di default la libreria viene buildata come dinamica (.so), ma se si volesse buildare come statica (.a), allora è sufficiente, nel Taskfile:

1. Commentare la seguente riga:

    ```code
    - "{{.GCC_BIN}} ./examples/main.c -Iexamples -L. -l:target/release/lib{{.LIB_NAME}}.so -o ./examples/bin/main"
    ```

2. Decommentare la seguente riga:

    ```code
    # - "{{.GCC_BIN}} ./examples/main.c -Iexamples -L. -l:target/release/lib{{.LIB_NAME}}.a -o ./examples/bin/main -lpthread -Wl,--no-as-needed -ldl"
    ```
