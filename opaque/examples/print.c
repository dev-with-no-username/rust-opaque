void printOpaqueWithState(OpaqueWithState * s, const char* prefix){
  printf("\n############ OpaqueWithState ############\n");
  printf("%s\n", prefix);
  printf("\ndata: [ ");
  for (int i=0; i < s->size_data; i++) {
    printf("%d, ", s->data[i]);
  }
  printf("]\n");

  printf("\nsize_data: %d\n",(int)s->size_data);

  printf("\nstate: [ ");
  for (int i=0; i < s->size_state; i++) {
    printf("%d, ", s->state[i]);
  }
  printf("]\n");

  printf("\nsize_state: %d\n",(int)s->size_state);
  printf("#########################################\n");
}

void printOpaqueWithSetup(OpaqueWithSetup * s, const char* prefix){
  printf("\n############ OpaqueWithSetup ############\n");
  printf("%s\n", prefix);
  printf("\ndata: [ ");
  for (int i=0; i < s->size_data; i++) {
    printf("%d, ", s->data[i]);
  }
  printf("]\n");

  printf("\nsize_data: %d\n",(int)s->size_data);

  printf("\nsetup: [ ");
  for (int i=0; i < s->size_setup; i++) {
    printf("%d, ", s->setup[i]);
  }
  printf("]\n");

  printf("\nsize_setup: %d\n",(int)s->size_setup);
  printf("#########################################\n");
}

void printOpaque(Opaque * s, const char* prefix){
  printf("\n################ Opaque #################\n");
  printf("%s\n", prefix);
  printf("\ndata: [ ");
  for (int i=0; i < s->size; i++) {
    printf("%d, ", s->data[i]);
  }
  printf("]\n");

  printf("\nsize: %d\n",(int)s->size);
  printf("#########################################\n");
}

void printServerRegPrivateKey(ServerRegPrivateKey * s, const char* prefix){
  printf("\n################ ServerRegPrivateKey #################\n");
  printf("%s\n", prefix);
  printf("\ndata: [ ");
  for (int i=0; i < s->size_data; i++) {
    printf("%d, ", s->data[i]);
  }
  printf("]\n");

  printf("\nsize_data: %d\n",(int)s->size_data);
  printf("#########################################\n");
}