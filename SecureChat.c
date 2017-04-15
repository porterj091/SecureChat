#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define SERVER_PORT 6993
#define MESSAGE_SIZE 1024
#define AES_KeySize 16  // In bytes
static int listen_fd, comm_fd, sockfd;

void Usage();
void runServer();
void runClient(char *);
RSA* generateKeys(char *, char *);

void sig_handler(int signo)
{
  if (signo == SIGINT)
  {
    printf("\n%s\n", "Shutting Down!");
    close(listen_fd);
    close(comm_fd);
    close(sockfd);
    exit(1);
  }
}

int main(int argc, char *argv[])
{

  if(signal(SIGINT, sig_handler) == SIG_ERR)
  {
    printf("%s\n", "Can't catch SIGINT");
  }

  if (argc > 3)
  {
    Usage();
    exit(1);
  }

  if(strncmp(argv[1], "-l", 2) == 0)  // Run the Server
  {
    runServer();
  }
  else if(strncmp(argv[1], "-c", 2) == 0) // Run the Client
  {
    if (argc != 3)
    {
      Usage();
      exit(1);
    }

    char ipAddr[16];
    strncpy(ipAddr, argv[2], 15);
    runClient(ipAddr);
  }
  else
  {
    Usage();
    return 1;
  }

  return 0;
}

void runServer()
{
  AES_KEY sessionKey;
  char message[MESSAGE_SIZE];
  char decryptedMessage[MESSAGE_SIZE];
  unsigned char rsaMessage[4096];
  char sendMessage[MESSAGE_SIZE];

  struct sockaddr_in serverAddr;

  listen_fd = socket(AF_INET, SOCK_STREAM, 0);

  if(listen_fd < 0)
  {
    perror("ERROR opening socket");
    exit(1);
  }

  memset(&serverAddr, 0, sizeof(serverAddr));

  serverAddr.sin_family = AF_INET;
  serverAddr.sin_addr.s_addr = htons(INADDR_ANY);
  serverAddr.sin_port = htons(SERVER_PORT);

  if(bind(listen_fd, (const struct sockaddr*) &serverAddr, sizeof(serverAddr)) != 0)
  {
    perror("Bind ERROR");
    exit(1);
  }

  listen(listen_fd, 10);

  comm_fd = accept(listen_fd, (struct sockaddr*) NULL, NULL);

  printf("\n%s\n", "Client trying to Connect\nEstablishing a secure session");

  // Read the RSA public key from the client
  read(comm_fd, rsaMessage, 4096);

  RSA *publicKey = NULL;
  BIO *pub = BIO_new_mem_buf(rsaMessage, (int)strlen(rsaMessage));
  PEM_read_bio_RSAPublicKey(pub, &publicKey, NULL, NULL);

  if(publicKey == NULL)
  {
    fprintf(stderr, "%s\n", "Problem reading public key from client");
    close(comm_fd);
    exit(1);
  }

  memset(&rsaMessage, 0, sizeof(rsaMessage));

  // Grab random bytes to use as session key
  unsigned char randomBytes[16];
  FILE *fp = fopen("/dev/urandom", "r");
  fread(&randomBytes, 1, AES_KeySize, fp);
  fclose(fp);

  // Server will only be decrypting the message
  if(AES_set_decrypt_key(randomBytes, 128, &sessionKey) != 0)
  {
    fprintf(stderr, "%s\n", "Session Key could not be generated");
    exit(1);
  }

  // Generate a Session key from /dev/urandom
  int encryptedLen;
  if((encryptedLen = RSA_public_encrypt(AES_KeySize, (unsigned char*)randomBytes, (unsigned char*)rsaMessage, publicKey, RSA_PKCS1_PADDING)) == -1)
  {
    fprintf(stderr, "%s\n", "Error encrypting session key");
    close(comm_fd);
    exit(1);
  }
  write(comm_fd, rsaMessage, encryptedLen);

  RSA_free(publicKey);
  free(pub);
  printf("%s\n\n", "Secure Connection Established");

  while(1)
  {
    memset(&message, 0, sizeof(message));
    memset(&decryptedMessage, 0, sizeof(decryptedMessage));
    read(comm_fd, message, MESSAGE_SIZE);

    // Decrypt the message in 16 byte chunks
    for(int i = 0; i < MESSAGE_SIZE; i += 16)
    {
      AES_ecb_encrypt(message + i, decryptedMessage + i, &sessionKey, AES_DECRYPT);
    }

    printf("Message Received: %s", decryptedMessage);
  }

  close(comm_fd);
}

void runClient(char *ipAddr)
{
  AES_KEY sessionKey;
  unsigned char sendline[MESSAGE_SIZE];
  unsigned char encryptedMessage[MESSAGE_SIZE];
  unsigned char recvline[MESSAGE_SIZE];
  unsigned char RSALine[4096];
  struct sockaddr_in serverAddr;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sockfd < 0)
  {
    perror("ERROR SOCKET");
    exit(1);
  }

  memset(&serverAddr, 0, sizeof(serverAddr));

  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(SERVER_PORT);

  if(inet_pton(AF_INET, ipAddr, &(serverAddr.sin_addr)) != 1)
  {
    fprintf(stderr, "%s\n", "ERROR COULD NOT FIND IP");
    fprintf(stderr, "%s\n", "IP Address must be in this format ddd.ddd.ddd.ddd");
    exit(1);
  }

  if(connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) != 0)
  {
    perror("CONNECTION");
    exit(1);
  }
  printf("\n%s\n", "Establishing a secure connection!");

  char publicKey[4096];
  char privateKey[4096];
  RSA *keypair = NULL;
  keypair = generateKeys(publicKey, privateKey);

  memset(&RSALine, 0, sizeof(RSALine));
  memset(&recvline, 0, sizeof(recvline));
  memcpy(RSALine, publicKey, 4096);

  // Send the public RSA key to the server
  write(sockfd, RSALine, 4096);

  // What is send back is the encrypted AES session key
  int readLen = read(sockfd, recvline, MESSAGE_SIZE);

  unsigned char decryptedKey[4096];
  if(RSA_private_decrypt(readLen, (unsigned char*)recvline, (unsigned char*)decryptedKey, keypair, RSA_PKCS1_PADDING) == -1)
  {
    fprintf(stderr, "%s\n", "Error decrypting session key");
    exit(1);
  }

  if(AES_set_encrypt_key(decryptedKey, 128, &sessionKey) != 0)
  {
    fprintf(stderr, "%s\n", "Session Key could not be generated");
    exit(1);
  }

  RSA_free(keypair);

  printf("%s\n\n", "Secure Connection Established!");


  // Now allow user to send messages encrypted to server
  while(1)
  {
    memset(&sendline, 0, sizeof(sendline));
    memset(&encryptedMessage, 0, sizeof(encryptedMessage));
    printf("%s", "Enter Message: ");
    fgets((char*)sendline, MESSAGE_SIZE, stdin);

    // Encrypt the message in 16 byte chunks
    for(int i = 0; i < MESSAGE_SIZE; i += 16)
    {
      AES_ecb_encrypt(sendline + i, encryptedMessage + i, &sessionKey, AES_ENCRYPT);
    }
    write(sockfd, encryptedMessage, MESSAGE_SIZE);
  }

  close(sockfd);
}

void Usage()
{
  printf("%s\n", "Incorrect Usage!");
  printf("%s\n", "./SecureChat {-l | -c TARGET-IP}");
}

RSA* generateKeys(char *publicDest, char *privateDest)
{
  RSA *keypair = NULL;
  keypair = RSA_new();
  BIGNUM *e = NULL;
  e = BN_new();
  BN_set_word(e, 65537);

  if(RSA_generate_key_ex(keypair, 4096, e, NULL) != 1)
  {
    perror("RSA Generation");
    exit(1);
  }

  BN_free(e);
  e = NULL;

  BIO *pri = BIO_new(BIO_s_mem());
  BIO *pub = BIO_new(BIO_s_mem());

  PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
  PEM_write_bio_RSAPublicKey(pub, keypair);

  size_t pri_len = BIO_pending(pri);
  size_t pub_len = BIO_pending(pub);

  char *pri_key = malloc(pri_len + 1);
  char *pub_key = malloc(pub_len + 1);

  BIO_read(pri, pri_key, pri_len);
  BIO_read(pub, pub_key, pub_len);

  memcpy(publicDest, pub_key, pub_len);
  memcpy(privateDest, pri_key, pri_len);

  free(pri);
  free(pub);

  return keypair;
}
