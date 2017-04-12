#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define SERVER_PORT 6993
#define MESSAGE_SIZE 1024

void Usage();
void runServer();
void runClient(char *);

int main(int argc, char *argv[])
{

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
  char message[MESSAGE_SIZE];
  char sendMessage[MESSAGE_SIZE];
  int listen_fd, comm_fd;

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

  while(1)
  {
    memset(&message, 0, sizeof(message));
    read(comm_fd, message, MESSAGE_SIZE);

    int length = strlen(message);
    // Grab the type of message INIT for when client is setting up connection
    // NORMAL for just a message should be last byte in message
    uint8_t type = (uint8_t)message[length-1];

    if (type == 0x01) // Initiation message
    {
      printf("%s\n", "Client trying to connect!!\nEstablishing secure connection!!");
      strcpy(sendMessage, "1234567890123456");
      write(comm_fd, sendMessage, strlen(sendMessage) + 1);
    }
    else if (type == 0x02)  // Normal message
    {
      printf("Message Received: %s\n", message);
    }
    else
    {
      fprintf(stderr, "%s\n", "Message had formatting errors");
      exit(1);
    }
  }
}

void runClient(char *ipAddr)
{
  int sockfd;
  char sendline[MESSAGE_SIZE];
  char recvline[MESSAGE_SIZE];
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
  printf("%s%d\n", "Got this far: ", __LINE__);

  while(1)
  {
    memset(&sendline, 0, sizeof(sendline));
    memset(&recvline, 0, sizeof(recvline));
    fgets(sendline, MESSAGE_SIZE-1, stdin);
    sendline[strlen(sendline)] = 0x01;
    write(sockfd, sendline, strlen(sendline) + 1);
    read(sockfd, recvline, MESSAGE_SIZE);
    printf("%s\n", recvline);
  }
}

void Usage()
{
  printf("%s\n", "Incorrect Usage!");
  printf("%s\n", "./SecureChat {-l | -c TARGET-IP}");
}
