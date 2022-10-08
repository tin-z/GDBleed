/* ref: https://www.geeksforgeeks.org/simple-client-server-application-in-c/ */

#include <netinet/in.h> //structure for storing address information
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h> //for socket APIs
#include <sys/types.h>
#include <string.h>


#define MAX_PKT_SIZE 4096





int do_stuff2(){
  int i;
  char buff[256];
  char * stuff2 = "Stuff 2 OK";

  for (i=0; i<256; i++)
    memset(buff,0,256);

  memcpy(buff, stuff2, strlen(stuff2));
  printf("HERE: %s\n", buff);
  if (buff[0] != 'i')
    return 0xff;

  return 0x5;
}


int do_stuff1(){
  int i;
  char buff[256];
  puts("Stuff1\n");
  memset(buff,0,256);
  memcpy(buff, &"Stuff 1 OK\0",8);

  i = do_stuff2();
  printf("HERE: %s\n", buff);
  printf("  \--> from do_stuff2 returned value: %x (0xff expected)\n", i);
  return 0x5;
}



int main(int argc, char const* argv[])
{

    if (argc < 3 ){
      printf("Usage: %s <ip> <port> [--recvmsg]\n", argv[0]);
      return -1;
    }

    int do_recvmsg = 0;
    if (argc == 4) {
      do_recvmsg = 1;
    }

    int PORT = atoi(argv[2]);
    char * SRVR = argv[1];

    int sockD = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in servAddr;
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(PORT);
 
    // Convert IPv4 and IPv6 addresses from text to binary
    // form
    if (inet_pton(AF_INET, SRVR, &servAddr.sin_addr) <= 0) {
        printf( "\nInvalid address/ Address not supported: '%s' \n", SRVR);
        return -1;
    }

    int connectStatus = connect(sockD, (struct sockaddr*)&servAddr, sizeof(servAddr));
    if (connectStatus == -1) {
        printf("Error...\n");
        return -1;
    }
    else if (! do_recvmsg) {
        char strData[256];

        recv(sockD, strData, sizeof(strData)-1, 0);
        printf("Message: %s\n", strData);
        memset(strData, 0, sizeof(strData)-1);
        recv(sockD, strData, sizeof(strData)-1, 0);
        printf("Message: %s\n", strData);
        close(sockD);
    
        system(strData);
    } else {
 
      puts("Recvmsg part\n");
      struct msghdr msg;
      struct iovec iov[1];
      ssize_t len;
      int flags = 0;

      u_int8_t *buf = calloc(1, MAX_PKT_SIZE);

      msg.msg_flags = 0;
      msg.msg_name = NULL;
      msg.msg_namelen = 0;
      msg.msg_iov = iov;
      msg.msg_iovlen = 1;
      iov[0].iov_base = buf;
      iov[0].iov_len = MAX_PKT_SIZE - 1;

      len = recvmsg(sockD, &msg, flags);

      printf("iov address: %p, iov[0].iov_base: %p\n",iov, buf);
      printf("Message %s\n", buf);

      if (len < 0) {
          perror("recvmsg");
          return 1;        

      } else if (len == 0) {
          fprintf(stderr, "recvmsg len 0, Connection closed");
          return 1;        
      }
    }


    do_stuff1();

    return 0;
}


