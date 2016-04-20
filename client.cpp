#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <cstdlib>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define PORT1 "80";
#define PORT2 "443";



struct connection {
	union {
		BIO *bio;
		int sockfd;
	};
	ssize_t (*read)(struct connection *conn, void *buf, size_t bytes);
	ssize_t (*write)(struct connection *conn, const void *buf, size_t bytes);
};

int main(int argc , char *argv[])
{
  std::string port;
  std::string host;
  std::string path;
  if (argc !=  2){
    std::cout << "bad arguments" << std::endl;
    return 1;
  }
  std::string input = argv[1];
  int index = input.find(":",6);
  int index2 = input.find("/",8);

  if (index2 == std::string::npos){
    index2 = input.size();
  }
  if (index == std::string::npos){
    index = index2;
  }
  else {
    port = input.substr(index+1,index2 - index - 1);
  }
  if (input.substr(0,5)=="https"){
    host = input.substr(8,index - 8);
    if (index == std::string::npos)
      port = PORT2;
  }
  else {
    host = input.substr(7,index - 7);
    if (index == std::string::npos)
      port = PORT1;

  }

  std::cout << host << ":" << port << std::endl;

  path = input.substr(index2,input.length() - index2);



  struct addrinfo hints;
  struct addrinfo * res = 0;

  memset(&hints, 0, sizeof hints); // make sure the struct is empty
  hints.ai_family = AF_UNSPEC;     // don't care IPv4 or IPv6
  hints.ai_socktype=SOCK_STREAM;
  hints.ai_protocol=IPPROTO_TCP;
  hints.ai_flags = (AI_ADDRCONFIG | AI_ALL);
  int err=getaddrinfo(host.c_str(),port.c_str(),&hints,&res);
  if (err!=0) {
      std::cout << "failed to resolve remote socket address " << gai_strerror(err) << std::endl;
      exit(1);
  }
  int fd=socket(res->ai_family,res->ai_socktype,res->ai_protocol);
  if (fd==-1) {
      perror("socked creation failed");
  }
  if (connect(fd,res->ai_addr,res->ai_addrlen)==-1) {
      perror("Failed to connect");
  }
  std::string request = "GET " + path + " HTTP/1.1\r\n";
  std::string header = "Host: " + host + ":" + port + "\r\n";
  std::string header2 = "User-Agent: martij24-netprog-hw3/1.0\r\n\r\n";
  std::cout << request + header + header2 << std::endl;
  if (send(fd, request.c_str(), request.size(), 0) < 0)
    perror("send()");

  if (send(fd, header.c_str(), header.size(), 0) < 0)
    perror("send()");

  if (send(fd, header2.c_str(), header2.size(), 0) < 0)
    perror("send()");
  char head[1000];
  bzero(head,1000);

  recv(fd, &head, sizeof(head)-1, 0);
  fputs(head, stderr);
  std::string data = std::string(head);
  int size_index = data.find("Content-Length: ");
  if (size_index == std::string::npos){
    std::cout << "error: Couldn't find content-length" << std::endl;
    return 1;
  }
  size_index+=16;
  std::string size_str = data.substr(size_index, data.find("\r",size_index) - size_index);
  int size = atoi(size_str.c_str());

  char content[size];
  bzero(content,size);
  int read = recv(fd, &content, size-1, MSG_WAITALL);
  std::cout.write(content,size) << std::endl;
  close(fd);

}
