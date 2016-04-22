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
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define PORT1 "80";
#define PORT2 "443";

int parseheader(std::string data){
  std::cout << data << std::endl;
  int size_index = data.find("Content-Length: ");
  if (size_index == std::string::npos){
    std::cout << "error: Couldn't find content-length" << std::endl;
    return 1;
  }
  size_index+=16;
  std::string size_str = data.substr(size_index, data.find("\r",size_index) - size_index);
  return atoi(size_str.c_str());
}



struct connection {
  bool ssl;
	union {
		BIO *bio;
		int sockfd;
	};
	//ssize_t (*read)(struct connection *conn, void *buf, size_t bytes);
	//ssize_t (*write)(struct connection *conn, const void *buf, size_t bytes);
  ssize_t read(void *buf, size_t bytes, int flags){
    if (ssl){
    return BIO_read(bio, buf,bytes);
    }
    else {
      return recv(sockfd, buf,bytes,flags);
    }
  }
  ssize_t write(const void *buf, size_t bytes, int flags){
    if (ssl){
    return BIO_write(bio, buf,bytes);
    }
    else {
      return send(sockfd, buf,bytes,flags);
    }
  }
  void closeconnec(){
    if (ssl){
      BIO_free_all(bio);
    }
    else {
      close(sockfd);
    }
  }
};

int main(int argc , char *argv[])
{
  if (SSL_library_init() < 0){
    std::cout<< "Could not initialize the OpenSSL library !" << std::endl;
  }
  SSL_load_error_strings();
  bool ssl = false;

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
    ssl = true;
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
  SSL_CTX *ctx;
  struct connection connec;
  connec.ssl = ssl;

if (ssl){
  const SSL_METHOD* method = TLSv1_client_method();
  //SSLv23_client_method()
  ctx = SSL_CTX_new(method);
  connec.bio = BIO_new_ssl_connect(ctx);
  BIO_set_conn_hostname(connec.bio, host.c_str());
  BIO_set_conn_port(connec.bio,port.c_str());
  BIO_do_connect(connec.bio);
  BIO_do_handshake(connec.bio);
}
else {
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
    connec.sockfd = fd;
}
  std::string request = "GET " + path + " HTTP/1.1\r\n";
  std::string header = "Host: " + host + ":" + port + "\r\n";
  std::string header2 = "User-Agent: martij24-netprog-hw5/1.0\r\n\r\n";
  std::cout << request + header + header2 << std::endl;
  if (connec.write(request.c_str(), request.size(), 0) < 0)
    perror("send()");

  if (connec.write(header.c_str(), header.size(), 0) < 0)
    perror("send()");

  if (connec.write(header2.c_str(), header2.size(), 0) < 0)
    perror("send()");
  char head[1000];
  bzero(head,1000);

  connec.read(&head, sizeof(head)-1, 0);
  fputs(head, stderr);
  std::string data = std::string(head);

  int size = parseheader(data);

  char content[size];
  bzero(content,size);
  int read = connec.read(&content, size-1, MSG_WAITALL);
  std::cout.write(content,size) << std::endl;
  connec.closeconnec();
  if (ssl)
    SSL_CTX_free(ctx);
}
