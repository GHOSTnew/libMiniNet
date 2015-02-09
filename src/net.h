/*
 * Project: libMiniNet
 * File: net.h
 * Created on: 6 févr. 2015
 *
 * Language: C
 *
 * License: GNU Public License
 *
 * (c) Copyright 2015 ~ Team Mondial
 *
 * Author: ghostnew
 * E-Mail: Base64:Z2hvc3RuZXcuZ2Vla0BnbWFpbC5jb20=
 */

#ifndef NET_H_
#define NET_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef _WIN33
	#ifndef _WIN32_WINNT
		#define  _WIN32_WINNT 0x0501
	#endif
	#include <winsock.h>
	#include <winsock2.h>
	#include <Ws2tcpip.h>
#else
	#include <sys/socket.h>
	#include <arpa/inet.h>
	#include <netdb.h>
	#include <unistd.h>
#endif

#ifdef OPENSSL
	#include <openssl/ssl.h>
	#include <openssl/err.h>
#endif
#ifdef GNUTLS
	#include <gnutls/gnutls.h>
#endif

#ifdef MINIUPNP
#include "miniwget.h"
#include "miniupnpc.h"
#include "upnpcommands.h"
#include "upnperrors.h"
#endif

typedef struct conn conn;
struct conn {
	int sock;
#ifdef OPENSSL
	int isSSL;
	SSL *sslHandle;
	SSL_CTX *ctx;
#endif
#ifdef GNUTLS
	int isSSL;
	gnutls_session_t session;
#endif
};

typedef enum CONN_TYPE CONN_TYPE;
enum CONN_TYPE {
	TCP,
	UDP
};

#ifdef  __cplusplus
extern "C" {
#endif
int NET_INIT(void);
int NET_SSL_INIT(void);
int NET_SSL_CLEAN(void);
int NET_CLEAN(void);

conn* socketClient(const char * hostname, const short port, CONN_TYPE type, int ssl);
conn * socketServer(const short port, CONN_TYPE type, int ssl);
conn * socketAccept(conn *connection, struct sockaddr *__restrict addr, socklen_t *__restrict __addr_len);
int loadCert(conn * connection, char * certPath, char * keyPath);
int socketClose(conn *connection);
int socketSend(conn *connection, const void * buf, size_t len, int flags);

#ifdef  __cplusplus
}
#endif

#endif /* NET_H_ */
