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

#define MININET_VERSION "2.0~prototype"

#include <string.h>
#include <malloc.h>

/* --------- WINDOWS ------------ */
#ifdef _WIN32
	#ifndef _WIN32_WINNT
		#define  _WIN32_WINNT 0x0501
	#endif
	#include <winsock.h>
	#include <winsock2.h>
	#include <Ws2tcpip.h>
/* --------- NINTENDO WII --------- */
#elif defined WII
	#include <network.h>

/* --------- NINTENDO DS ---------- */
#elif defined DS
	#include <dswifi9.h>
	#include <sys/socket.h>
	#include <netdb.h>
	#include <netinet/in.h>
/* ------------- UNIX ------------- */
#else
/* -------- z/OS------------- */
	#ifdef  __MVS__
		#define _OE_SOCKETS
	#endif
/* -------- end z/OS--------- */
	#include <sys/socket.h>
	#include <arpa/inet.h>
	#include <netdb.h>
	#include <unistd.h>
#endif

#ifdef OPENSSL
	#include <openssl/ssl.h>
	#include <openssl/err.h>
#elif defined GNUTLS
	#include <gnutls/gnutls.h>
	#include <gnutls/x509.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif /* !__cplusplus */

struct Conn {
#ifdef WII
	s32 sock;
#else
	int sock;
#endif
#if defined OPENSSL || defined GNUTLS
	int isSSL;
	#ifdef OPENSSL
		SSL *sslHandle;
		SSL_CTX *ctx;
	#else
		gnutls_session_t session;
	#endif
#endif
};
typedef struct Conn Conn_t;

enum ConnType {
	TCP,
	UDP
};
typedef enum ConnType ConnType_t;

enum ProxyType {
	PROXY_NONE,
	PROXY_SOCKS5
};
typedef enum ProxyType ProxyType_t;

/* -------- init function --------- */
int NET_INIT(void);
int NET_SSL_INIT(void);
int NET_SSL_CLEAN(void);
int NET_CLEAN(void);

/* ------ create socket func ------ */
Conn_t *socketClient(const char * hostname, const unsigned short port, ConnType_t type, int ssl);
Conn_t *socketServer(const short port, ConnType_t type, int ssl);
Conn_t *socketAccept(Conn_t *connection, struct sockaddr *addr, socklen_t *addr_len);

/* --------- act on socket ---------*/
int loadCert(Conn_t * connection, const char * certPath, const char * keyPath);
int socketClose(Conn_t *connection);
int socketSend(Conn_t *connection, const void *buf, size_t len, int flags);
int socketRecv(Conn_t *connection, void *buf, int len, int flags);

#ifdef  __cplusplus
}
#endif /* !__cplusplus */

#endif /* NET_H_ */
