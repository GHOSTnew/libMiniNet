/*
 * Project: libMiniNet
 * File: net.c
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

#include "net.h"

int NET_INIT(void) {
#ifdef _WIN32
	WSADATA wsaData;
	if(WSAStartup(MAKEWORD(2, 0), &wsaData) != 0)
	{
		return -1
	}
#elif defined WII
	if(if_config(ip_addr, NULL, NULL, TRUE) < 0) {
		return -1;
	}
#elif defined DS
	if(!Wifi_InitDefault(WFC_CONNECT)) {
		return -1
	}
#endif
	return 0;
}

int NET_SSL_INIT(void) {
#ifdef OPENSSL
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
#elif defined GNUTLS
	if (gnutls_check_version("3.1.4") == NULL) {
		return -1;
	}
	gnutls_global_init();
#endif
	return 0;
}

int NET_SSL_CLEAN(void) {
#ifdef OPENSSL
#elif defined GNUTLS
	gnutls_global_deinit();
#endif
	return 0;
}

int NET_CLEAN(void) {
#ifdef _WIN32
	return WSACleanup();
#endif
	return 0;
}

Conn_t *socketClient(const char *hostname, const unsigned short port, ConnType_t type, int ssl) {
	struct sockaddr_in ServerAddr;
	struct hostent *host;
	Conn_t *connection;
	connection = malloc(sizeof(Conn_t));
#if defined OPENSSL || defined GNUTLS
	connection->isSSL = ssl;
	#ifdef OPENSSL
		connection->sslHandle = NULL;
		connection->ctx = NULL;
	#elif defined GNUTLS
		gnutls_init(&(connection->session), GNUTLS_CLIENT);
		gnutls_session_set_ptr(connection->session, (void *)hostname);
		gnutls_server_name_set(connection->session, GNUTLS_NAME_DNS, hostname, strlen(hostname));
		gnutls_set_default_priority(connection->session);
	#endif
#else
	if (ssl == 1) {
		return NULL;
	}
#endif
#ifdef WII
	host = net_gethostbyname(hostname);
#else
	host = gethostbyname(hostname);
#endif
	if (type == TCP) {
#ifdef WII
		if ((connection->sock = net_socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) < 0) {
#else
		if ((connection->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
#endif
			return NULL;
		}
	} else {
#ifdef WII
		if ((connection->sock = net_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
#else
		if ((connection->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
#endif
			return NULL;
		}
	}
	memset(&ServerAddr, 0, sizeof(ServerAddr));
	ServerAddr.sin_family = AF_INET;
	ServerAddr.sin_addr = *((struct in_addr *) host->h_addr_list[0]);
	ServerAddr.sin_port = htons(port);
#ifdef WII
	if (net_connect(connection->sock, (struct sockaddr *) &ServerAddr, sizeof(ServerAddr)) < 0) {
#else
	if (connect(connection->sock, (struct sockaddr *) &ServerAddr, sizeof(ServerAddr)) < 0) {
#endif
		return NULL;
	}

#if defined OPENSSL || defined GNUTLS
	if (type == TCP && connection->isSSL == 1) {
#ifdef OPENSSL
		connection->ctx = SSL_CTX_new(TLSv1_2_client_method());
		if (connection->ctx == NULL) {
			return NULL;
		}
		connection->sslHandle = SSL_new(connection->ctx);
		if (connection->sslHandle == NULL) {
			return NULL;
		}

		if (!SSL_set_fd(connection->sslHandle, connection->sock)) {
			return NULL;
		}

		if (SSL_connect(connection->sslHandle) != 1) {
			return NULL;
		}
#elif defined GNUTLS
		gnutls_handshake(connection->session);
#endif
	} else if (type == UDP && connection->isSSL == 1){

	}
#endif
	return connection;
}

Conn_t *socketServer(const short port, ConnType_t type, int ssl) {
	struct sockaddr_in ServerAddr;
	Conn_t *connection;
	connection = malloc(sizeof(Conn_t));
#if defined OPENSSL || defined GNUTLS
	connection->isSSL = ssl;
	#ifdef OPENSSL
		connection->sslHandle = NULL;
		connection->ctx = NULL;
	#elif defined GNUTLS
		connection->session = NULL;
	#endif
#else
		if (ssl == 1) {
			return NULL;
		}
#endif

	if (type == TCP) {
#ifdef WII
		if ((connection->sock = net_socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) < 0) {
#else
		if ((connection->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
#endif
			return NULL;
		}
	} else {
#ifdef WII
		if ((connection->sock = net_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
#else
		if ((connection->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
#endif
			return NULL;
		}
	}
	memset(&ServerAddr, 0, sizeof(ServerAddr));
	ServerAddr.sin_family = AF_INET;
	ServerAddr.sin_port = htons(port);
	ServerAddr.sin_addr.s_addr = INADDR_ANY;
#ifdef WII
	if (net_bind(conection->sock, (struct sockaddr*)&ServerAddr, sizeof(ServerAddr)) < 0) {
#else
	if (bind(connection->sock, (struct sockaddr*)&ServerAddr, sizeof(ServerAddr)) < 0) {
#endif
		return NULL;
	}
#ifdef WII
	if (net_listen(connection->sock, 10) != 0) {
#else
	if (listen(connection->sock, 10) != 0) {
#endif
		return NULL;
	}
	return connection;
}

int loadCert(Conn_t *connection, const char *certPath, const char *keyPath) {
#ifdef OPENSSL
	if (SSL_CTX_use_certificate_file(connection->ctx, certPath, SSL_FILETYPE_PEM) < 0) {
		return -1;
	}
	if (SSL_CTX_use_PrivateKey_file(connection->ctx, keyPath, SSL_FILETYPE_PEM) < 0) {
		return -1;
	}

	if ( !SSL_CTX_check_private_key(connection->ctx)) {
		return -1;
	}
	return 0;
#elif defined GNUTLS
	return -1;
#else
	return -1;
#endif
}

Conn_t * socketAccept(Conn_t *connection, struct sockaddr *addr, socklen_t *addr_len) {
	Conn_t * client;
	client = malloc(sizeof(Conn_t));
#if defined OPENSSL || defined GNUTLS
	client->isSSL = connection->isSSL;
	#ifdef OPENSSL
		client->ctx = NULL;
		client->sslHandle = NULL;
	#elif defined GNUTLS
		client->session = NULL;
	#endif
#endif

#ifdef WII
	client->sock = net_accept(connection->sock, addr, addr_len);
#else
	client->sock = accept(connection->sock, addr, addr_len);
#endif

#if defined OPENSSL || defined GNUTLS
	if (connection->isSSL == 1) {
	#ifdef OPENSSL
		client->ctx = SSL_CTX_new(TLSv1_2_server_method());
		if (client->ctx == NULL) {
			return NULL;
		}
		client->sslHandle = SSL_new(client->ctx);
		SSL_set_fd(client->sslHandle, client->sock);
		if (SSL_accept(connection->sslHandle) < 0) {
			return NULL;
		}
	#elif defined GNUTLS
	#endif
	} else {
#endif
#if defined OPENSSL || defined GNUTLS
	}
#endif
	return client;
}

int socketClose(Conn_t *connection) {
	if (connection->sock) {
#ifdef _WIN32
	shutdown(connection->sock, SD_BOTH);
	closesocket(connection->sock);
#elif defined WII
	net_close(connection->sock);
#else
	shutdown(connection->sock, SHUT_RDWR);
	close(connection->sock);
#endif
	}
#ifdef OPENSSL
	if (connection->sslHandle) {
		SSL_shutdown(connection->sslHandle);
		SSL_free(connection->sslHandle);
	}
	if (connection->ctx) {
		SSL_CTX_free(connection->ctx);
	}
#endif
#ifdef GNUTLS
	if (connection->session) {
		 gnutls_deinit(connection->session);
	}
#endif
	free(connection);
	return 0;
}

int socketSend(Conn_t *connection, const void *buf, size_t len, int flags) {
#ifdef OPENSSL
	if (connection->isSSL == 1) {
		SSL_write (connection->sslHandle, buf, len);
	} else {
#elif defined GNUTLS
	if (connection->isSSL == 1) {
		gnutls_record_send(connection->session, buf, len);
	} else {
#endif

#ifdef WII
	if (net_send(connection->sock, buf, len, flags) != len) {
#else
	if (send(connection->sock, buf, len, flags) != (int)len) {
#endif
		return -1;
	}
#if defined OPENSSL || defined GNUTLS
	}
#endif
	return 0;
}

int socketRecv(Conn_t *connection, void *buf, int len, int flags) {
#if defined OPENSSL || defined GNUTLS
	if (connection->isSSL == 1) {
	#ifdef OPENSSL
		return SSL_read(connection->sslHandle, buf, len);
	#elif defined GNUTLS
		return gnutls_record_recv(connection->session, buf, len);
	#endif
	} else {
#endif
#ifdef WII
		return net_recv(connection->sock, buf, len, flags);
#else
		return recv(connection->sock, buf, len, flags);
#endif
#if defined OPENSSL || defined GNUTLS
	}
#endif
}
