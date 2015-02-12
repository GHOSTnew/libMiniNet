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
	if(if_config(adresse_ip,NULL,NULL, TRUE) < 0) {
		return -1;
	}
#endif
	return 0;
}

int NET_SSL_INIT(void) {
#ifdef OPENSSL
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
#endif
#ifdef GNUTLS
	if (gnutls_check_version("3.1.4") == NULL) {
		return -1;
	}
	gnutls_global_init();
#endif
	return 0;
}

int NET_SSL_CLEAN(void) {
#ifdef OPENSSL
#endif
#ifdef GNUTLS
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

conn* socketClient(const char * hostname, const short port, CONN_TYPE type, int ssl) {
	struct sockaddr_in ServerAddr;
	struct hostent *host;
	conn * connection;
	connection = malloc(sizeof(conn));
#if defined OPENSSL || defined GNUTLS
	connection->isSSL = ssl;
#ifdef OPENSSL
	connection->sslHandle = NULL;
	connection->ctx = NULL;
	connection->isSSL = ssl;
#endif
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

#endif
	} else if (type == UDP && connection->isSSL == 1){

	}
#endif
	return connection;
}

conn * socketServer(const short port, CONN_TYPE type, int ssl) {
	struct sockaddr_in ServerAddr;
	conn * connection;
	connection = malloc(sizeof(conn));
#ifdef OPENSSL
	connection->sslHandle = NULL;
	connection->ctx = NULL;
	connection->isSSL = ssl;
#endif
#ifdef GNUTLS
	connection->isSSL = ssl;
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

int loadCert(conn * connection, char * certPath, char * keyPath) {
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
#endif
	return 0;
}

conn * socketAccept(conn *connection, struct sockaddr *__restrict addr, socklen_t *__restrict __addr_len) {
	conn * client;
	client = malloc(sizeof(conn));
#ifdef OPENSSL
	client->ctx = NULL;
	client->sslHandle = NULL;
	client->isSSL = connection->isSSL;
#endif
#ifdef GNUTLS
	client->isSSL = connection->isSSL;
#endif

#ifdef WII
	client->sock = net_accept(connection->sock, addr, __addr_len);
#else
	client->sock = accept(connection->sock, addr, __addr_len);
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

int socketClose(conn *connection) {
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

int socketSend(conn *connection, const void * buf, size_t len, int flags) {
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
	if (send(connection->sock, buf, len, flags) != len) {
#endif
		return -1;
	}
#if defined OPENSSL || defined GNUTLS
	}
#endif
	return 0;
}

int socketRecv(conn *connection, void *buf, int len, int flags) {
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

int openPort(short port) {
#ifdef UPNP
#else
	return -1;
#endif
}

int closePort(short port) {
#ifdef UPNP
#else
	return -1;
#endif
}
