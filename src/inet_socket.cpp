/*
 * Copyright 2010-2015 Branimir Karadzic. All rights reserved.
 * License: http://www.opensource.org/licenses/BSD-2-Clause
 */

#ifndef BNET_INET_SOCKET_H_HEADER_GUARD
#define BNET_INET_SOCKET_H_HEADER_GUARD

#include "config.h"

#if BNET_CONFIG_INET_SOCKET

#ifndef BNET_CONFIG_OPENSSL
#	define BNET_CONFIG_OPENSSL 0 //(BX_PLATFORM_WINDOWS && BX_COMPILER_MSVC) || BX_PLATFORM_ANDROID || BX_PLATFORM_LINUX
#endif // BNET_CONFIG_OPENSSL

#if BX_PLATFORM_WINDOWS | BX_PLATFORM_XBOX360
#	if BX_PLATFORM_WINDOWS
#		if !defined(_WIN32_WINNT)
#			define _WIN32_WINNT 0x0501
#		endif
#		include <ws2tcpip.h>
#	elif BX_PLATFORM_XBOX360
#		include <xtl.h>
#	endif
#	define BNET_INET_WOULDBLOCK WSAEWOULDBLOCK
#	define BNET_INET_INPROGRESS WSAEINPROGRESS
#	define BNET_INET_SOCKET SOCKET
#	define BNET_INET_INVALID_SOCKET INVALID_SOCKET
#elif BX_PLATFORM_LINUX | BX_PLATFORM_ANDROID | BX_PLATFORM_OSX | BX_PLATFORM_IOS
#	include <memory.h>
#	include <errno.h> // errno
#	include <fcntl.h>
#	include <netdb.h>
#	include <unistd.h>
#	include <sys/socket.h>
#	include <sys/time.h> // gettimeofday
#	include <arpa/inet.h> // inet_addr
#	include <netinet/in.h>
#	include <netinet/tcp.h>
#	define closesocket close
#	define BNET_INET_WOULDBLOCK EWOULDBLOCK
#	define BNET_INET_INPROGRESS EINPROGRESS
#	define BNET_INET_SOCKET int
#	define BNET_INET_INVALID_SOCKET -1
#endif // BX_PLATFORM_

#include "bnet_p.h"

#if BNET_CONFIG_OPENSSL
#	include <openssl/err.h>
#	include <openssl/ssl.h>
#	include <openssl/crypto.h>
#endif // BNET_CONFIG_OPENSSL


namespace bnet {

	struct InetSocket
	{
		BNET_INET_SOCKET sock;
#if BNET_CONFIG_OPENSSL
		SSL* ssl;
#endif // BNET_CONFIG_OPENSSL
	};

	struct InetListenSocket
	{
		BNET_INET_SOCKET sock;
#if BNET_CONFIG_OPENSSL
		X509* cert;
		EVP_PKEY* pkey;
#endif // BNET_CONFIG_OPENSSL
	};

	struct InetContext
	{
		InetSocket* sockets;
		InetListenSocket* listenSockets;
#if BNET_CONFIG_OPENSSL
		SSL_CTX* m_sslCtx;
		SSL_CTX* m_sslCtxServer;

		static void* sslMalloc(size_t _size)
		{
			return BX_ALLOC(g_allocator, _size);
		}

		static void* sslRealloc(void* _ptr, size_t _size)
		{
			return BX_REALLOC(g_allocator, _ptr, _size);
		}

		static void sslFree(void* _ptr)
		{
			return BX_FREE(g_allocator, _ptr);
		}

		typedef void* (*MallocFn)(size_t _size);
		MallocFn m_sslMalloc;

		typedef void* (*ReallocFn)(void* _ptr, size_t _size);
		ReallocFn m_sslRealloc;

		typedef void (*FreeFn)(void* _ptr);
		FreeFn m_sslFree;
#endif // BNET_CONFIG_OPENSSL
	};

	static InetContext s_ctx;

#if BNET_CONFIG_OPENSSL && BNET_CONFIG_DEBUG

	static void getSslErrorInfo()
	{
		BIO* bio = BIO_new(BIO_s_mem());
		ERR_print_errors(bio);
		BUF_MEM *bptr;
		BIO_get_mem_ptr(bio, &bptr);
		BX_TRACE("OpenSSL Error: %.*s", bptr->length, bptr->data);
		BIO_free(bio);
	}

#	define TRACE_SSL_ERROR() getSslErrorInfo()
#else
#	define TRACE_SSL_ERROR()
#endif // BNET_CONFIG_OPENSSL && BNET_CONFIG_DEBUG

	static void setSockOpts(BNET_INET_SOCKET _socket)
	{
		int result;

		int win = 256<<10;
		result = ::setsockopt(_socket, SOL_SOCKET, SO_RCVBUF, (char*)&win, sizeof(win));
		result = ::setsockopt(_socket, SOL_SOCKET, SO_SNDBUF, (char*)&win, sizeof(win));

		int noDelay = 1;
		result = ::setsockopt(_socket, IPPROTO_TCP, TCP_NODELAY, (char*)&noDelay, sizeof(noDelay));
		BX_UNUSED(result);
	}

	static void setNonBlock(BNET_INET_SOCKET _socket)
	{
#if BX_PLATFORM_WINDOWS || BX_PLATFORM_XBOX360
		unsigned long opt = 1;
		ioctlsocket(_socket, FIONBIO, &opt);
#elif BX_PLATFORM_LINUX || BX_PLATFORM_ANDROID || BX_PLATFORM_IOS
		fcntl(_socket, F_SETFL, O_NONBLOCK);
#else
#	error "setNonBlock not implemented for platform"
#endif // BX_PLATFORM_
	}

	static int getLastError()
	{
#if BX_PLATFORM_WINDOWS || BX_PLATFORM_XBOX360
		return WSAGetLastError();
#elif BX_PLATFORM_LINUX || BX_PLATFORM_NACL || BX_PLATFORM_ANDROID || BX_PLATFORM_OSX || BX_PLATFORM_IOS
		return errno;
#else
#	error "getLastError not implemented for platform"
#endif // BX_PLATFORM_
	}

	static bool isInProgress()
	{
		return BNET_INET_INPROGRESS == getLastError();
	}

	static bool isWouldBlock()
	{
		return BNET_INET_WOULDBLOCK == getLastError();
	}

	void socketInit(uint16_t _maxConnections, uint16_t _maxListenSockets, const char* _certs[])
	{
		BX_UNUSED(_certs);

#if BNET_CONFIG_OPENSSL
		CRYPTO_get_mem_functions(&s_ctx.m_sslMalloc, &s_ctx.m_sslRealloc, &s_ctx.m_sslFree);
		CRYPTO_set_mem_functions(s_ctx.sslMalloc, s_ctx.sslRealloc, s_ctx.sslFree);
		SSL_library_init();
#	if BNET_CONFIG_DEBUG
		SSL_load_error_strings();
#	endif // BNET_CONFIG_DEBUG
		s_ctx.m_sslCtx = SSL_CTX_new(SSLv23_client_method());
		SSL_CTX_set_verify(s_ctx.m_sslCtx, SSL_VERIFY_NONE, NULL);
		if (NULL != _certs)
		{
			X509_STORE* store = SSL_CTX_get_cert_store(s_ctx.m_sslCtx);
			for (const char** cert = _certs; NULL != *cert; ++cert)
			{
				BIO* mem = BIO_new_mem_buf(const_cast<char*>(*cert), -1);
				X509* x509 = PEM_read_bio_X509(mem, NULL, NULL, NULL);
				X509_STORE_add_cert(store, x509);
				X509_free(x509);
				BIO_free(mem);
			}
		}

		if (_maxListenSockets)
		{
			s_ctx.m_sslCtxServer = SSL_CTX_new(SSLv23_server_method());
		}
#endif // BNET_CONFIG_OPENSSL

		s_ctx.sockets = (InetSocket*)BX_ALLOC(g_allocator, sizeof(InetSocket)*_maxConnections);
		for (int ii = 0; ii < _maxConnections; ++ii)
		{
			s_ctx.sockets[ii].sock = BNET_INET_INVALID_SOCKET;
#if BNET_CONFIG_OPENSSL
			s_ctx.sockets[ii].ssl = NULL;
#endif // BNET_CONFIG_OPENSSL
		}

		if (_maxListenSockets)
		{
			s_ctx.listenSockets = (InetListenSocket*)BX_ALLOC(g_allocator, sizeof(InetListenSocket)*_maxListenSockets);
			for (int ii = 0; ii < _maxListenSockets; ++ii)
			{
				s_ctx.listenSockets[ii].sock = BNET_INET_INVALID_SOCKET;
#if BNET_CONFIG_OPENSSL
				s_ctx.listenSockets[ii].cert = NULL;
				s_ctx.listenSockets[ii].pkey = NULL;
#endif // BNET_CONFIG_OPENSSL
			}
		}
	}

	void socketShutdown()
	{
		BX_FREE(g_allocator, s_ctx.sockets);
		s_ctx.sockets = NULL;
		BX_FREE(g_allocator, s_ctx.listenSockets);
		s_ctx.listenSockets = NULL;

#if BNET_CONFIG_OPENSSL
		if (s_ctx.m_sslCtx)
		{
			SSL_CTX_free(s_ctx.m_sslCtx);
			s_ctx.m_sslCtx = NULL;
		}

		if (s_ctx.m_sslCtxServer)
		{
			SSL_CTX_free(s_ctx.m_sslCtxServer);
			s_ctx.m_sslCtx = NULL;
		}

		CRYPTO_set_mem_functions(s_ctx.m_sslMalloc, s_ctx.m_sslRealloc, s_ctx.m_sslFree);
#endif // BNET_CONFIG_OPENSSL
	}

	SocketResult::Enum socketResolveIPv4(const char* _addr, uint32_t* _ip)
	{
#if BX_PLATFORM_XBOX360
		return SocketResult::Failure;
#else
		struct addrinfo* result = NULL;
		struct addrinfo hints;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;

		int res = getaddrinfo(_addr, NULL, &hints, &result);
		if (res != 0)
		{
			return SocketResult::Failure;
		}

		struct addrinfo* iter = result;
		while (iter)
		{
			const sockaddr_in* addr = (const sockaddr_in*)result->ai_addr;
			if (AF_INET == result->ai_family
			&&  INADDR_LOOPBACK != addr->sin_addr.s_addr)
			{
				*_ip = ntohl(addr->sin_addr.s_addr);
				freeaddrinfo(result);
				return SocketResult::OK;
			}
		}

		if (result)
		{
			freeaddrinfo(result);
		}

		return SocketResult::Failure;
#endif // BX_PLATFORM_XBOX360
	}

	SocketResult::Enum socketConnect(Handle _handle, uint32_t _ip, uint16_t _port, bool _secure)
	{
		BNET_INET_SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (BNET_INET_INVALID_SOCKET == sock)
		{
			return SocketResult::Failure;
		}

		setSockOpts(sock);
		setNonBlock(sock);

		sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(_ip);
		addr.sin_port = htons(_port);
		memset(&addr.sin_zero, 0, sizeof(addr.sin_zero));

		union
		{
			sockaddr* sa;
			sockaddr_in* sain;
		} saintosa;
		saintosa.sain = &addr;

		int result = connect(sock, saintosa.sa, sizeof(addr));
		if (0 != result)
		{
			if (!(isInProgress() || isWouldBlock()))
			{
				closesocket(sock);
				return SocketResult::Failure;
			}
		}

		s_ctx.sockets[_handle.idx].sock = sock;
#if BNET_CONFIG_OPENSSL
		if (_secure)
		{
			SSL* ssl = SSL_new(s_ctx.m_sslCtx);
			SSL_set_fd(ssl, (int)sock);
			SSL_set_connect_state(ssl);
			SSL_write(ssl, NULL, 0);
			s_ctx.sockets[_handle.idx].ssl = ssl;
		}
		else
		{
			s_ctx.sockets[_handle.idx].ssl = NULL;
		}
#else
		if (_secure)
		{
			BX_TRACE("NO OPENSSL SUPPORT");
			closesocket(sock);
			return SocketResult::Failure;
		}
#endif // BNET_CONFIG_OPENSSL

		return SocketResult::OK;
	}

	void socketClose(Handle _handle)
	{
#if BNET_CONFIG_OPENSSL
		SSL* ssl = s_ctx.sockets[_handle.idx].ssl;
		if (ssl)
		{
			SSL_shutdown(ssl);
			SSL_free(ssl);
			s_ctx.sockets[_handle.idx].ssl = NULL;
		}
#endif // BNET_CONFIG_OPENSSL

		BNET_INET_SOCKET sock = s_ctx.sockets[_handle.idx].sock;
		if (BNET_INET_INVALID_SOCKET != sock)
		{
			closesocket(sock);
			s_ctx.sockets[_handle.idx].sock = BNET_INET_INVALID_SOCKET;
		}
	}

	bool socketIsValid(Handle _handle)
	{
		return BNET_INET_INVALID_SOCKET != s_ctx.sockets[_handle.idx].sock;
	}

	SocketResult::Enum socketHandshake(Handle _handle)
	{
#if BNET_CONFIG_OPENSSL
		SSL* ssl = s_ctx.sockets[_handle.idx].ssl;
		if (ssl)
		{
			int err = SSL_do_handshake(ssl);
			if (1 == err)
			{
#	if BNET_CONFIG_DEBUG
				X509* cert = SSL_get_peer_certificate(ssl);
				BX_TRACE("Server certificate:");

				char *temp;
				temp = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
				BX_TRACE("\t subject: %s", temp);
				OPENSSL_free(temp);

				temp = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
				BX_TRACE("\t issuer: %s", temp);
				OPENSSL_free(temp);

				X509_free(cert);
#	endif // BNET_CONFIG_DEBUG

				long result = SSL_get_verify_result(ssl);
				if (X509_V_OK != result)
				{
					BX_TRACE("SSL verify %d - Failed. %ld", _handle.idx, result);
					return SocketResult::Failure;
				}

				BX_TRACE("SSL %d - connection using %s", _handle.idx, SSL_get_cipher(ssl));
				return SocketResult::OK;
			}
			else
			{
				int sslError = SSL_get_error(ssl, err);
				switch (sslError)
				{
				case SSL_ERROR_WANT_READ:
					SSL_read(ssl, NULL, 0);
					break;

				case SSL_ERROR_WANT_WRITE:
					SSL_write(ssl, NULL, 0);
					break;

				default:
					TRACE_SSL_ERROR();
					break;
				}

				return SocketResult::WouldBlock;
			}
		}
		else
#endif // BNET_CONFIG_OPENSSL
		{
			BNET_INET_SOCKET sock = s_ctx.sockets[_handle.idx].sock;
			fd_set rfds;
			FD_ZERO(&rfds);
			fd_set wfds;
			FD_ZERO(&wfds);
			FD_SET(sock, &rfds);
			FD_SET(sock, &wfds);

			timeval timeout;
			timeout.tv_sec = 0;
			timeout.tv_usec = 0;

			const int nfds =
#if BX_PLATFORM_WINDOWS | BX_PLATFORM_XBOX360
				0 /*nfds is ignored on windows*/
#else
				sock + 1
#endif // BX_PLATFORM_
				;

			int result = select(nfds, &rfds, &wfds, NULL, &timeout);
			if (result <= 0)
			{
				if (result == 0 || isWouldBlock() || isInProgress())
				{
					return SocketResult::WouldBlock;
				}

				BX_TRACE("socketHandshake %d - Select failed. %ld", _handle.idx, getLastError());
				return SocketResult::Failure;
			}

			return SocketResult::OK;
		}
	}

	SocketResult::Enum socketRecv(Handle _handle, uint32_t* _bytesRead, void* _buf, uint32_t _maxBuf)
	{
		int bytes;

#if BNET_CONFIG_OPENSSL
		SSL* ssl = s_ctx.sockets[_handle.idx].ssl;
		if (ssl)
		{
			bytes = SSL_read(ssl, _buf, _maxBuf);
		}
		else
#endif // BNET_CONFIG_OPENSSL
		{
			bytes = ::recv(s_ctx.sockets[_handle.idx].sock, (char*)_buf, _maxBuf, 0);
		}

		if (0 > bytes)
		{
			if (!isWouldBlock())
			{
				TRACE_SSL_ERROR();
				BX_TRACE("Receive %d - failed. %d", _handle.idx, getLastError());
				return SocketResult::Failure;
			}

			return SocketResult::WouldBlock;
		}

		*_bytesRead = bytes;
		return SocketResult::OK;
	}

	SocketResult::Enum socketSendAndRelease(Handle _handle, Message* _msg, int32_t _offset, uint32_t _size)
	{
#if BNET_CONFIG_OPENSSL
		SSL* ssl = s_ctx.sockets[_handle.idx].ssl;
#endif // BNET_CONFIG_OPENSSL
		BNET_INET_SOCKET sock = s_ctx.sockets[_handle.idx].sock;

		while (_size > 0)
		{
			int written;

#if BNET_CONFIG_OPENSSL
			if (ssl)
			{
				written = SSL_write(ssl, _msg->data + _offset, _size);
			}
			else
#endif // BNET_CONFIG_OPENSSL
			{
				written = ::send(sock, (const char*)_msg->data + _offset, _size, 0);
			}

			if (0 > written)
			{
				if (!isWouldBlock())
				{
					return SocketResult::Failure;
				}
			}
			else
			{
				_offset += written;
				_size -= written;
			}
		}

		return SocketResult::OK;
	}

	SocketResult::Enum socketListen(Handle _listenHandle, uint32_t _ip, uint16_t _port, const char *_cert, const char* _key)
	{
#if BNET_CONFIG_OPENSSL
		struct KeyCert
		{
			KeyCert()
			{
				clear();
			}

			~KeyCert()
			{
				if (cert)
				{
					X509_free(cert);
				}
				if (pkey)
				{
					EVP_PKEY_free(pkey);
				}
			}

			void clear()
			{
				cert = NULL;
				pkey = NULL;
			}

			X509* cert;
			EVP_PKEY* pkey;
		};

		KeyCert keycert;
#endif // BNET_CONFIG_OPENSSL

#if BNET_CONFIG_OPENSSL
		if (NULL != _cert)
		{
			BIO* mem = BIO_new_mem_buf(const_cast<char*>(_cert), -1);
			keycert.cert = PEM_read_bio_X509(mem, NULL, NULL, NULL);
			BIO_free(mem);
		}

		if (NULL != _key)
		{
			BIO* mem = BIO_new_mem_buf(const_cast<char*>(_key), -1);
			keycert.pkey = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL);
			BIO_free(mem);
		}
#endif // BNET_CONFIG_OPENSSL

		if (NULL != _cert || NULL != _key)
		{
#if BNET_CONFIG_OPENSSL
			if (keycert.cert == NULL || keycert.pkey == NULL)
			{
				BX_TRACE("Certificate or key is not set correctly.");
				return SocketResult::Failure;
			}
#else
			BX_TRACE("BNET_CONFIG_OPENSSL is not enabled.");
			return SocketResult::Failure;
#endif // BNET_CONFIG_OPENSSL
		}

		BNET_INET_SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (BNET_INET_INVALID_SOCKET == sock)
		{
			return SocketResult::Failure;
		}

		setSockOpts(sock);

		sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(_ip);
		addr.sin_port = htons(_port);
		memset(&addr.sin_zero, 0, sizeof(addr.sin_zero));

		if (0 != bind(sock, (sockaddr*)&addr, sizeof(addr))
		|| 0 != ::listen(sock, SOMAXCONN))
		{
			closesocket(sock);
			BX_TRACE("Bind or listen socket failed.");
			return SocketResult::Failure;
		}

		setNonBlock(sock);

		s_ctx.listenSockets[_listenHandle.idx].sock = sock;
#if BNET_CONFIG_OPENSSL
		s_ctx.listenSockets[_listenHandle.idx].cert = keycert.cert;
		s_ctx.listenSockets[_listenHandle.idx].pkey = keycert.pkey;
		keycert.clear();
#endif // BNET_CONFIG_OPENSSL

		return SocketResult::OK;
	}

	void socketListenClose(Handle _listenHandle)
	{
		BNET_INET_SOCKET sock = s_ctx.listenSockets[_listenHandle.idx].sock;
		if (sock != BNET_INET_INVALID_SOCKET)
		{
			closesocket(sock);
			s_ctx.listenSockets[_listenHandle.idx].sock = BNET_INET_INVALID_SOCKET;
		}

#if BNET_CONFIG_OPENSSL
		X509* cert = s_ctx.listenSockets[_listenHandle.idx].cert;
		if (cert)
		{
			X509_free(cert);
			s_ctx.listenSockets[_listenHandle.idx].cert = NULL;
		}

		EVP_PKEY* pkey = s_ctx.listenSockets[_listenHandle.idx].pkey;
		if (pkey)
		{
			EVP_PKEY_free(pkey);
			s_ctx.listenSockets[_listenHandle.idx].pkey = NULL;
		}
#endif // BNET_CONFIG_OPENSSL
	}

	SocketResult::Enum socketListenHasPending(Handle _listenHandle)
	{
		BNET_INET_SOCKET sock = s_ctx.listenSockets[_listenHandle.idx].sock;
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);

		timeval timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 0;

		const int nfds =
#if BX_PLATFORM_WINDOWS | BX_PLATFORM_XBOX360
			0 /*nfds is ignored on windows*/
#else
			sock + 1
#endif // BX_PLATFORM_
			;

		int result = select(nfds, &rfds, NULL, NULL, &timeout);
		if (result <= 0)
		{
			if (result == 0 || isWouldBlock() || isInProgress())
			{
				return SocketResult::WouldBlock;
			}

			BX_TRACE("socketListenHasPending %d - Select failed. %ld", _listenHandle.idx, getLastError());
			return SocketResult::Failure;
		}

		return SocketResult::OK;
	}

	SocketResult::Enum socketAccept(Handle _listenHandle, Handle _newConnHandle, uint32_t* _ip, uint16_t* _port)
	{
		BNET_INET_SOCKET sock = s_ctx.listenSockets[_listenHandle.idx].sock;

		sockaddr_in addr;
		socklen_t len = sizeof(addr);
		BNET_INET_SOCKET newSock = ::accept(sock, (sockaddr*)&addr, &len);
		if (BNET_INET_INVALID_SOCKET == newSock)
		{
			return SocketResult::Failure;
		}

		s_ctx.sockets[_newConnHandle.idx].sock = sock;

#if BNET_CONFIG_OPENSSL
		if (s_ctx.m_sslCtxServer)
		{
			X509* cert = s_ctx.listenSockets[_listenHandle.idx].cert;
			EVP_PKEY* pkey = s_ctx.listenSockets[_listenHandle.idx].pkey;

			if (cert && pkey)
			{
				SSL* ssl = SSL_new(s_ctx.m_sslCtxServer);
				int result;
				result = SSL_use_certificate(ssl, cert);
				result = SSL_use_PrivateKey(ssl, pkey);
				result = SSL_set_fd(ssl, (int)sock);
				BX_UNUSED(result);
				SSL_set_accept_state(ssl);
				SSL_read(ssl, NULL, 0);

				s_ctx.sockets[_newConnHandle.idx].ssl = ssl;
			}
		}
#endif // BNET_CONFIG_OPENSSL

		*_ip = ntohl(addr.sin_addr.s_addr);
		*_port = ntohs(addr.sin_port);
		return SocketResult::OK;
	}

} // namespace bnet

#endif // BNET_CONFIG_INET_SOCKET

#endif // BNET_INET_SOCKET_H_HEADER_GUARD
