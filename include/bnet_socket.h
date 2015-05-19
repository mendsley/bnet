/*
 * Copyright 2010-2015 Branimir Karadzic. All rights reserved.
 * License: http://www.opensource.org/licenses/BSD-2-Clause
 */

#ifndef BNET_SOCKET_H_HEADER_GUARD
#define BNET_SOCKET_H_HEADER_GUARD

#include <stdint.h>

namespace bnet
{
	struct Handle;

	struct SocketResult
	{
		enum Enum
		{
			Failure,
			OK,
			WouldBlock,
		};
	};

	void socketInit(uint16_t _maxConnections, uint16_t _maxListenSockets, const char* _certs[]);
	void socketShutdown();

	SocketResult::Enum socketResolveIPv4(const char* _addr, uint32_t* _ip);

	SocketResult::Enum socketConnect(Handle _handle, uint32_t _ip, uint16_t _port, bool _secure);
	void socketClose(Handle _handle);
	bool socketIsValid(Handle _handle);
	SocketResult::Enum socketHandshake(Handle _handle);
	SocketResult::Enum socketRecv(Handle _handle, uint32_t* _bytesRead, void* _buf, uint32_t _maxBuf);
	SocketResult::Enum socketSendAndRelease(Handle _handle, bnet::Message* _msg, int32_t _offset, uint32_t _size);

	SocketResult::Enum socketListen(Handle _listenHandle, uint32_t _ip, uint16_t _port, const char *_cert, const char* _key);
	void socketListenClose(Handle _listenHandle);
	SocketResult::Enum socketListenHasPending(Handle _listenHandle);
	SocketResult::Enum socketAccept(Handle _listenHandle, Handle _newConnHandle, uint32_t* _ip, uint16_t* _port);

} // namespace bnet

#endif // BNET_SOCKET_H_HEADER_GUARD
