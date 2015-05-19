/*
 * Copyright 2010-2015 Branimir Karadzic. All rights reserved.
 * License: http://www.opensource.org/licenses/BSD-2-Clause
 */

#ifndef BNET_CONFIG_H_HEADER_GUARD
#define BNET_CONFIG_H_HEADER_GUARD

#include <stdint.h>

#ifndef BNET_CONFIG_DEBUG
#	define BNET_CONFIG_DEBUG 0
#endif // BNET_CONFIG_DEBUG

extern void dbgPrintf(const char* _format, ...);
extern void dbgPrintfData(const void* _data, uint32_t _size, const char* _format, ...);

#if BNET_CONFIG_DEBUG
#	define BX_TRACE(_format, ...) \
				do { \
					dbgPrintf(BX_FILE_LINE_LITERAL "BNET " _format "\n", ##__VA_ARGS__); \
				} while(0)

#	define BX_CHECK(_condition, _format, ...) \
				do { \
					if (!(_condition) ) \
					{ \
						BX_TRACE(BX_FILE_LINE_LITERAL _format, ##__VA_ARGS__); \
						bx::debugBreak(); \
					} \
				} while(0)
#endif // 0

#include <bx/bx.h>

#ifndef BNET_CONFIG_DEBUG
#	define BNET_CONFIG_DEBUG 0
#endif // BNET_CONFIG_DEBUG

#ifndef BNET_CONFIG_CONNECT_TIMEOUT_SECONDS
#	define BNET_CONFIG_CONNECT_TIMEOUT_SECONDS 5
#endif // BNET_CONFIG_CONNECT_TIMEOUT_SECONDS

#ifndef BNET_CONFIG_MAX_INCOMING_BUFFER_SIZE
#	define BNET_CONFIG_MAX_INCOMING_BUFFER_SIZE (64<<10)
#endif // BNET_CONFIG_MAX_INCOMING_BUFFER_SIZE

#ifndef BNET_CONFIG_INET_SOCKET
#	define BNET_CONFIG_INET_SOCKET (0 \
		| BX_PLATFORM_WINDOWS \
		| BX_PLATFORM_XBOX360 \
		| BX_PLATFORM_LINUX \
		| BX_PLATFORM_ANDROID \
		| BX_PLATFORM_OSX \
		| BX_PLATFORM_IOS \
		)
#endif // BNET_CONFIG_INET_SOCKET

#endif // BNET_CONFIG_H_HEADER_GUARD
