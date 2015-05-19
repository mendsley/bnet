/*
 * Copyright 2010-2015 Branimir Karadzic. All rights reserved.
 * License: http://www.opensource.org/licenses/BSD-2-Clause
 */

#include "bnet_p.h"

#include <bx/endian.h>

namespace bnet
{
	static bx::CrtAllocator s_allocatorStub;
	bx::ReallocatorI* g_allocator = &s_allocatorStub;

	class Connection
	{
	public:
		Connection()
			: m_handle(invalidHandle)
			, m_incomingBuffer( (uint8_t*)BX_ALLOC(g_allocator, BNET_CONFIG_MAX_INCOMING_BUFFER_SIZE) )
			, m_incoming(BNET_CONFIG_MAX_INCOMING_BUFFER_SIZE)
			, m_recv(m_incoming, (char*)m_incomingBuffer)
			, m_len(-1)
			, m_raw(false)
			, m_handshake(true)
		{
			BX_TRACE("ctor %d", m_handle);
		}

		~Connection()
		{
			BX_TRACE("dtor %d", m_handle);
			BX_FREE(g_allocator, m_incomingBuffer);
		}

		void connect(Handle _handle, uint32_t _ip, uint16_t _port, bool _raw, bool _secure)
		{
			init(_handle, _raw);

			SocketResult::Enum result = socketConnect(_handle, _ip, _port, _secure);
			if (result != SocketResult::OK)
			{
				ctxPush(m_handle, MessageId::ConnectFailed);
				return;
			}
		}

		void accept(Handle _handle, Handle _listenHandle, bool _raw)
		{
			init(_handle, _raw);

			uint32_t ip;
			uint16_t port;
			SocketResult::Enum result = socketAccept(_listenHandle, _handle, &ip, &port);
			if (result != SocketResult::OK)
			{
				BX_TRACE("Accept %d -> %d - Failed.", _listenHandle.idx, _handle.idx);
				disconnect();
				return;
			}

			Message* msg = msgAlloc(m_handle, 9, true);
			msg->data[0] = MessageId::IncomingConnection;
			*( (uint16_t*)&msg->data[1]) = _listenHandle.idx;
			*( (uint32_t*)&msg->data[3]) = ip;
			*( (uint16_t*)&msg->data[7]) = port;
			ctxPush(msg);
		}

		void disconnect(DisconnectReason::Enum _reason = DisconnectReason::None)
		{
			if (hasSocket())
			{
				socketClose(m_handle);
			}

			for (Message* msg = m_outgoing.pop(); NULL != msg; msg = m_outgoing.pop() )
			{
				release(msg);
			}

			if (_reason != DisconnectReason::None)
			{
				Message* msg = msgAlloc(m_handle, 2, true);
				msg->data[0] = MessageId::LostConnection;
				msg->data[1] = _reason;
				ctxPush(msg);
			}
		}

		void send(Message* _msg)
		{
			BX_CHECK(m_raw || _msg->data[0] >= MessageId::UserDefined, "Sending message with MessageId below UserDefined is not allowed!");
			if (hasSocket())
			{
				m_outgoing.push(_msg);
				update();
			}
		}

		void update()
		{
			if (hasSocket())
			{
				updateSocket();

				if (!m_handshake)
				{
					updateIncomingMessages();
				}
			}
		}

		bool hasSocket() const
		{
			return socketIsValid(m_handle);
		}

	private:
		void init(Handle _handle, bool _raw)
		{
			m_handle = _handle;
			m_handshake = true;
			m_handshakeTimeout = bx::getHPCounter() + bx::getHPFrequency()*BNET_CONFIG_CONNECT_TIMEOUT_SECONDS;
			m_len = -1;
			m_raw = _raw;

			BX_TRACE("init %d", m_handle);
		}

		void read(bx::WriteRingBuffer& _out, uint32_t _len)
		{
			bx::ReadRingBuffer incoming(m_incoming, (char*)m_incomingBuffer, _len);
			_out.write(incoming, _len);
			incoming.end();
		}

		void read(uint32_t _len)
		{
			m_incoming.consume(_len);
		}

		void read(char* _data, uint32_t _len)
		{
			bx::ReadRingBuffer incoming(m_incoming, (char*)m_incomingBuffer, _len);
			incoming.read(_data, _len);
			incoming.end();
		}

		void peek(char* _data, uint32_t _len)
		{
			bx::ReadRingBuffer incoming(m_incoming, (char*)m_incomingBuffer, _len);
			incoming.read(_data, _len);
		}

		void updateIncomingMessages()
		{
			if (m_raw)
			{
				uint32_t available = bx::uint32_min(m_incoming.available(), maxMessageSize-1);

				if (0 < available)
				{
					Message* msg = msgAlloc(m_handle, available+1, true);
					msg->data[0] = MessageId::RawData;
					read( (char*)&msg->data[1], available);
					ctxPush(msg);
				}
			}
			else
			{
				uint32_t available = bx::uint32_min(m_incoming.available(), maxMessageSize);

				while (0 < available)
				{
					if (-1 == m_len)
					{
						if (2 > available)
						{
							return;
						}
						else
						{
							uint16_t len;
							read((char*)&len, 2);
							m_len = bx::toHostEndian(len, true);
						}
					}
					else
					{
						if (m_len > int(available) )
						{
							return;
						}
						else
						{
							Message* msg = msgAlloc(m_handle, m_len, true);
							read( (char*)msg->data, m_len);
							uint8_t id = msg->data[0];

							if (id < MessageId::UserDefined)
							{
								msgRelease(msg);

								BX_TRACE("Disconnect %d - Invalid message id.", m_handle);
								disconnect(DisconnectReason::InvalidMessageId);
								return;
							}

							ctxPush(msg);
						
							m_len = -1;
						}
					}
					
					available = bx::uint32_min(m_incoming.available(), maxMessageSize);
				}
			}
		}

		void updateSocket()
		{
			if (updateHandshake())
			{
				uint32_t bytes;
				SocketResult::Enum result = m_recv.recv(m_handle, &bytes);

				if (result == SocketResult::Failure)
				{
					BX_TRACE("Disconnect %d - Receive failed", m_handle);
					disconnect(DisconnectReason::RecvFailed);
					return;
				}
				else if (result == SocketResult::OK && 0 == bytes)
				{
					BX_TRACE("Disconnect %d - Host closed connection.", m_handle);
					disconnect(DisconnectReason::HostClosed);
					return;
				}

				if (m_raw)
				{
					for (Message* msg = m_outgoing.peek(); NULL != msg; msg = m_outgoing.peek() )
					{
						Internal::Enum id = Internal::Enum(*(msg->data - 2) );
						if (Internal::None != id)
						{
							if (!processInternalAndRelease(id, msg) )
							{
								return;
							}
						}
						else if (!sendAndRelease(msg, 0, msg->size))
						{
							return;
						}

						m_outgoing.pop();
					}
				}
				else
				{
					for (Message* msg = m_outgoing.peek(); NULL != msg; msg = m_outgoing.peek() )
					{
						Internal::Enum id = Internal::Enum(*(msg->data - 2) );
						if (Internal::None != id)
						{
							*( (uint16_t*)msg->data - 1) = msg->size;
							if (!processInternalAndRelease(id, msg) )
							{
								return;
							}
						}
							else
							{
								*( (uint16_t*)msg->data - 1) = bx::toLittleEndian(msg->size);
								if (!sendAndRelease(msg, -2, msg->size+2))
								{
									return;
								}
						}

						m_outgoing.pop();
					}
				}
			}
		}

		bool processInternalAndRelease(Internal::Enum _id, Message* _msg)
		{
			switch (_id)
			{
			case Internal::Disconnect:
				{
					Message* msg = msgAlloc(_msg->handle, 2, true);
					msg->data[0] = 0;
					msg->data[1] = Internal::Disconnect;
					ctxPush(msg);

					BX_TRACE("Disconnect %d - Client closed connection (finish).", m_handle);
					disconnect();
				}
				release(_msg);
				return false;

			case Internal::Notify:
				{
					Message* msg = msgAlloc(_msg->handle, _msg->size+1, true);
					msg->data[0] = MessageId::Notify;
					memcpy(&msg->data[1], _msg->data, _msg->size);
					ctxPush(msg);
				}
				release(_msg);
				return true;

			default:
				break;
			}

			BX_CHECK(false, "You shoud not be here!");
			return true;
		}

		bool updateHandshake()
		{
			if (!m_handshake)
			{
				return true;
			}

			uint64_t now = bx::getHPCounter();
			if (now > m_handshakeTimeout)
			{
				BX_TRACE("Disconnect %d - Connect timeout.", m_handle);
				ctxPush(m_handle, MessageId::ConnectFailed);
				disconnect();
				return false;
			}

			SocketResult::Enum result = socketHandshake(m_handle);
			if (result == SocketResult::Failure)
			{
				BX_TRACE("Disconnect %d - Connect failed.", m_handle.idx);
				ctxPush(m_handle, MessageId::ConnectFailed);
				disconnect();
				return false;
			}


			m_handshake = (result == SocketResult::WouldBlock);
			return !m_handshake;
		}

		bool sendAndRelease(bnet::Message* _msg, int32_t _offset, uint32_t _size)
		{
			SocketResult::Enum result = socketSendAndRelease(m_handle, _msg, _offset, _size);
			if (result != SocketResult::OK)
			{
				BX_TRACE("Disconnect %d - Send failed.", m_handle);
				disconnect(DisconnectReason::SendFailed);
				return false;
			}

			return true;
		}

		uint64_t m_handshakeTimeout;
		Handle m_handle;
		uint8_t* m_incomingBuffer;
		bx::RingBufferControl m_incoming;
		RecvRingBuffer m_recv;
		MessageQueue m_outgoing;

		int m_len;
		bool m_raw;
		bool m_handshake;
	};

	typedef FreeList<Connection> Connections;

	class ListenSocket
	{
	public:
		ListenSocket()
			: m_handle(invalidHandle)
			, m_raw(false)
		{
		}

		~ListenSocket()
		{
			close();
		}

		void close()
		{
			socketListenClose(m_handle);
		}

		void listen(Handle _handle, uint32_t _ip, uint16_t _port, bool _raw, const char* _cert, const char* _key)
		{
			m_handle = _handle;
			m_raw = _raw;

			SocketResult::Enum result = socketListen(_handle, _ip, _port, _cert, _key);
			if (result == SocketResult::Failure)
			{
				BX_TRACE("Listen socket failed.");
				ctxPush(m_handle, MessageId::ListenFailed);
			}
		}

		void update()
		{
			SocketResult::Enum result = socketListenHasPending(m_handle);
			if (result == SocketResult::OK)
			{
				ctxAccept(m_handle, m_raw);
			}
		}

	private:
		Handle m_handle;
		bool m_raw;
	};

	typedef FreeList<ListenSocket> ListenSockets;

	class Context
	{
	public:
		Context()
			: m_connections(NULL)
			, m_listenSockets(NULL)
		{
		}

		~Context()
		{
		}

		void init(uint16_t _maxConnections, uint16_t _maxListenSockets, const char* _certs[])
		{
			socketInit(_maxConnections, _maxListenSockets, _certs);

			_maxConnections = _maxConnections == 0 ? 1 : _maxConnections;

			m_connections = BX_NEW(g_allocator, Connections)(_maxConnections);

			if (0 != _maxListenSockets)
			{
				m_listenSockets = BX_NEW(g_allocator, ListenSockets)(_maxListenSockets);
			}
		}

		void shutdown()
		{
			for (Message* msg = m_incoming.pop(); NULL != msg; msg = m_incoming.pop() )
			{
				release(msg);
			}

			BX_DELETE(g_allocator, m_connections);

			if (NULL != m_listenSockets)
			{
				BX_DELETE(g_allocator, m_listenSockets);
			}

			socketShutdown();
		}

		Handle listen(uint32_t _ip, uint16_t _port, bool _raw, const char* _cert, const char* _key)
		{
			ListenSocket* listenSocket = m_listenSockets->create();
			if (NULL != listenSocket)
			{
				Handle handle = { m_listenSockets->getHandle(listenSocket) };
				listenSocket->listen(handle, _ip, _port, _raw, _cert, _key);
				return handle;
			}

			return invalidHandle;
		}

		void stop(Handle _handle)
		{
			ListenSocket* listenSocket = { m_listenSockets->getFromHandle(_handle.idx) };
			listenSocket->close();
			m_listenSockets->destroy(listenSocket);
		}

		Handle accept(Handle _listenHandle, bool _raw)
		{
			Connection* connection = m_connections->create();
			if (NULL != connection)
			{
				Handle handle = { m_connections->getHandle(connection) };
				connection->accept(handle, _listenHandle, _raw);
				return handle;
			}

			return invalidHandle;
		}

		Handle connect(uint32_t _ip, uint16_t _port, bool _raw, bool _secure)
		{
			Connection* connection = m_connections->create();
			if (NULL != connection)
			{
				Handle handle = { m_connections->getHandle(connection) };
				connection->connect(handle, _ip, _port, _raw, _secure);
				return handle;
			}

			return invalidHandle;
		}

		void disconnect(Handle _handle, bool _finish)
		{
			BX_CHECK(_handle.idx < m_connections->getMaxHandles(), "Invalid handle %d!", _handle.idx);

			Connection* connection = { m_connections->getFromHandle(_handle.idx) };
			if (_finish
			&&  connection->hasSocket() )
			{
				Message* msg = msgAlloc(_handle, 0, false, Internal::Disconnect);
				connection->send(msg);
			}
			else
			{
				BX_TRACE("Disconnect %d - Client closed connection.", _handle);
				connection->disconnect();

				Message* msg = msgAlloc(_handle, 2, true);
				msg->data[0] = 0;
				msg->data[1] = Internal::Disconnect;
				ctxPush(msg);
			}
		}

		void notify(Handle _handle, uint64_t _userData)
		{
			BX_CHECK(_handle.idx == invalidHandle.idx // loopback
			      || _handle.idx < m_connections->getMaxHandles(), "Invalid handle %d!", _handle.idx);

			if (invalidHandle.idx != _handle.idx)
			{
				Message* msg = msgAlloc(_handle, sizeof(_userData), false, Internal::Notify);
				memcpy(msg->data, &_userData, sizeof(_userData) );
				Connection* connection = m_connections->getFromHandle(_handle.idx);
				connection->send(msg);
			}
			else
			{
				// loopback
				Message* msg = msgAlloc(_handle, sizeof(_userData)+1, true);
				msg->data[0] = MessageId::Notify;
				memcpy(&msg->data[1], &_userData, sizeof(_userData) );
				ctxPush(msg);
			}
		}

		void send(Message* _msg)
		{
			BX_CHECK(_msg->handle.idx == invalidHandle.idx // loopback
			      || _msg->handle.idx < m_connections->getMaxHandles(), "Invalid handle %d!", _msg->handle.idx);

			if (invalidHandle.idx != _msg->handle.idx)
			{
				Connection* connection = m_connections->getFromHandle(_msg->handle.idx);
				connection->send(_msg);
			}
			else
			{
				// loopback
				push(_msg);
			}
		}

		Message* recv()
		{
			if (NULL != m_listenSockets)
			{
				for (uint16_t ii = 0, num = m_listenSockets->getNumHandles(); ii < num; ++ii)
				{
					ListenSocket* listenSocket = m_listenSockets->getFromHandleAt(ii);
					listenSocket->update();
				}
			}

			for (uint32_t ii = 0, num = m_connections->getNumHandles(); ii < num; ++ii)
			{
				Connection* connection = m_connections->getFromHandleAt(ii);
				connection->update();
			}

			Message* msg = m_incoming.pop();

			while (NULL != msg)
			{
				if (invalidHandle.idx == msg->handle.idx) // loopback
				{
					return msg;
				}

				Connection* connection = m_connections->getFromHandle(msg->handle.idx);

				uint8_t id = msg->data[0];
				if (0 == id
				&&  Internal::Disconnect == msg->data[1])
				{
					m_connections->destroy(connection);
				}
				else if (connection->hasSocket() || MessageId::UserDefined > id)
				{
					return msg;
				}

				release(msg);
				msg = m_incoming.pop();
			}

			return msg;
		}

		void push(Message* _msg)
		{
			m_incoming.push(_msg);
		}

	private:
		Connections* m_connections;
		ListenSockets* m_listenSockets;

		MessageQueue m_incoming;
	};

	static Context s_ctx;
	
	Handle ctxAccept(Handle _listenHandle, bool _raw)
	{
		return s_ctx.accept(_listenHandle, _raw);
	}

	void ctxPush(Handle _handle, MessageId::Enum _id)
	{
		Message* msg = msgAlloc(_handle, 1, true);
		msg->data[0] = _id;
		s_ctx.push(msg);
	}

	void ctxPush(Message* _msg)
	{
		s_ctx.push(_msg);
	}

	Message* msgAlloc(Handle _handle, uint16_t _size, bool _incoming, Internal::Enum _type)
	{
		uint16_t offset = _incoming ? 0 : 2;
		Message* msg = (Message*)BX_ALLOC(g_allocator, sizeof(Message) + offset + _size);
		msg->size = _size;
		msg->handle = _handle;
		uint8_t* data = (uint8_t*)msg + sizeof(Message);
		data[0] = _type;
		msg->data = data + offset;
		return msg;
	}

	void msgRelease(Message* _msg)
	{
		BX_FREE(g_allocator, _msg);
	}

	void init(uint16_t _maxConnections, uint16_t _maxListenSockets, const char* _certs[], bx::ReallocatorI* _allocator)
	{
		if (NULL != _allocator)
		{
			g_allocator = _allocator;
		}

#if BX_PLATFORM_WINDOWS || BX_PLATFORM_XBOX360
		WSADATA wsaData;
		WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif // BX_PLATFORM_WINDOWS || BX_PLATFORM_XBOX360

		s_ctx.init(_maxConnections, _maxListenSockets, _certs);
	}

	void shutdown()
	{
		s_ctx.shutdown();

#if BX_PLATFORM_WINDOWS || BX_PLATFORM_XBOX360
		WSACleanup();
#endif // BX_PLATFORM_WINDOWS || BX_PLATFORM_XBOX360
	}

	Handle listen(uint32_t _ip, uint16_t _port, bool _raw, const char* _cert, const char* _key)
	{
		return s_ctx.listen(_ip, _port, _raw, _cert, _key);
	}

	void stop(Handle _handle)
	{
		return s_ctx.stop(_handle);
	}

	Handle connect(uint32_t _ip, uint16_t _port, bool _raw, bool _secure)
	{
		return s_ctx.connect(_ip, _port, _raw, _secure);
	}

	void disconnect(Handle _handle, bool _finish)
	{
		s_ctx.disconnect(_handle, _finish);
	}

	void notify(Handle _handle, uint64_t _userData)
	{
		s_ctx.notify(_handle, _userData);
	}

	OutgoingMessage* alloc(Handle _handle, uint16_t _size)
	{
		return msgAlloc(_handle, _size);
	}

	void release(IncomingMessage* _msg)
	{
		msgRelease(_msg);
	}

	void send(OutgoingMessage* _msg)
	{
		s_ctx.send(_msg);
	}

	IncomingMessage* recv()
	{
		return s_ctx.recv();
	}

	uint32_t toIpv4(const char* _addr)
	{
		uint32_t a0, a1, a2, a3;
		char dummy;
		if (4 == sscanf(_addr, "%d.%d.%d.%d%c", &a0, &a1, &a2, &a3, &dummy)
		&&  a0 <= 0xff
		&&  a1 <= 0xff
		&&  a2 <= 0xff
		&&  a3 <= 0xff)
		{
			return (a0<<24) | (a1<<16) | (a2<<8) | a3;
		}

		uint32_t ip;
		SocketResult::Enum result = socketResolveIPv4(_addr, &ip);
		if (result == SocketResult::OK)
		{
			return ip;
		}

		return 0;
	}

} // namespace bnet
