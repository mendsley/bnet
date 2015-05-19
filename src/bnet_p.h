/*
 * Copyright 2010-2015 Branimir Karadzic. All rights reserved.
 * License: http://www.opensource.org/licenses/BSD-2-Clause
 */

#ifndef BNET_P_H_HEADER_GUARD
#define BNET_P_H_HEADER_GUARD

#include "bnet.h"
#include "bnet_socket.h"

#include "config.h"
#include <bx/debug.h>
#include <bx/handlealloc.h>
#include <bx/ringbuffer.h>
#include <bx/timer.h>
#include <bx/allocator.h>

#include <new> // placement new
#include <stdio.h> // sscanf

#include <list>

namespace bnet
{
	struct Internal
	{
		enum Enum
		{
			None,
			Disconnect,
			Notify,
		};
	};

	extern bx::ReallocatorI* g_allocator;

	Handle ctxAccept(Handle _listenHandle, bool _raw);
	void ctxPush(Handle _handle, MessageId::Enum _id);
	void ctxPush(Message* _msg);
	Message* msgAlloc(Handle _handle, uint16_t _size, bool _incoming = false, Internal::Enum _type = Internal::None);
	void msgRelease(Message* _msg);

	template<typename Ty>
	class FreeList
	{
	public:
		FreeList(uint16_t _max)
		{
			m_memBlock = BX_ALLOC(g_allocator, _max*sizeof(Ty) );
			m_handleAlloc = bx::createHandleAlloc(g_allocator, _max);
		}

		~FreeList()
		{
			bx::destroyHandleAlloc(g_allocator, m_handleAlloc);
			BX_FREE(g_allocator, m_memBlock);
		}

		Ty* create()
		{
			Ty* first = reinterpret_cast<Ty*>(m_memBlock);
			Ty* obj = &first[m_handleAlloc->alloc()];
			obj = ::new (obj) Ty;
			return obj;
		}

		template<typename Arg0> Ty* create(Arg0 _a0)
		{
			Ty* first = reinterpret_cast<Ty*>(m_memBlock);
			Ty* obj = &first[m_handleAlloc->alloc()];
			obj = ::new (obj) Ty(_a0);
			return obj;
		}

		template<typename Arg0, typename Arg1> Ty* create(Arg0 _a0, Arg1 _a1)
		{
			Ty* first = reinterpret_cast<Ty*>(m_memBlock);
			Ty* obj = &first[m_handleAlloc->alloc()];
			obj = ::new (obj) Ty(_a0, _a1);
			return obj;
		}

		template<typename Arg0, typename Arg1, typename Arg2> Ty* create(Arg0 _a0, Arg1 _a1, Arg2 _a2)
		{
			Ty* first = reinterpret_cast<Ty*>(m_memBlock);
			Ty* obj = &first[m_handleAlloc->alloc()];
			obj = ::new (obj) Ty(_a0, _a1, _a2);
			return obj;
		}

		void destroy(Ty* _obj)
		{
			_obj->~Ty();
			m_handleAlloc->free(getHandle(_obj) );
		}

		uint16_t getHandle(Ty* _obj) const
		{
			Ty* first = reinterpret_cast<Ty*>(m_memBlock);
			return (uint16_t)(_obj - first);
		}

		Ty* getFromHandle(uint16_t _index)
		{
			Ty* first = reinterpret_cast<Ty*>(m_memBlock);
			return &first[_index];
		}

		uint16_t getNumHandles() const
		{
			return m_handleAlloc->getNumHandles();
		}

		uint16_t getMaxHandles() const
		{
			return m_handleAlloc->getMaxHandles();
		}

		Ty* getFromHandleAt(uint16_t _at)
		{
			uint16_t handle = m_handleAlloc->getHandleAt(_at);
			return getFromHandle(handle);
		}

	private:
		void* m_memBlock;
		bx::HandleAlloc* m_handleAlloc;
	};

	class RecvRingBuffer
	{
		BX_CLASS(RecvRingBuffer
			, NO_COPY
			, NO_ASSIGNMENT
			);

	public:
		RecvRingBuffer(bx::RingBufferControl& _control, char* _buffer)
			: m_control(_control)
			, m_write(_control.m_current)
			, m_reserved(0)
			, m_buffer(_buffer)
		{
		}

		~RecvRingBuffer()
		{
		}

		SocketResult::Enum recv(Handle _handle, uint32_t* _bytes)
		{
			m_reserved += m_control.reserve(UINT32_MAX);
			uint32_t end = (m_write + m_reserved) % m_control.m_size;
			uint32_t wrap = end < m_write ? m_control.m_size - m_write : m_reserved;
			char* to = &m_buffer[m_write];

			uint32_t bytes;
			SocketResult::Enum result = socketRecv(_handle, &bytes, to, wrap);

			if (result == SocketResult::OK)
			{
				m_write += bytes;
				m_write %= m_control.m_size;
				m_reserved -= bytes;
				m_control.commit(bytes);
			}

			*_bytes = bytes;
			return result;
		}

	private:
		RecvRingBuffer();

		bx::RingBufferControl& m_control;
		uint32_t m_write;
		uint32_t m_reserved;
		char* m_buffer;
	};

	class MessageQueue
	{
	public:
		MessageQueue()
		{
		}

		~MessageQueue()
		{
		}

		void push(Message* _msg)
		{
			m_queue.push_back(_msg);
		}

		Message* peek()
		{
			if (!m_queue.empty() )
			{
				return m_queue.front();
			}

			return NULL;
		}

		Message* pop()
		{
			if (!m_queue.empty() )
			{
				Message* msg = m_queue.front();
				m_queue.pop_front();
				return msg;
			}

			return NULL;
		}

	private:
		std::list<Message*> m_queue;
	};

} // namespace bnet

#endif // BNET_P_H_HEADER_GUARD
