/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2018 Haivision Systems Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#include "platform_sys.h"

#include <cstring>

#ifndef _WIN32
#include <unistd.h>
#endif

#include "external.h"

using namespace srt::sync;

SRT_EXTERNAL::SRT_EXTERNAL(int wake_fd)
    : m_iRefs(1)
    , m_iWakeFd(wake_fd)
    , m_pInbound(new Slot[INBOUND])
    , m_uInHead(0)
    , m_uInTail(0)
    , m_bAsleep(false)
    , m_uInPending(0)
    , m_pOutbound(new Slot[OUTBOUND])
    , m_uOutHead(0)
    , m_uOutTail(0)
{
    setupMutex(m_SleepLock, "ExternalSleep");
    setupCond(m_Wakeup, "ExternalWakeup");
    setupMutex(m_OutLock, "ExternalOut");
}

SRT_EXTERNAL::~SRT_EXTERNAL()
{
    releaseMutex(m_OutLock);
    releaseCond(m_Wakeup);
    releaseMutex(m_SleepLock);
    delete[] m_pOutbound;
    delete[] m_pInbound;
#ifndef _WIN32
    ::close(m_iWakeFd);
#endif
}

void SRT_EXTERNAL::release()
{
    if (--m_iRefs == 0)
        delete this;
}

bool SRT_EXTERNAL::push(const sockaddr* from, const char* data, int len)
{
    if (len < 0 || len > SRT_EXTERNAL_MAX_DATAGRAM)
        return false;
    if (m_uInPending - m_uInTail.load() >= INBOUND)
        return false;

    Slot& slot = m_pInbound[m_uInPending % INBOUND];
    slot.addr.set(from);
    slot.len = len;
    memcpy(slot.data, data, len);
    ++m_uInPending;
    return true;
}

void SRT_EXTERNAL::flush()
{
    m_uInHead.store(m_uInPending);
    // Pairs with recv(): it says it's asleep and then looks at the head, this
    // moves the head and then looks if it's asleep, so one of them notices.
    if (m_bAsleep.load())
    {
        ScopedLock lock(m_SleepLock);
        m_Wakeup.notify_one();
    }
}

int SRT_EXTERNAL::pop(sockaddr_storage* to, char* data, int cap)
{
    ScopedLock lock(m_OutLock);
    if (m_uOutHead == m_uOutTail)
        return 0;

    Slot& slot = m_pOutbound[m_uOutTail++ % OUTBOUND];
    if (slot.len > cap)
        return -1;
    memcpy(to, slot.addr.get(), slot.addr.size());
    memcpy(data, slot.data, slot.len);
    return slot.len;
}

bool SRT_EXTERNAL::recv(srt::sockaddr_any& w_from, char* header, size_t header_size, char* data, size_t& w_len)
{
    const unsigned tail = m_uInTail.load();
    if (m_uInHead.load() == tail)
    {
        UniqueLock lock(m_SleepLock);
        m_bAsleep.store(true);
        if (m_uInHead.load() == tail)
            m_Wakeup.wait_for(lock, milliseconds_from(10));
        m_bAsleep.store(false);
        if (m_uInHead.load() == tail)
            return false;
    }

    const Slot&  slot = m_pInbound[tail % INBOUND];
    const size_t len  = size_t(slot.len);
    const bool   fits = len >= header_size && len - header_size <= w_len;
    if (fits)
    {
        w_from.set(slot.addr.get());
        memcpy(header, slot.data, header_size);
        w_len = len - header_size;
        memcpy(data, slot.data + header_size, w_len);
    }
    m_uInTail.store(tail + 1);
    return fits;
}

int SRT_EXTERNAL::send(const srt::sockaddr_any& to, const char* header, size_t header_size, const char* data, size_t len)
{
    const size_t size = header_size + len;
    if (size > SRT_EXTERNAL_MAX_DATAGRAM)
        return -1;

    bool wake = false;
    {
        ScopedLock lock(m_OutLock);
        // As with a full socket buffer: SRT recovers from it.
        if (m_uOutHead - m_uOutTail >= OUTBOUND)
            return -1;
        wake = m_uOutHead == m_uOutTail;

        Slot& slot = m_pOutbound[m_uOutHead % OUTBOUND];
        slot.addr  = to;
        slot.len   = int(size);
        memcpy(slot.data, header, header_size);
        if (len)
            memcpy(slot.data + header_size, data, len);
        ++m_uOutHead;
    }

#ifndef _WIN32
    if (wake)
    {
        const uint64_t one = 1;
        (void)!::write(m_iWakeFd, &one, sizeof one);
    }
#else
    (void)wake;
#endif
    return int(size);
}
