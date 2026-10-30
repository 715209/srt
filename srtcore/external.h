/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2018 Haivision Systems Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 */

#ifndef INC_SRT_EXTERNAL_H
#define INC_SRT_EXTERNAL_H

#include "atomic.h"
#include "netinet_any.h"
#include "srt.h"
#include "sync.h"

// Datagrams on their way between a multiplexer and the application running
// its transport (see srt_external_attach). They are bytes in network order,
// as on the wire, so nothing above CChannel can tell them from recvmsg's.
//
// Inbound is a single-producer, single-consumer ring: the application pushes,
// CRcvQueue::worker takes. Outbound is sent from several libsrt threads, so
// it's a ring under a mutex, and the application pops.
//
// The channel and the application each hold a reference, so either can go
// first: a multiplexer outlives srt_close() by an unknown time, and whatever
// the application pushes after that fills the ring and is refused.
struct SRT_EXTERNAL
{
    // Takes over `wake_fd`, which is written to whenever outbound stops being
    // empty.
    explicit SRT_EXTERNAL(int wake_fd);

    void retain() { ++m_iRefs; }
    void release();

    // Application's side, all on one thread.
    bool push(const sockaddr* from, const char* data, int len);
    void flush();
    int  pop(sockaddr_storage* to, char* data, int cap);

    // Channel's side. Waits up to 10ms, as CChannel::recvfrom does, because
    // the worker's timers depend on it. `w_len` is the room in `data` on
    // input and what was put there on return. False: nothing was received.
    bool recv(srt::sockaddr_any& w_from, char* header, size_t header_size, char* data, size_t& w_len);
    int  send(const srt::sockaddr_any& to, const char* header, size_t header_size, const char* data, size_t len);

private:
    struct Slot
    {
        srt::sockaddr_any addr;
        int               len;
        char              data[SRT_EXTERNAL_MAX_DATAGRAM];
    };

    ~SRT_EXTERNAL();
    SRT_EXTERNAL(const SRT_EXTERNAL&);
    SRT_EXTERNAL& operator=(const SRT_EXTERNAL&);

    // Packets a burst may be ahead of the worker. At 100k packets a second
    // that's 80ms, about what a socket's 8 MiB receive buffer holds.
    static const unsigned INBOUND = 8192;
    // Control packets only: ACKs, NAKs and handshakes.
    static const unsigned OUTBOUND = 1024;

    srt::sync::atomic<int> m_iRefs;
    int                    m_iWakeFd;

    Slot*                       m_pInbound;
    srt::sync::atomic<unsigned> m_uInHead; // Published by flush().
    char                        m_Pad1[64];
    srt::sync::atomic<unsigned> m_uInTail;
    char                        m_Pad2[64];
    srt::sync::atomic<bool>     m_bAsleep;
    char                        m_Pad3[64];
    unsigned                    m_uInPending; // Pushed, not published yet.

    srt::sync::Mutex     m_SleepLock;
    srt::sync::Condition m_Wakeup;

    srt::sync::Mutex m_OutLock;
    Slot*            m_pOutbound;
    unsigned         m_uOutHead;
    unsigned         m_uOutTail;
};

#endif
