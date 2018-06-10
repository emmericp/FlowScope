#include <rte_config.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>

#include "QQ.hpp"
#include "lifecycle.hpp"

constexpr size_t bucket_size 		= 8;	// bucket size in 2 MiB pages, pick something between 4 and 32 (8 MiB - 64 MiB)

namespace QQ {
	static inline void inserter_loop(uint8_t port_id, uint16_t queue_id, QQ<bucket_size>* qq) {
		constexpr size_t batchsize = 64;
		
		const uint64_t tsc_hz = rte_get_tsc_hz();              //!< cycles per second
		const double tsc_hz_usec = tsc_hz / (1000.0 * 1000.0); //!< cycles per microsecond
		
		auto enq_ptr = qq->enqueue();
		struct rte_mbuf* bufs[batchsize] __rte_cache_aligned;
		
		while (libmoon::is_running(0)) {
			uint16_t rx_cnt = rte_eth_rx_burst(port_id, queue_id, bufs, batchsize);
			
			if (rx_cnt == 0) {
				rte_delay_us(2); // taken from dpdk example bond/main
			}
			
			// we need the floating point op, tsc / (tsc_hz / 10^6) is too imprecise
			// (and tsc * 10^6 overflows after a few hours)
			uint64_t timestamp_batch = (uint64_t) (rte_rdtsc() / tsc_hz_usec);
			
			for (uint16_t i = 0; i < rx_cnt; ++i) {
				while (!enq_ptr.store(
					timestamp_batch,
					// vlan
					bufs[i]->ol_flags & PKT_RX_VLAN_PKT ? bufs[i]->vlan_tci & 0xFFF : 0,
					rte_pktmbuf_pkt_len(bufs[i]),              // packet length
					rte_pktmbuf_mtod(bufs[i], const uint8_t*)  // packet data
				)) {
					enq_ptr.release();				// Unlock the old one
					enq_ptr = qq->enqueue(); 		// Get a new one
				}
				rte_pktmbuf_free(bufs[i]);
			}
		}
		enq_ptr.release();
		// Attempt to make stray packets eligible for dequeuing after shutdown
		// FIXME: Loop counter should depend on actual number of buckets blocked
		for (int i = 0; i < 30; ++i) {
			auto t = qq->enqueue();
			t.release();
			rte_delay_ms(10);
		}
	}
}

extern "C" {    
	void qq_init() {
		QQ::init();
	}

    QQ::QQ<bucket_size>* qq_create(uint32_t storage_capacity) {
		const size_t num_buckets = (storage_capacity / 2) / bucket_size;
        return new QQ::QQ<bucket_size>(num_buckets);
    }
    
    void qq_delete(QQ::QQ<bucket_size>* q) {
        delete q;
    }
    
    size_t qq_size(const QQ::QQ<bucket_size>* q) {
        return q->size();
    }
    
    
    const QQ::Ptr<bucket_size>* qq_storage_peek(QQ::QQ<bucket_size>* q) {
        auto temp = new QQ::Ptr<bucket_size>(std::move(q->peek()));
        return temp;
    }
    
    const QQ::Ptr<bucket_size>* qq_storage_dequeue(QQ::QQ<bucket_size>* q) {
		auto c = new QQ::Ptr<bucket_size>(std::move(q->dequeue()));
        return c;
    }

    const QQ::Ptr<bucket_size>* qq_storage_try_dequeue(QQ::QQ<bucket_size>* q) {
        return q->try_dequeue();
    }
    
    const QQ::Ptr<bucket_size>* qq_storage_try_peek(QQ::QQ<bucket_size>* q) {
        return q->try_peek();
    }

    const QQ::Ptr<bucket_size>* qq_storage_enqueue(QQ::QQ<bucket_size>* q) {
        auto c = new QQ::Ptr<bucket_size>(std::move(q->enqueue()));
        return c;
    }
    
    void qq_storage_release(QQ::Ptr<bucket_size>* ptr) {
		delete ptr; // dtor unlocks the storage mutex
    }
    
    size_t qq_storage_size(QQ::Ptr<bucket_size>* ptr) {
        return ptr->size();
    }
    
    size_t qq_get_enqueue_counter(QQ::QQ<bucket_size>* q) {
        return q->get_enqueue_counter();
    }
    
    size_t qq_get_dequeue_counter(QQ::QQ<bucket_size>* q) {
        return q->get_dequeue_counter();
    }
    
    size_t qq_get_enqueue_overflow_counter(QQ::QQ<bucket_size>* q) {
        return q->get_enqueue_overflow_counter();
    }
    
    void qq_set_priority(QQ::QQ<bucket_size>* q, const uint8_t new_priority) {
        return q->set_priority(new_priority);
    }
    
    const QQ::packet_header& qq_storage_get_packet(QQ::Ptr<bucket_size>* ptr, const size_t idx) {
        return (const QQ::packet_header&) *ptr->operator[](idx);
    }
    
    bool qq_storage_store(QQ::Ptr<bucket_size>* ptr,
						  uint64_t ts,
						  uint16_t vlan,
						  uint16_t len,
						  const uint8_t* data) {
		return ptr->store(ts, vlan, len, data);
    }
    
    void dummy_enqueue(QQ::QQ<bucket_size>* q) {
        auto ptr = q->enqueue();
        uint8_t data[64] = {55};
        memset(data, 55, 64);
        ptr.store(123456789, 4095, 64, data);
    }
    
    
    uint64_t qq_packet_header_get_timestamp(QQ::packet_header* h) {
        return h->timestamp;
    }
    
    uint64_t qq_packet_header_get_vlan(QQ::packet_header* h) {
        return h->vlan;
    }
    
    uint16_t qq_packet_header_get_len(QQ::packet_header* h) {
        return h->len;
    }
    
    const uint8_t* qq_packet_header_get_data(QQ::packet_header* h) {
        return h->data;
    }
 	
	// implemented in C++ for better timestamp precision
    void qq_inserter_loop(uint8_t device, uint16_t queue_id, QQ::QQ<bucket_size>* qq) {
        QQ::inserter_loop(device, queue_id, qq);
    }
    
	size_t qq_capacity(const QQ::QQ<bucket_size>* q) noexcept {
        return q->capacity();
    }
    
}

