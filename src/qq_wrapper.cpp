#include <rte_config.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>

#include "QQ.hpp"
#include "pcap_writer.hpp"
#include "lifecycle.hpp"

constexpr size_t wanted_cap_in_GiB 	= 8;	// total raw capacity, real memory usage will be a bit higher
constexpr size_t bucket_size 		= 8;	// bucket size in 2 MiB pages, pick something between 4 and 32 (8 MiB - 64 MiB)
constexpr size_t num_buckets = (wanted_cap_in_GiB * 512) / bucket_size;

namespace QQ {
	static inline void inserter_loop(uint8_t port_id, uint16_t queue_id, QQ<bucket_size, num_buckets>* qq) {
		constexpr size_t batchsize = 64;
		
		const static uint64_t tsc_hz = rte_get_tsc_hz();			//!< cycles per second
		const static uint64_t tsc_hz_usec = tsc_hz / (1000 * 1000);	//!< cycles per microsecond
		
		
		//std::cout << "Port: " << (int) port_id << ", queue_id:" << queue_id << std::endl;
		
		auto enq_ptr = qq->enqueue();
		struct rte_mbuf* bufs[batchsize] __rte_cache_aligned;
		
		uint64_t ctx = 0;
		uint64_t last_ctx = 0;
		uint64_t last_ts = 0;
		
		while (phobos::is_running(0)) {
			//uint64_t ts_0 = _rdtsc();
			uint16_t rx_cnt = rte_eth_rx_burst(port_id, queue_id, bufs, batchsize);
			//uint64_t ts_1 = _rdtsc();
			
			if (rx_cnt == 0) {
				//std::cout << ".";
				//std::cout << "[" << queue_id << "]";
				rte_delay_us(5); // taken from dpdk example bond/main
			}
			
			//std::cout << (ts_1 - ts_0)/rx_cnt << std::endl;
			
			uint64_t timestamp_batch = _rdtsc() / tsc_hz_usec;
			
			/*
			if (ctx % (1ULL<<21) == 0) {
				const uint64_t timestamp = _rdtsc();
				const double diff = (timestamp - last_ts) / static_cast<double>(tsc_hz);
				std::cout << std::fixed << (ctx - last_ctx) / diff << std::endl;
				//std::cout << rx_cnt / ((timestamp_batch - last_ts) / tsc_hz) << std::endl;
				last_ts = timestamp;
				last_ctx = ctx;
			}
			ctx += rx_cnt;
			*/
			
			//uint64_t ts_0 = _rdtsc();
			for (uint64_t i = 0; i < rx_cnt; ++i) {
				
				try_again:
				//std::cout << "["<< rte_ctrlmbuf_len(bufs[i]) << "] ";
				const bool success = enq_ptr.store(
					timestamp_batch,			// timestamp
					// vlan
					bufs[i]->ol_flags & PKT_RX_VLAN_PKT ? bufs[i]->vlan_tci & 0xFFF : 0,
					rte_pktmbuf_pkt_len(bufs[i]),	// packet length
					rte_pktmbuf_mtod(bufs[i], const uint8_t*)  // packet data
				);
				if (!success) {						// The storage is full or held for too long
					//std::cout << "storage full" << std::endl;
					enq_ptr.release();				// Unlock the old one
					enq_ptr = qq->enqueue(); 		// Get a new one
					//std::cout << "got new one" << std::endl;
					goto try_again; 				// Try to store this packet again
				}
				
				rte_pktmbuf_free(bufs[i]);
			}
			//uint64_t ts_1 = _rdtsc();
			//std::cout << (ts_1 - ts_0)/rx_cnt << std::endl;
		}
	}
}

extern "C" {    
	void qq_init() {
		QQ::init();
	}

    QQ::QQ<bucket_size, num_buckets>* qq_create() {
        return new QQ::QQ<bucket_size, num_buckets>();
    }
    
    void qq_delete(QQ::QQ<bucket_size, num_buckets>* q) {
        delete q;
    }
    
    size_t qq_size(const QQ::QQ<bucket_size, num_buckets>* q) {
        return q->size();
    }
    
    
    const QQ::Ptr<bucket_size>* qq_storage_peek(QQ::QQ<bucket_size, num_buckets>* q) {
        auto temp = new QQ::Ptr<bucket_size>(std::move(q->peek()));
        return temp;
    }
    
    const QQ::Ptr<bucket_size>* qq_storage_dequeue(QQ::QQ<bucket_size, num_buckets>* q) {
		auto c = new QQ::Ptr<bucket_size>(std::move(q->dequeue()));
        return c;
    }
    
    const QQ::Ptr<bucket_size>* qq_storage_enqueue(QQ::QQ<bucket_size, num_buckets>* q) {
        auto c = new QQ::Ptr<bucket_size>(std::move(q->enqueue()));
        return c;
    }
    
    void qq_storage_release(QQ::Ptr<bucket_size>* ptr) {
		//std::cout << "release()" << std::endl;
		delete ptr;  // c++ calls the dtor implicitly, which unlocks the storage mutex
    }
    
    size_t qq_storage_size(QQ::Ptr<bucket_size>* ptr) {
        //std::cout << "storage size: " << ptr->size() << std::endl;
        return ptr->size();
    }
    
    
    size_t qq_get_enqueue_counter(QQ::QQ<bucket_size, num_buckets>* q) {
		return q->get_enqueue_counter();
	}
	
	size_t qq_get_dequeue_counter(QQ::QQ<bucket_size, num_buckets>* q) {
		return q->get_dequeue_counter();
	}
	
	void qq_set_priority(QQ::QQ<bucket_size, num_buckets>* q, const uint8_t new_priority) {
		return q->set_priority(new_priority);
	}
    
    const QQ::packet_header& qq_storage_get_packet(QQ::Ptr<bucket_size>* ptr, const size_t idx) {
        //std::cout << "get_packet(" << idx << "): " << ptr->operator[](idx) << std::endl;
        return (const QQ::packet_header&) *ptr->operator[](idx);
    }
    
    bool qq_storage_store(QQ::Ptr<bucket_size>* ptr,
						  uint64_t ts,
						  uint16_t vlan,
						  uint16_t len,
						  const uint8_t* data) {
		return ptr->store(ts, vlan, len, data);
    }
    
    void dummy_enqueue(QQ::QQ<bucket_size, num_buckets>* q) {
        auto ptr = q->enqueue();
        uint8_t data[64] = {55};
        //
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
    
    
    // ############
    
    void qq_inserter_loop(uint8_t device, uint16_t queue_id, QQ::QQ<bucket_size, num_buckets>* qq) {
        QQ::inserter_loop(device, queue_id, qq);
    }
    
    
	size_t qq_capacity(const QQ::QQ<bucket_size, num_buckets>* q) noexcept {
        return q->capacity();
    }
    
    
	
    // #### pcap_writer ####
    pcap_writer* pcap_writer_create(const char* path) {
		if (!path)
			return new pcap_writer();
		else
			return new pcap_writer(path);
	}
    
    void pcap_writer_delete(pcap_writer* pcw) {
		delete pcw;
	}
    
    void pcap_writer_store(pcap_writer* pcw, const uint64_t timestamp, const uint32_t len, const uint8_t* data) {
		pcw->store(timestamp, len, data);
	}
	
}
