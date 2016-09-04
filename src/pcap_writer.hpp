#pragma once

#include <cstdint>

#define PP_STR2(str) #str
#define PP_STR(str) PP_STR2(str)
#define handle_error(msg) \
       do { perror(__FILE__ ":" PP_STR(__LINE__) ":\n\t" msg); exit(EXIT_FAILURE); } while (0)



// https://wiki.wireshark.org/Development/LibpcapFileFormat

struct pcap_packet_header {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

struct pcap_file_header {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;	/* gmt to local time correction */
    uint32_t sigfigs;	/* accuracy of timestamps */
    uint32_t snaplen;	/* max length saved portion of each pkt */
    uint32_t linktype;	/* data link type (LINKTYPE_*) */
};

static_assert(sizeof(pcap_packet_header) == 16, "");
static_assert(sizeof(pcap_file_header) == 24, "");


uint8_t* write_pcap_header(uint8_t* memory) noexcept {
    reinterpret_cast<pcap_file_header*>(memory)->magic = 0xa1b2c3d4;
    reinterpret_cast<pcap_file_header*>(memory)->version_major = 2;
    reinterpret_cast<pcap_file_header*>(memory)->version_minor = 4;
    reinterpret_cast<pcap_file_header*>(memory)->thiszone = 0;
    reinterpret_cast<pcap_file_header*>(memory)->sigfigs = 0;
    reinterpret_cast<pcap_file_header*>(memory)->snaplen = UINT32_MAX;
    reinterpret_cast<pcap_file_header*>(memory)->linktype = 1;

    return memory + sizeof(pcap_file_header);
}

class pcap_writer {
public:
    pcap_writer(const std::string path = "./") : fd(-1) { init(path); }

    ~pcap_writer() { close(); }

    void init(const std::string path, const size_t size_hint = 1024ULL * 1024ULL * 256ULL) {
        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::stringstream file_name;
        file_name << path.c_str() << "QQ_" << std::put_time(std::localtime(&now), "%FT%TZ%z") << ".pcap";
        //fd = ::open(file_name.str().c_str(), O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
		fd = ::open(file_name.str().c_str(), O_CREAT | O_RDWR | O_TRUNC | O_DIRECT | O_SYNC, S_IRUSR | S_IWUSR);
        if (fd == -1)
            handle_error("open");
        allocated_size = size_hint;
        if (::fallocate(fd, 0, 0, allocated_size))
            handle_error("fallocate");
        //void* ptr = ::mmap(NULL, allocated_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		void* ptr = ::mmap(NULL, allocated_size, PROT_WRITE, MAP_SHARED | MAP_NORESERVE, fd, 0);
        if (ptr == MAP_FAILED)
            handle_error("mmap");
        backend = (uint8_t*) ptr;
        cursor = write_pcap_header(backend);
    }

    void close() {
#ifndef NDEBUG
		std::cout << "[pcap] closing" << std::endl;
#endif
        if (::ftruncate(fd, cursor - backend)) //!< truncate to actually used size. See: resize()
            handle_error("ftruncate");
        if (::fsync(fd))
            handle_error("fsync");
        if (::close(fd))
            handle_error("close");
        fd = -1;
        if (::msync(backend, allocated_size, MS_SYNC))
		//if (::msync(backend, allocated_size, MS_ASYNC))
            handle_error("msync");
        if (::munmap(backend, allocated_size))
            handle_error("munmap");
        backend = nullptr;
        cursor = nullptr;
        allocated_size = 0;
    }

    inline void resize(const size_t new_size) noexcept {
#ifndef NDEBUG
        std::cout << "[pcap] resizing from " << allocated_size << " to " << new_size << std::endl;
#endif
        // TODO: investigate if syncing (writing out to HDD) early helps or hinders performance
        if (::msync(backend, allocated_size, MS_SYNC))
            handle_error("msync");
        if (::fallocate(fd, 0, 0, new_size))
            handle_error("fallocate");
        void* ptr = ::mremap(backend, allocated_size, new_size, MREMAP_MAYMOVE);
        if (ptr == MAP_FAILED)
            handle_error("mremap");
        auto distance = cursor - backend; //!< backup cursor because of mremap's MAYMOVE. Mitigation: make cursor relative to backend, not absolute
        backend = (uint8_t*) ptr;
        cursor = backend + distance; //!< restore original cursor offset
        allocated_size = new_size;
    }

    inline void store(const uint64_t timestamp, const uint32_t len, const uint8_t* data) noexcept {
        if ((cursor - backend) + sizeof(pcap_packet_header) + len >= allocated_size) {
            resize(allocated_size * 2); //!< double size, something something O(log(n))
        }

        reinterpret_cast<pcap_packet_header*>(cursor)->ts_sec = (uint32_t) timestamp / 1000000; // FIXME: find correct conversion
        reinterpret_cast<pcap_packet_header*>(cursor)->ts_usec = (uint32_t) timestamp % 1000000;
        reinterpret_cast<pcap_packet_header*>(cursor)->incl_len = len;
        reinterpret_cast<pcap_packet_header*>(cursor)->orig_len = len;
        cursor += sizeof(pcap_packet_header);

        memcpy(cursor, data, len);
        cursor += len;
		
		/*
		if ((cursor - backend) - old_diff > 1024LL * 1024LL * 32LL) {
			std::cout << ".";
			if (::msync(backend, allocated_size, MS_SYNC))
				handle_error("msync");
			old_diff = cursor - backend;
		}
		*/
    }

private:
    uint8_t* backend;
    uint8_t* cursor;
    size_t old_diff = 0;
    int fd;
    size_t allocated_size;
};
