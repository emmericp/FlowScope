#pragma once

#include <iostream>
#include <iomanip>
#include <thread>
#include <mutex>
#include <vector>
#include <algorithm>
#include <numeric>
#include <condition_variable>
#include <sys/mman.h>
#include <x86intrin.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <sstream>
#include <memory>


#define PP_STR2(str) #str
#define PP_STR(str) PP_STR2(str)
#define handle_error(msg) \
       do { perror(__FILE__ ":" PP_STR(__LINE__) ":\n\t" msg); exit(EXIT_FAILURE); } while (0)


#if __GNUC__ < 5 && !defined(__clang__)
/* Taken from LLVM libcxx - MIT Licence */
namespace std {
inline void*
align(size_t alignment, size_t size, void*& ptr, size_t& space) noexcept
{
    void* r = nullptr;
    if (size <= space)
    {
        char* p1 = static_cast<char*>(ptr);
        char* p2 = reinterpret_cast<char*>(reinterpret_cast<size_t>(p1 + (alignment - 1)) & -alignment);
        size_t d = static_cast<size_t>(p2 - p1);
        if (d <= space - size)
        {
            r = p2;
            ptr = r;
            space -= d;
        }
    }
    return r;
}
} // namespace std
#endif

namespace QQ {
    template<typename T>
    std::string format_bytes(T bytes, int precision = 2) {
        std::stringstream s;
        s << std::setprecision(precision) << std::fixed;
        if (bytes >= 1ULL << 40)
            s << (1. * bytes / (1ULL << 40)) << " TiB";
        else if (bytes >= 1ULL << 30)
            s << (1. * bytes / (1ULL << 30)) << " GiB";
        else if (bytes >= 1ULL << 20)
            s << (1. * bytes / (1ULL << 20)) << " MiB";
        else if (bytes >= 1ULL << 10)
            s << (1. * bytes / (1ULL << 10)) << " KiB";
        else
            s << bytes << " B";

        return s.str();
    }

    template<typename T>
    std::string format_bits(T bytes, int precision = 2) {
        std::stringstream s;
        s << std::setprecision(precision) << std::fixed;
        if (bytes >= 100000000000ULL)
            s << (8. * bytes / 1000000000000ULL) << " Tbit";
        else if (bytes >= 100000000ULL)
            s << (8. * bytes / 1000000000ULL) << " Gbit";
        else if (bytes >= 100000ULL)
            s << (8. * bytes / 1000000ULL) << " Mbit";
        else if (bytes >= 100ULL)
            s << (8. * bytes / 1000ULL) << " Kbit";
        else
            s << 8. * bytes << " bit";

        return s.str();
    }

    template<typename T>
    std::string format_SI(T num, int precision = 2) {
        std::stringstream s;
        s << std::setprecision(precision) << std::fixed;
        if (num >= 1000000000000ULL)
            s << (1. * num / 1000000000000ULL) << " T";
        else if (num >= 1000000000ULL)
            s << (1. * num / 1000000000ULL) << " G";
        else if (num >= 1000000ULL)
            s << (1. * num / 1000000ULL) << " M";
        else if (num >= 1000ULL)
            s << (1. * num / 1000ULL) << " K";
        else
            s << num;

        return s.str();
    }
}


namespace QQ {
    namespace literals {
        constexpr unsigned long long int operator
        ""

        _KiB(unsigned long long int value) { return value * 1024ULL; }

        constexpr unsigned long long int operator
        ""

        _MiB(unsigned long long int value) { return value * 1024_KiB; }

        constexpr unsigned long long int operator
        ""

        _GiB(unsigned long long int value) { return value * 1024_MiB; }

        constexpr unsigned long long int operator
        ""

        _TiB(unsigned long long int value) { return value * 1024_GiB; }
    }

    constexpr size_t KiB(const size_t value) { return value * 1024ULL; }

    constexpr size_t MiB(const size_t value) { return value * KiB(1024ULL); }

    constexpr size_t GiB(const size_t value) { return value * MiB(1024ULL); }

    constexpr size_t TiB(const size_t value) { return value * GiB(1024ULL); }
}


namespace QQ {
    double CYCLES_PER_SECOND;
    constexpr size_t huge_page_size = 1024ULL * 1024 * 2; //!< 2 MiB

    void init() {
        CYCLES_PER_SECOND = (double) rte_get_tsc_hz();
    }

    //! The struct used to store packets internally.
    /*!
     * More of a metadata header than a real storage struct for packets.
     */
    struct packet_header {
        packet_header() { }

        explicit packet_header(const packet_header& r) : timestamp(r.timestamp), vlan(r.vlan), len(r.len) { }

        explicit packet_header(const uint64_t ts, const uint64_t vlan, const uint16_t len)
                : timestamp(ts), vlan(vlan), len(len) { }

        uint64_t timestamp:48;  //!< Stores a timestamp. Unit is microseconds.
        uint64_t vlan:12;       //!< Field to store the VLAN tag. Prevents messy Ethernet header.
        uint16_t len;           //!< Holds the length of the data array.
        uint8_t data[];         //!< Flexible array member. Valid since C99, not really in C++.
    };

    static_assert(sizeof(packet_header) == 16, "packet_header size mismatch");
    static_assert(alignof(packet_header) == 8, "packet_header alignment mismatch");
    static_assert(offsetof(packet_header, len) == 8, "expected len field at 8th byte");
    static_assert(offsetof(packet_header, data) == 10, "expected len field at 10th byte");
    
    template<size_t storage_cap>
    struct Storage {
        explicit Storage(uint8_t* data) : backend(data), current(data) {
            refs.reserve(storage_cap / 64);
        }

        Storage& operator=(Storage&& other) noexcept {
            std::swap(m_, other.m_);
            backend = other.backend;
            current = other.current;
            refs = std::move(other.refs);

            return *this;
        }

        [[deprecated]] inline bool store(const packet_header& p) noexcept {
            return store(p.timestamp, p.vlan, p.len, p.data);
        }

        inline bool store(const uint64_t timestamp, const uint64_t vlan, const uint16_t length,
                          const uint8_t* data) noexcept {
            // TODO: make the actual value depend on the storage cap and/or expected speed
            auto now = _rdtsc();
            auto diff = now - acquisition;
            if (diff > timeout * CYCLES_PER_SECOND) {
#ifndef NDEBUG
                std::cout << "Hold time too long: " << std::fixed << diff / CYCLES_PER_SECOND << " s , max: " <<
                timeout << " s. Returning false" << std::endl;
#endif
                return false;
            }

            // TODO: Alignment on current and/or new_pkt->data
            size_t space = storage_cap - (current - backend);
            if (!std::align(alignof(packet_header), sizeof(packet_header) + length, (void*&) current, space))
                return false;
            auto new_pkt = new(current) packet_header(timestamp, vlan, length);
            std::memcpy(new_pkt->data, data, length);
            refs.push_back(new_pkt);
            current += sizeof(packet_header) + length;
            return true;
        }

        inline const packet_header* operator[](const size_t idx) const {
            return refs.at(idx);
        }

        // TODO: test if works
        inline void pop_back() noexcept {
            current = (uint8_t*) refs.back();
            refs.pop_back();
        }

        inline void clear() noexcept {
            refs.clear();
            current = (uint8_t*) backend;
        }

        inline std::vector<packet_header*>::const_iterator cbegin() const noexcept {
            return refs.cbegin();
        }

        inline std::vector<packet_header*>::const_iterator cend() const noexcept {
            return refs.cend();
        }

        inline size_t size() const noexcept {
            return refs.size();
        }


        template<size_t storage_size = 8, uint16_t packet_len = 64, bool verbose = true>
        static void perf_test() {
            constexpr uint64_t runs = (1024 * 8) / storage_size;
            constexpr int num_threads = 4;

            std::vector<uint64_t> all_counter(num_threads);

            auto task = [&all_counter](unsigned int thread_id) {
                uint64_t counter = 0;
                uint8_t* bytes;
                if ((bytes = (uint8_t*) mmap(NULL, storage_size * huge_page_size,
                                             PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
                    handle_error("mmap");
                if (madvise(bytes, storage_size * huge_page_size, MADV_HUGEPAGE))
                    handle_error("madvise");
				if (mlock(bytes, storage_size * huge_page_size))
					handle_error("mlock");
                auto packet_data = new uint8_t[packet_len];


                Storage<huge_page_size * storage_size> s(bytes);
                for (auto i = 0ULL; i < runs; ++i) {
                    s.acquisition = _rdtsc();
                    counter = 0;
                    while (s.store(123, 1, packet_len, packet_data)) {
                        ++counter;
                        continue;
                    }
                    if (counter != s.size())
                        std::cerr << "Counter mismatch! Is: " << counter << ", stored: " << s.size() << std::endl;
                    s.clear();
                }

                if (munmap(bytes, storage_size * huge_page_size))
                    handle_error("munmap");
                delete[] packet_data;

                all_counter.at(thread_id) = counter;
            };

            auto start = std::chrono::high_resolution_clock::now();

            std::vector<std::thread> threads(0);
            for (unsigned int i = 0; i < num_threads; ++i) {
                threads.emplace_back(task, i);
            }

            for (auto &e : threads)
                e.join();

            double diff = std::chrono::duration<double>(std::chrono::high_resolution_clock::now() - start).count();


#ifndef NDEBUG
            if (!std::equal(all_counter.begin() + 1, all_counter.end(), all_counter.cbegin())) {
                std::cerr << "Counter mismatch over the threads!" << std::endl;
                std::exit(2);
            }
#endif
            const uint64_t total_packets = all_counter.at(0);
            const uint64_t total_data = (sizeof(packet_header) + packet_len) * total_packets * runs;

            if (verbose) {
                std::cout << "####  QQ::Storage  ####" << std::endl;
                std::cout << "Sizeof packet: " << sizeof(packet_header) + packet_len << " B" << std::endl;
                std::cout << "Storage size: " << storage_size << " huge pages, " <<
                format_bytes(storage_size * huge_page_size) << std::endl;
                std::cout << "Parallel threads: " << num_threads << std::endl;
                std::cout << "Took: " << diff << " s" << std::endl;
                std::cout << format_SI(total_packets * runs) << " packets; " << format_SI((total_packets * runs) / diff) <<
                " packets/s" << std::endl;
                std::cout << "Throughput: " << format_bytes(total_data) << "; " << format_bits(total_data / diff) <<
                "/s" << std::endl << std::endl;
            } else {
                // bucket_size  packet_length    packets/s
                std::cout << storage_size * 2 << " " << packet_len << " " << std::fixed <<
                ((total_packets * runs) / diff) / (1000. * 1000.) << std::endl;
            }


        }


        template<size_t storage_size = 8>
        static void variable_packet_size_perf_test() {
            constexpr uint64_t runs = (1024 * 12) / storage_size;
            constexpr size_t max_packet_len = 512;
            uint64_t counter = 0;

            uint8_t* bytes;
            if ((bytes = (uint8_t*) mmap(NULL, storage_size * huge_page_size,
                                         PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
                handle_error("mmap");
            if (madvise(bytes, storage_size * huge_page_size, MADV_HUGEPAGE))
                handle_error("madvise");
            auto packet_data = new uint8_t[max_packet_len];

            auto start = std::chrono::high_resolution_clock::now();

            Storage<huge_page_size * storage_size> s(bytes);
            for (auto i = 0ULL; i < runs; ++i) {
                s.acquisition = _rdtsc();
                counter = 0;
                const uint16_t real_pkt_len = (uint16_t) ((counter + 1) % 128);
                while (s.store(123, 1, real_pkt_len, packet_data)) {
                    ++counter;
                    continue;
                }
                if (counter != s.size())
                    std::cerr << "Counter mismatch! Is: " << counter << ", stored: " << s.size() << std::endl;
                s.clear();
            }

            double diff = std::chrono::duration<double>(std::chrono::high_resolution_clock::now() - start).count();

            const uint64_t total_data = (sizeof(packet_header) + 64) * counter * runs;

            std::cout << "####  QQ::Storage  ####" << std::endl;
            std::cout << "Sizeof packet: " << sizeof(packet_header) + 64 << " B" << std::endl;
            std::cout << "Storage size: " << storage_size << " huge pages, " <<
            format_bytes(storage_size * huge_page_size) << std::endl;
            std::cout << "Took: " << diff << " s" << std::endl;
            std::cout << format_SI(counter * runs) << " packets; " << format_SI((counter * runs) / diff) <<
            " packets/s" << std::endl;
            std::cout << "Throughput: " << format_bytes(total_data) << "; " << format_bits(total_data / diff) <<
            "/s" << std::endl << std::endl;
            if (munmap(bytes, storage_size * huge_page_size))
                handle_error("munmap");
            delete[] packet_data;
        }

        static void timeout_test() {
            constexpr size_t packet_len = 64;
            constexpr size_t storage_size = 8;

            auto bytes = new uint8_t[huge_page_size * storage_size];
            auto packet_data = new uint8_t[packet_len];

            Storage<storage_size * huge_page_size> s(bytes);
            s.acquisition = _rdtsc();

            if (!s.store(213, 1, packet_len, packet_data)) {
                std::cerr << "Store failed when it should have not!" << std::endl;
                std::cout << "Timeout test failed!" << std::endl;
                return;
            }
            uint64_t t = static_cast<uint64_t>(timeout * 1.01 * 1000);
            std::this_thread::sleep_for(std::chrono::milliseconds(t));

            if (s.store(213, 1, packet_len, packet_data)) {
                std::cerr << "Store succeeded when it should have not!" << std::endl;
                std::cout << "Timeout test failed!" << std::endl;
                return;
            }

            std::cout << "Timeout test passed" << std::endl;
            delete[] bytes;
            delete[] packet_data;
        }

    public:
        std::mutex m_;
        uint64_t acquisition = 0;
    private:
        const uint8_t* backend;
        uint8_t* current;
        // TODO: can be optimized to store offsets instead of pointers, saving 4 byte/packet
        // (a variant without random access could save even more memory)
        std::vector<packet_header*> refs;
        constexpr static double timeout = 0.3;  // time in seconds
    };

    template<size_t num_pages>
    struct Ptr {
        Ptr() { }
        
        Ptr(Storage<num_pages * huge_page_size>& s) : storage(&s) {
            lock_ = std::unique_lock<std::mutex>(storage->m_);
            storage->acquisition = _rdtsc();
        }
        
        Ptr(const Ptr& other) = delete;

        Ptr(Ptr&& other) : storage(other.storage), lock_(std::move(other.lock_)) { }

        Ptr& operator=(Ptr&& other) {
            storage = other.storage;
            lock_ = std::move(other.lock_);
            return *this;
        }

        ~Ptr() {
            release();
        }
        
        inline void release() noexcept {
            if (lock_)
                lock_.unlock();
        }

        template<typename ...Args>
        inline bool store(Args&& ...args) {
            return storage->store(std::forward<Args>(args)...);
        }

        inline const packet_header* operator[](const size_t idx) const noexcept {
            return storage->operator[](idx);
        }

        inline void pop_back() {
            storage->pop_back();
        }

        inline void clear() {
            storage->clear();
        }

        inline size_t size() const noexcept {
            return storage->size();
        }

        inline std::vector<packet_header*>::const_iterator cbegin() const noexcept {
            return storage->cbegin();
        }

        inline std::vector<packet_header*>::const_iterator cend() const noexcept {
            return storage->cend();
        }

    private:
        Storage<num_pages * huge_page_size>* storage;  //!< Handle of the managed storage element
        std::unique_lock<std::mutex> lock_;            //!< To lock the QQ::Storage::m_ mutex
    };

    template<size_t pages_per_bucket>
    class QQ {

    public:
        QQ(size_t num_buckets): num_buckets(num_buckets) {
            if ((backend_ = (uint8_t*) mmap(NULL, pages_per_bucket * num_buckets * huge_page_size,
                                            PROT_READ | PROT_WRITE,
                                            MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == MAP_FAILED) {
                handle_error("mmap");
            }
            if (madvise(backend_, pages_per_bucket * num_buckets * huge_page_size, MADV_HUGEPAGE))
                handle_error("madvise");

            memset(backend_, 0, pages_per_bucket * num_buckets * huge_page_size);
            head = tail = peek_pos = 0;
            priority = 1;

            for (unsigned int i = 0; i < num_buckets; ++i) {
                storage_in_use.emplace_back(new Storage<pages_per_bucket * huge_page_size>(
                        backend_ + i * pages_per_bucket * huge_page_size));
            }
        }

        QQ(const QQ&) = delete;

        QQ(QQ&&) = delete;

        ~QQ() {
            if (munmap(backend_, pages_per_bucket * num_buckets * huge_page_size))
                handle_error("munmap");
            for (auto& e : storage_in_use)
                delete e;
        }

        QQ& operator=(const QQ&) = delete;

        QQ& operator=(QQ&&) = delete;

        Ptr<pages_per_bucket> waiting_enqueue(const uint8_t call_priority = 1) {
            Storage<pages_per_bucket * huge_page_size>* s = nullptr;
            //{
                std::unique_lock<std::mutex> lk(mutex_);
                //cv_prio.wait(lk, [&] { return check_priority_no_lock(call_priority); }); // wait until true/while false

                while (full_no_lock()) {
#ifndef NDEBUG
                    std::cout << "waiting_enqueue(" << (uint32_t) call_priority << "): full == true, head: " << head << ", tail: " << tail << std::endl;
#endif
                    not_full.wait(lk);
                }
                //not_full.wait(lk, [&] { return !full_no_lock(); });
#ifndef NDEBUG
                if (!lk.owns_lock()) {
                    std::cerr << "Lock not owned" << std::endl;
                    std::exit(2);
                }
#endif
                s = storage_in_use.at(head);
#ifndef NDEBUG
                std::cout << "waiting_enqueue(" << (uint32_t) call_priority << "): head " << head << " -> " << wrap(head+1) << std::endl;
#endif

                if (wrap(head + 1) == tail) {
                    std::cerr << "Enqueuing into full queue" << std::endl;
                    std::exit(2);
                    //throw new std::logic_error("Enqueuing into full queue");
                }

                head = wrap(head + 1);

#ifndef NDEBUG
                if (head == tail) {
                    std::cerr << "Enqueued into full queue" << std::endl;
                    std::exit(2);
                }
#endif

                ++waiting_enqueue_call_counter;

                Ptr<pages_per_bucket> p{*s};
                p.clear();
                lk.unlock();
                non_empty.notify_one();
                return p;
            //}

            //non_empty.notify_all();
            //not_full.notify_one();
            //Ptr<pages_per_bucket> p{*s};
            //p.clear();
            //return p;
        }


        Ptr<pages_per_bucket> enqueue(const uint8_t call_priority = 1) {
            Storage<pages_per_bucket * huge_page_size>* s = nullptr;
            std::unique_lock<std::mutex> lk(mutex_);
            not_full.wait(lk, [&] { return check_priority_no_lock(call_priority) || !full_no_lock(); });
            s = storage_in_use.at(head);
            head = wrap(head + 1);
            ++enqueue_call_counter;
            if (head == tail) {
                tail = wrap(tail + 16);
                ++enqueue_overflow_counter;
#ifndef NDEBUG
                std::cerr << "[QQ] Enqueue overflow occurred, dropping last 16 buckets!" << std::endl;
#endif
            }
            Ptr<pages_per_bucket> p{*s};  // The ctor locks the Storage mutex, potentially blocking if another Ptr hold still holds it
            lk.unlock();
            non_empty.notify_one();
            p.clear();
            return std::move(p);
        }

        Ptr<pages_per_bucket>* try_dequeue(const uint8_t call_priority = 1) {
            Storage<pages_per_bucket * huge_page_size>* s = nullptr;
            std::unique_lock<std::mutex> lk(mutex_);
            if (!non_empty.wait_for(lk, std::chrono::milliseconds(10), [&] {
                return distance(head, tail) < 8 // Wait until head is less than 8 buckets behind tail
                && distance(tail, head) > 8;    // Wait until tail is more than 8 buckets behind head
            }))
                return nullptr;
            s = storage_in_use.at(tail);
            tail = wrap(tail + 1);
            ++dequeue_call_counter;
            Ptr<pages_per_bucket> p{*s};
            lk.unlock();
            not_full.notify_one();
            return new Ptr<pages_per_bucket>(std::move(p));
        }

        Ptr<pages_per_bucket> dequeue(const uint8_t call_priority = 1) {
            Storage<pages_per_bucket * huge_page_size>* s = nullptr;
            std::unique_lock<std::mutex> lk(mutex_);
            //non_empty.wait(lk, [&] { return distance(tail, head) > 8; }); //This waits as short as possible
            non_empty.wait(lk, [&] {
                return distance(head, tail) < 8 // Wait until head is less than 8 buckets behind tail
                && distance(tail, head) > 8;    // Wait until tail is more than 8 buckets behind head
            }); // This waits until QQ is full
            s = storage_in_use.at(tail);
            tail = wrap(tail + 1);
            ++dequeue_call_counter;
            Ptr<pages_per_bucket> p{*s};
            lk.unlock();
            not_full.notify_one();
            return p;
        }

        Ptr<pages_per_bucket> peek(const uint8_t call_priority = 1) {
            Storage<pages_per_bucket * huge_page_size>* s = nullptr;
            std::unique_lock<std::mutex> lk(mutex_);
            if (distance(peek_pos, head) > num_buckets / 2) {
                peek_pos = wrap(peek_pos + 16);
#ifndef NDEBUG
                std::cerr << "[QQ::peek()]: peek pointer is lacking more than 50% behind head!" << std::endl;
#endif
            }
            //cv_prio.wait(lk, [&] { return check_priority_no_lock(call_priority); });
            non_empty.wait(lk, [&] { return distance(peek_pos, head) > 8; });
            s = storage_in_use.at(peek_pos);
            peek_pos = wrap(peek_pos + 1);
            Ptr<pages_per_bucket> p{*s};
            lk.unlock();
            non_empty.notify_one();
            return p;
        }

        Ptr<pages_per_bucket>* try_peek(const uint8_t call_priority = 1) {
            Storage<pages_per_bucket * huge_page_size>* s = nullptr;
            std::unique_lock<std::mutex> lk(mutex_);
            if (distance(peek_pos, head) > num_buckets / 2) {
                peek_pos = wrap(peek_pos + 16);
            }
            if (!non_empty.wait_for(lk, std::chrono::milliseconds(10), [&] {
                return distance(peek_pos, head) > 8; // Wait until peek_pos is more than 8 buckets behind head
            }))
                return nullptr;
            s = storage_in_use.at(peek_pos);
            peek_pos = wrap(peek_pos + 1);
            auto p = new Ptr<pages_per_bucket>(*s);
            lk.unlock();
            non_empty.notify_one();
            return p;
        }

        inline bool empty() {
            std::lock_guard<std::mutex> lg(mutex_);
            return head == tail;
        }

        inline bool empty_no_lock() const noexcept {
            return head == tail;
        }

        inline bool full_no_lock() const noexcept {
            return wrap(head + 1) == tail;
        }

        inline bool check_priority_no_lock(const uint8_t prio_to_check) const noexcept {
            return prio_to_check >= priority;
        }

        inline void set_priority(const uint8_t new_priority) noexcept {
            std::unique_lock<std::mutex> lk(mutex_);
            priority = new_priority;
            lk.unlock(); // unlock early to prevent instant re-blocking in other thread.
            cv_prio.notify_all();
        }

        inline void set_priority_no_lock(const uint8_t new_priority) noexcept {
            priority = new_priority;
        }

        inline size_t size() const noexcept {
            if (head >= tail)
                return head - tail;
            else
                return num_buckets - (tail - head);
        }
        
        inline size_t capacity() const noexcept {
            return num_buckets;
        }
        
        inline size_t distance(const size_t a, const size_t b) const noexcept {
            if (b >= a)
                return b - a;
            else
                return num_buckets - (a - b);
        }

        inline size_t wrap(const size_t value) const noexcept {
            if (value >= num_buckets)
                return value - num_buckets;
            else
                return value;
        }
                
        inline size_t get_enqueue_counter() const noexcept {
            return enqueue_call_counter;
        }
        
        inline size_t get_enqueue_overflow_counter() const noexcept {
            return enqueue_overflow_counter;
        }
        
        inline size_t get_dequeue_counter() const noexcept {
            return dequeue_call_counter;
        }

        void print_storages() const noexcept {
            std::cout << "Storages: ";
            for (auto& e : storage_in_use) {
                std::cout << " | " << e->size();
            }
            std::cout << " |" << std::endl;
        }

        void debug() const {
            std::cout << "Number of buckets: " << num_buckets << std::endl;
            std::cout << "Bucket size: " << format_bytes(pages_per_bucket * huge_page_size) << std::endl;
            std::cout << "Total size: " << format_bytes(num_buckets * pages_per_bucket * huge_page_size) << std::endl;
            std::cout << "Minimal look back time at 10 Gbit/s: " <<
            (num_buckets * pages_per_bucket * huge_page_size) / (1024 * 1024 * 1024 * 10. / 8) << " s" << std::endl;
            std::cout << "head: " << head << std::endl;
            std::cout << "tail: " << tail << std::endl;
            std::cout << "dequeue call counter: " << dequeue_call_counter << ", " << format_SI(dequeue_call_counter) <<
            std::endl;
            std::cout << "enqueue call counter: " << enqueue_call_counter << ", " << format_SI(enqueue_call_counter) <<
            std::endl;
            std::cout << "waiting_enqueue call counter: " << waiting_enqueue_call_counter << ", " <<
            format_SI(waiting_enqueue_call_counter) << std::endl;
            std::cout << "enqueue overflow counter: " << enqueue_overflow_counter << ", " <<
            format_SI(enqueue_overflow_counter) << std::endl;
        }


        template<int num_producer = 4, int num_consumer = 4, size_t num_buckets = 2048, bool verbose = true>
        static void pure_perf_test() {
            //constexpr uint64_t runs = 1024 * 1024 * 1;
            constexpr uint64_t runs = 1024 * 16;

            std::vector<std::thread> producer(0);
            std::vector<std::thread> consumer(0);

            QQ<1> qq(num_buckets);

            auto start = std::chrono::high_resolution_clock::now();

            for (unsigned int i = 0; i < num_producer; ++i) {
                producer.emplace_back([&, i]() {
                    for (auto j = 0ULL; j < runs; ++j) {
                        //auto enq_ptr = qq.waiting_enqueue((uint8_t) i);
                        auto enq_ptr = qq.waiting_enqueue();
                        if (enq_ptr.size() != 0) {
                            std::cerr << i << ": enqueue storage was not empty" << std::endl;
                            std::exit(2);
                            //throw new std::logic_error("enqueue storage was not empty");
                        }
                        if (!enq_ptr.store(1ULL, 1, 4, (const uint8_t*) &i)) {
                            std::cerr << i << ": store failed where it should not" << std::endl;
                            std::exit(2);
                            //throw new std::logic_error("store failed where it should not");
                        }
                        if (enq_ptr.size() != 1) {
                            std::cerr << i << ": storage must hold one element" << std::endl;
                            std::exit(2);
                        }
#ifndef NDEBUG
                        //std::cout << "producer " << i << " enqueue'd. j: " << j << std::endl;
#endif
                    }
                    {
#ifndef NDEBUG
                        std::cout << "producer " << i << " trying to send termination value... ";
#endif
                        auto enq_ptr = qq.waiting_enqueue();
                        if (!enq_ptr.store(0ULL, 1, 4, (const uint8_t*) &i)) {
                            std::cerr << i << ": store failed where it should not" << std::endl;
                            std::exit(2);
                            //throw new std::logic_error("store failed where it should not");
                        }
                        if (enq_ptr.size() != 1) {
                            std::cerr << i << ": storage must hold one element" << std::endl;
                            std::exit(2);
                        }
                    }
#ifndef NDEBUG
                    std::cout << " Done. value: " << i << ". QQ size: " << qq.size()
                    << ", head: " << qq.head << ", tail: " << qq.tail << std::endl;
#endif
                });
            }

            for (unsigned int i = 0; i < num_consumer; ++i) {
                consumer.emplace_back([&, i]() {
                    while (true) {
#ifndef NDEBUG
                        //std::cout << "consumer " << i << " trying to dequeue..." << std::endl;
#endif
                        //auto deq_prt = qq.dequeue((uint8_t) i);
                        auto deq_prt = qq.dequeue();
#ifndef NDEBUG
                        //std::cout << "consumer " << i << " got it." << std::endl;
#endif
                        if (deq_prt.size() != 1) {
                            std::cerr << i << ": dequeued storage was empty or over filled: " << deq_prt.size() << std::endl;
                            std::exit(2);
                            //throw new std::logic_error("dequeued storage was empty or over filled");
                        }

                        if (deq_prt[0]->timestamp == 0) {
#ifndef NDEBUG
                            uint8_t val = deq_prt[0]->data[0];
                            std::cout << "consumer " << i << " got termination value: " << (uint32_t) val
                            << ". QQ size: " << qq.size() << ", head: " << qq.head << ", tail: " << qq.tail << std::endl;
#endif
                            break;
                        } else if (deq_prt[0]->timestamp != 1) {
                            std::cerr << i << ": Timestamp invalid" << std::endl;
                            std::exit(2);
                            //throw new std::logic_error("timestamp invalid");
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
                        deq_prt.clear();
                    }
                });
            }

            for (auto& e : producer) {
                e.join();
            }
            for (auto& e : consumer) {
                e.join();
            }

            double diff = std::chrono::duration<double>(std::chrono::high_resolution_clock::now() - start).count();

            if (verbose) {
                std::cout << "####  New QQ (pure perf)  ####" << std::endl;
                std::cout << "Debug" << std::endl;
                qq.debug();
                std::cout << "END Debug" << std::endl;
                std::cout << "Producer: " << num_producer << std::endl;
                std::cout << "Consumer: " << num_consumer << std::endl;
                std::cout << "Bucket size: " << 1 << " huge pages" << std::endl;
                std::cout << "Number of buckets: " << num_buckets << std::endl;
                std::cout << "Took: " << diff << " s" << std::endl;
                std::cout << format_SI(runs) << " enqueue calls; " << format_SI(runs / diff) <<
                " enqueues/s" << std::endl;
            } else {
                std::cout << num_buckets << " " << std::fixed << runs / diff << std::endl;
            }
        }

    private:
        uint8_t* backend_;
        size_t head;
        size_t tail;
        size_t peek_pos;
        uint8_t priority; //!< stores the current priority level of the queue.
        const size_t num_buckets;
        std::mutex mutex_;
        std::vector<Storage<pages_per_bucket * huge_page_size>*> storage_in_use;

        std::condition_variable non_empty;
        std::condition_variable not_full;
        std::condition_variable cv_prio;

        // Performance counter
        uint64_t dequeue_call_counter = 0;
        uint64_t enqueue_call_counter = 0;
        uint64_t waiting_enqueue_call_counter = 0;
        uint64_t enqueue_overflow_counter = 0;
    };


    static void perf_test() {
        constexpr uint64_t runs = 1024 * 1024 * 256;
        constexpr size_t packet_len = 32;
        constexpr int num_producer = 4;
        constexpr int num_consumer = 4;
        constexpr size_t bucket_size = 64;
        constexpr size_t num_buckets = 128;

        std::vector<std::thread> producer(0);
        std::vector<std::thread> consumer(0);
        std::vector<uint64_t> producer_counter(num_producer, 0);
        std::vector<uint64_t> consumer_counter(num_consumer, 0);

        QQ<bucket_size> myq(num_buckets);

        auto start = std::chrono::high_resolution_clock::now();

        for (unsigned int i = 0; i < num_producer; ++i) {
            producer.emplace_back([&, i]() {
                uint64_t counter = 0;
                while (counter < runs) {
                    {
                        auto enq_ptr = myq.enqueue();
                        while (enq_ptr.store(i, 1, packet_len, (uint8_t*) &counter)) {
                            ++counter;
                            continue;
                        }
                    }
                }
                {
                    auto enq_ptr = myq.enqueue();
                    enq_ptr.clear();
                }
                producer_counter[i] = counter;
            });
        }


        for (unsigned int i = 0; i < num_consumer; ++i) {
            consumer.emplace_back([&, i]() {
                while (true) {
                    {
                        auto deq_prt = myq.dequeue();
                        if (deq_prt.size() == 0)
                            break;
                        for (size_t j = 0; j < deq_prt.size(); ++j) {
                            if (deq_prt[j]->timestamp >= num_producer)
                                std::cerr << "Data corruption in ts: " << deq_prt[j]->timestamp << std::endl;
                            consumer_counter[i] += deq_prt[j]->vlan;
                        }
                        deq_prt.clear();
                    }
                }
            });
        }

        for (auto& e : producer) {
            e.join();
        }
        for (auto& e : consumer) {
            e.join();
        }

        double diff = std::chrono::duration<double>(std::chrono::high_resolution_clock::now() - start).count();

        int64_t producer_sum = std::accumulate(producer_counter.begin(), producer_counter.end(), 0);
        int64_t consumer_sum = std::accumulate(consumer_counter.begin(), consumer_counter.end(), 0);
        //assert(consumer_sum == producer_sum);
        const uint64_t total_data = (sizeof(packet_header) + packet_len) * producer_sum;
        std::cout << "####  New QQ  ####" << std::endl;
        std::cout << "Debug" << std::endl;
        myq.debug();
        std::cout << "END Debug" << std::endl;
        std::cout << "Producer: " << num_producer << std::endl;
        std::cout << "Consumer: " << num_consumer << std::endl;
        std::cout << "Bucket size: " << bucket_size << " huge pages" << std::endl;
        std::cout << "Number of buckets: " << num_buckets << std::endl;
        std::cout << "Producer sum: " << producer_sum << std::endl;
        std::cout << "Consumer sum: " << consumer_sum << std::endl;
        std::cout << "Sizeof packet: " << sizeof(packet_header) + packet_len << " B" << std::endl;
        std::cout << "Took: " << diff << " s" << std::endl;
        std::cout << format_SI((uint64_t) producer_sum) << " packets; " << format_SI(producer_sum / diff) <<
        " packets/s" << std::endl;
        std::cout << "Throughput: " << format_bytes(total_data) << "; " << format_bits(total_data / diff) <<
        "/s" << std::endl << std::endl;
    }

    static void perf_test_write_only() {
        constexpr uint64_t runs = 1024 * 1024 * 256;
        constexpr size_t packet_len = 32;
        constexpr int num_producer = 4;
        constexpr size_t bucket_size = 8;
        constexpr size_t num_buckets = 512;

        std::vector<std::thread> producer(0);
        std::vector<std::thread> consumer(0);
        std::vector<uint64_t> producer_counter(num_producer, 0);

        QQ<bucket_size> myq(num_buckets);

        auto start = std::chrono::high_resolution_clock::now();

        for (unsigned int i = 0; i < num_producer; ++i) {
            producer.emplace_back([&, i]() {
                uint64_t counter = 0;
                while (counter < runs) {
                    {
                        auto enq_ptr = myq.enqueue();
                        while (enq_ptr.store(i, 1, packet_len, (uint8_t*) &counter)) {
                            ++counter;
                            continue;
                        }
                    }
                }
                {
                    auto enq_ptr = myq.enqueue();
                    enq_ptr.clear();
                }
                producer_counter[i] = counter;
            });
        }

        for (auto& e : producer) {
            e.join();
        }

        double diff = std::chrono::duration<double>(std::chrono::high_resolution_clock::now() - start).count();

        int64_t producer_sum = std::accumulate(producer_counter.begin(), producer_counter.end(), 0);
        //assert(consumer_sum == producer_sum);
        const uint64_t total_data = (sizeof(packet_header) + packet_len) * producer_sum;
        std::cout << "####  New QQ (write only)  ####" << std::endl;
        std::cout << "Debug" << std::endl;
        myq.debug();
        std::cout << "END Debug" << std::endl;
        std::cout << "Producer: " << num_producer << std::endl;
        std::cout << "Bucket size: " << bucket_size << " huge pages" << std::endl;
        std::cout << "Number of buckets: " << num_buckets << std::endl;
        std::cout << "Producer sum: " << producer_sum << std::endl;
        std::cout << "Sizeof packet: " << sizeof(packet_header) + packet_len << " B" << std::endl;
        std::cout << "Took: " << diff << " s" << std::endl;
        std::cout << format_SI((uint64_t) producer_sum) << " packets; " << format_SI(producer_sum / diff) <<
        " packets/s" << std::endl;
        std::cout << "Throughput: " << format_bytes(total_data) << "; " << format_bits(total_data / diff) <<
        "/s" << std::endl << std::endl;
    }

    static void cons_test() {
        // TODO: implement consistency test that takes enqueue overflows into account

        constexpr size_t map_size = 5000000ULL;

        std::vector<bool> map(map_size, false);
        QQ<1> qq(4);

        std::thread writer([&]() {
            auto q_ptr = qq.enqueue();
            for (uint64_t i = 0ULL; i < map.size(); ++i) {
                while (!q_ptr.store(uint64_t(123), 1, /*sizeof(i) * 10*/ 23, (uint8_t*) &i)) {
                    q_ptr = qq.waiting_enqueue();
                }
            }
            {
                q_ptr = qq.waiting_enqueue();
                q_ptr.clear();
            }
        });

        // Dequeue everything
        std::thread reader([&]() {
            while (true) {
                auto deq_ptr = qq.dequeue();
                if (deq_ptr.size() == 0)
                    break;
                for (auto it = deq_ptr.cbegin(); it != deq_ptr.cend(); ++it) {
                    uint64_t* number = (uint64_t*) (*it)->data;
                    map.at(*number) = true;
                }
            }
        });

        writer.join();
        reader.join();

        std::cout << "####  New QQ (consistency test)  ####" << std::endl;
        qq.debug();
        // Check bits
        for (auto it = map.cbegin(); it != map.cend(); ++it) {
            if (*it == false) {
                std::cerr << "Found bit that should be set at " << it - map.cbegin() << std::endl;
                return;
            }
        }
        std::cout << "Map size: " << map_size << ", " << format_SI(map_size) << std::endl;
        std::cout << "All packets there" << std::endl;
    }
} // namespace QQ
