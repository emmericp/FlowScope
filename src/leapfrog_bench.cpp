#include <junction/ConcurrentMap_Leapfrog.h>
#include <junction/QSBR.h>

#include <tuple.hpp>

#include <cstdint>
#include <atomic>
#include <thread>
#include <chrono>

int main() {
    using Key = std::uint32_t;
    using Value = std::uint64_t;
    using ConcurrentMap = junction::ConcurrentMap_Leapfrog<Key, Value>; 
    constexpr uint64_t batchsize = 1024;
    
    auto ctx = junction::DefaultQSBR.createContext();
    
    
    auto map = ConcurrentMap{};
    
    std::atomic<std::uint64_t> exchange_ctr{0};
    
    auto printer = std::thread([&](){
        while (true) {
            auto ctr = exchange_ctr.exchange(0);
            std::printf("%0.2lfM exchanges/s\n", ctr/1000000.);
            std::this_thread::sleep_until(std::chrono::system_clock::now() + std::chrono::seconds(1));
        }
    });
    
    while (true) {
        std::uint64_t kv = 2;  // Skip null and redirect value
        for (uint i = 0; i < batchsize; ++i) {
            map.exchange(kv + 1000, kv);
            ++kv;
        }
        junction::DefaultQSBR.update(ctx);
        exchange_ctr.fetch_add(batchsize);
    }
    
    junction::DefaultQSBR.destroyContext(ctx);
}
