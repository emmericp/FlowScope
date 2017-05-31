#include <junction/ConcurrentMap_Leapfrog.h>
#include <junction/QSBR.h>

#include <tuple.hpp>

#include <cstdint>


extern "C" {
    using Key = std::uint32_t;
    using Value = std::uint64_t;
    //using Value = flowtracker::ttl_flow_data*;
    using ConcurrentMap = junction::ConcurrentMap_Leapfrog<Key, Value>;
    
    static_assert(std::is_same<junction::QSBR::Context, std::uint16_t>::value, "QSBR::Context typedef changed, rewrite the wrapper");
    
    junction::QSBR::Context QSBR_create_context() {
        return junction::DefaultQSBR.createContext();
    }
    
    void QSBR_update(junction::QSBR::Context ctx) {
        junction::DefaultQSBR.update(ctx);
    }
    
    void QSBR_destroy_context(junction::QSBR::Context ctx) {
        junction::DefaultQSBR.destroyContext(ctx);
    }
    
    ConcurrentMap* concurrent_map_create() {
        return new ConcurrentMap;
    }
    
    void concurrent_map_delete(ConcurrentMap* map) {
        delete map;
    }
    
    /* Low-level functions */
    Value concurrent_map_get(ConcurrentMap* map, Key key) {
        return map->get(key);
    }
    
    Value concurrent_map_exchange(ConcurrentMap* map, Key key, Value val) {
        return map->exchange(key, val);
    }
    
    Value concurrent_map_erase(ConcurrentMap* map, Key key) {
        return map->erase(key);
    }
    
}
