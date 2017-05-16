#include <junction/ConcurrentMap_Leapfrog.h>
#include <junction/QSBR.h>

#include <tuple.hpp>

#include <cstdint>

extern "C" {
    using Key = std::uint32_t;
    using Value = std::uint64_t;
    using ConcurrentMap = junction::ConcurrentMap_Leapfrog<Key, Value>;
    
    junction::QSBR::Context QSBR_create_context() {
        return junction::DefaultQSBR.createContext();
    }
    
    void QSBR_update(junction::QSBR::Context ctx) {
        junction::DefaultQSBR.update(ctx);
    }
    
    ConcurrentMap* concurrent_map_create() {
        return new ConcurrentMap;
    }
    
    void concurrent_map_delete(ConcurrentMap* map) {
        delete map;
    }
    
    Value concurrent_map_get(ConcurrentMap* map, Key key) {
        return map->get(key);
    }
    
    void concurrent_map_set(ConcurrentMap* map, Key key, Value val) {
        map->assign(key, val);
    }
    
}
