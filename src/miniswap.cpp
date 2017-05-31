#include<atomic>

namespace miniswap {
    
    struct miniswap {
        explicit miniswap(void* a, void* b) : current_(a), old_(b) { }
        
        ~miniswap() {
            current_ = nullptr;
            old_ = nullptr;
        }
        
        void* current() const noexcept { return current_.load(); }
        
        void swap() noexcept {
            old_ = current_.exchange(old_);
        }
        
    private:
        std::atomic<void*> current_;
        void* old_;
    };
}

extern "C" {
    using ms = miniswap::miniswap;
    
    ms* miniswap_create(void* const a, void* const b) {
        return new miniswap::miniswap{a, b};
    }
    
    void miniswap_delete(ms* ms) {
        delete ms;
    }
    
    void* miniswap_current(const ms* ms) {
        return ms->current();
    }
    
    void miniswap_swap(ms* ms) {
        ms->swap();
    }
}
