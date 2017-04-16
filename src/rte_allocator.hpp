#pragma once

#include <cstddef>
#include <type_traits>


#include <iostream>

#include <rte_config.h>
#include <rte_malloc.h>


template <class T>
struct rte_allocator {
    using value_type = T;
    using propagate_on_container_copy_assignment = std::true_type;
    using propagate_on_container_move_assignment = std::true_type;
    using propagate_on_container_swap = std::true_type;
    rte_allocator() noexcept { }
    template <class U> rte_allocator (const rte_allocator<U>&) noexcept { }
    T* allocate (std::size_t n);
    void deallocate (T* p, std::size_t n);
};

template <class T>
T* rte_allocator<T>::allocate(std::size_t n) {
#if 0
    return static_cast<T*>(rte_malloc(NULL, n, 0));
#else
    std::cout << "Allocate " << n << " bytes" << std::endl;
    auto m = rte_malloc(NULL, n, 0);
    if (m == NULL)
        exit(55);
    return static_cast<T*>(m);
#endif
}

template <class T>
void rte_allocator<T>::deallocate(T* p, std::size_t n) {
    return rte_free(p);
}

template <class T, class U>
constexpr bool operator== (const rte_allocator<T>&, const rte_allocator<U>&) noexcept {
    return true;
}

template <class T, class U>
constexpr bool operator!= (const rte_allocator<T>&, const rte_allocator<U>&) noexcept {
    return false;
}
