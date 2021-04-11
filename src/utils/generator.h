#ifndef CPP_GENERATOR_H
#define CPP_GENERATOR_H

// generator experimental header

// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//#include <yvals_core.h>
#include <exception>
#include <memory>
#include <coroutine>
#include <variant>

template <class T>
struct generator {
    struct promise_type {
        std::variant<T const*, std::exception_ptr> value;

        generator get_return_object() noexcept {
            return generator{*this};
        }

        std::suspend_always initial_suspend() noexcept {
            return {};
        }

        std::suspend_always final_suspend() noexcept {
            return {};
        }

        void unhandled_exception() noexcept {
            value = std::current_exception();
        }

        void rethrow_if_failed()
        {
            if (value.index() == 1)
            {
                std::rethrow_exception(std::get<1>(value));
            }
        }

        std::suspend_always yield_value(const T& _Val) noexcept {
            value = std::addressof(_Val);
            return {};
        }

        void return_void() noexcept {}

        template <typename Expression>
        Expression&& await_transform(Expression&& expression) {
            static_assert(sizeof(expression) == 0,
                          "co_await is not supported in coroutines of type generator");
            return std::forward<Expression>(expression);
        }

//            using _Alloc_char = _Rebind_alloc_t<_Alloc, char>;
//            static_assert(is_same_v<char*, typename allocator_traits<_Alloc_char>::pointer>,
//                "generator does not support allocators with fancy pointer types");
//            static_assert(
//                allocator_traits<_Alloc_char>::is_always_equal::value && is_default_constructible_v<_Alloc_char>,
//                "generator supports only stateless allocators");
//
//            static void* operator new(size_t _Size) {
//                _Alloc_char _Al{};
//                return allocator_traits<_Alloc_char>::allocate(_Al, _Size);
//            }
//
//            static void operator delete(void* _Ptr, size_t _Size) noexcept {
//                _Alloc_char _Al{};
//                return allocator_traits<_Alloc_char>::deallocate(_Al, static_cast<char*>(_Ptr), _Size);
//            }
    };

    struct iterator {
        using iterator_category = std::input_iterator_tag;
        using difference_type   = ptrdiff_t;
        using value_type        = T;
        using reference         = const T&;
        using pointer           = const T*;

        std::coroutine_handle<promise_type> coro_ = nullptr;

        iterator() = default;
        explicit iterator(std::coroutine_handle<promise_type> Coro) noexcept : coro_(Coro) {}

        iterator& operator++() {
            coro_.resume();
            if (coro_.done()) {
                std::exchange(coro_, nullptr).promise().rethrow_if_failed();
            }

            return *this;
        }

        void operator++(int) {
            // This operator meets the requirements of the C++20 input_iterator concept,
            // but not the Cpp17InputIterator requirements.
            ++*this;
        }

        [[nodiscard]] bool operator==(const iterator& _Right) const noexcept {
            return coro_ == _Right.coro_;
        }

        [[nodiscard]] bool operator!=(const iterator& _Right) const noexcept {
            return !(*this == _Right);
        }

        [[nodiscard]] reference operator*() const noexcept {
            return *(std::get<0>(coro_.promise().value));
        }

        [[nodiscard]] pointer operator->() const noexcept {
            return *(std::get<0>(coro_.promise().value));
        }
    };

    [[nodiscard]] iterator begin() {
        if (coro_) {
            coro_.resume();
            if (coro_.done()) {
                coro_.promise().rethrow_if_failed();
                return {};
            }
        }

        return iterator{coro_};
    }

    [[nodiscard]] iterator end() noexcept {
        return {};
    }

    explicit generator(promise_type& _Prom) noexcept : coro_(std::coroutine_handle<promise_type>::from_promise(_Prom)) {}

    generator() = default;

    generator(generator&& _Right) noexcept : coro_(std::exchange(_Right.coro_, nullptr)) {}

    generator& operator=(generator&& _Right) noexcept {
        coro_ = std::exchange(_Right.coro_, nullptr);
        return *this;
    }

    ~generator() {
        if (coro_) {
            coro_.destroy();
        }
    }

private:
    std::coroutine_handle<promise_type> coro_ = nullptr;
};


#endif //CPP_GENERATOR_H
