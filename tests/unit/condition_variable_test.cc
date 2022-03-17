/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/*
 * Copyright (C) 2015 Cloudius Systems, Ltd.
 */

#include <seastar/core/thread.hh>
#include <seastar/core/do_with.hh>
#include <seastar/testing/test_case.hh>
#include <seastar/testing/thread_test_case.hh>
#include <seastar/core/sstring.hh>
#include <seastar/core/condition-variable.hh>
#include <seastar/core/do_with.hh>
#include <seastar/core/loop.hh>
#include <seastar/core/map_reduce.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/shared_mutex.hh>
#include <seastar/core/when_all.hh>
#include <seastar/core/when_any.hh>
#include <seastar/core/with_timeout.hh>
#include <boost/range/irange.hpp>

using namespace seastar;
using namespace std::chrono_literals;
using steady_clock = std::chrono::steady_clock;

SEASTAR_THREAD_TEST_CASE(test_condition_variable_signal_consume) {
    condition_variable cv;

    cv.signal();
    auto f = cv.wait();

    BOOST_REQUIRE_EQUAL(f.available(), true);
    f.get();

    auto f2 = cv.wait();

    BOOST_REQUIRE_EQUAL(f2.available(), false);

    cv.signal();

    with_timeout(steady_clock::now() + 10ms, std::move(f2)).get();

    std::vector<future<>> waiters;
    waiters.emplace_back(cv.wait());
    waiters.emplace_back(cv.wait());
    waiters.emplace_back(cv.wait());

    BOOST_REQUIRE_EQUAL(std::count_if(waiters.begin(), waiters.end(), std::mem_fn(&future<>::available)), 0u);

    cv.signal();

    BOOST_REQUIRE_EQUAL(std::count_if(waiters.begin(), waiters.end(), std::mem_fn(&future<>::available)), 1u);
    // FIFO
    BOOST_REQUIRE_EQUAL(waiters.front().available(), true);

    cv.broadcast();

    BOOST_REQUIRE_EQUAL(std::count_if(waiters.begin(), waiters.end(), std::mem_fn(&future<>::available)), 3u);
}

SEASTAR_THREAD_TEST_CASE(test_condition_variable_signal_break) {
    condition_variable cv;

    std::vector<future<>> waiters;
    waiters.emplace_back(cv.wait());
    waiters.emplace_back(cv.wait());
    waiters.emplace_back(cv.wait());

    BOOST_REQUIRE_EQUAL(std::count_if(waiters.begin(), waiters.end(), std::mem_fn(&future<>::available)), 0u);

    cv.broken();

    for (auto& f : waiters) {
        try {
            f.get();
        } catch (broken_condition_variable&) {
            // ok
            continue;
        }
        BOOST_FAIL("should not reach");
    }

    try {
        auto f = cv.wait();
        f.get();
        BOOST_FAIL("should not reach");
    } catch (broken_condition_variable&) {
        // ok
    } catch (...) {
        BOOST_FAIL("should not reach");
    }
}

SEASTAR_THREAD_TEST_CASE(test_condition_variable_timeout) {
    condition_variable cv;

    auto f = cv.wait(100ms);
    BOOST_REQUIRE_EQUAL(f.available(), false);

    sleep(200ms).get();
    BOOST_REQUIRE_EQUAL(f.available(), true);

    try {
        f.get();
        BOOST_FAIL("should not reach");
    } catch (condition_variable_timed_out&) {
        // ok
    } catch (...) {
        BOOST_FAIL("should not reach");
    }
}

SEASTAR_THREAD_TEST_CASE(test_condition_variable_pred) {
    condition_variable cv;

    bool ready = false;
    auto f = cv.wait(10000ms, [&] { return ready; });

    BOOST_REQUIRE_EQUAL(f.available(), false);
    sleep(200ms).get();
    BOOST_REQUIRE_EQUAL(f.available(), false);
    ready = true;
    cv.signal();
    with_timeout(steady_clock::now() + 10ms, std::move(f)).get();
}

#ifdef SEASTAR_COROUTINES_ENABLED

SEASTAR_TEST_CASE(test_condition_variable_signal_consume_coroutine) {
    condition_variable cv;

    cv.signal();
    co_await with_timeout(steady_clock::now() + 10ms, [&]() -> future<> {
        co_await cv.when();
    }());

    try {
        co_await with_timeout(steady_clock::now() + 10ms, [&]() -> future<> {
            co_await cv.when();
        }());
        BOOST_FAIL("should not reach");
    } catch (condition_variable_timed_out&) {
        BOOST_FAIL("should not reach");
    } catch (timed_out_error&) {
        // ok
    } catch (...) {
        BOOST_FAIL("should not reach");
    }

    try {
        co_await with_timeout(steady_clock::now() + 10s, [&]() -> future<> {
            co_await cv.when(100ms);
        }());
        BOOST_FAIL("should not reach");
    } catch (timed_out_error&) {
        BOOST_FAIL("should not reach");
    } catch (condition_variable_timed_out&) {
        // ok
    } catch (...) {
        BOOST_FAIL("should not reach");
    }

}

#endif