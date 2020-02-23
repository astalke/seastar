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
 * Copyright (C) 2019 ScyllaDB
 */

#pragma once

#include "fs/bitwise.hh"
#include "fs/units.hh"
#include "seastar/core/future.hh"
#include "seastar/core/temporary_buffer.hh"
#include "seastar/fs/block_device.hh"

#include <cstring>

namespace seastar::fs {

class to_disk_buffer {
protected:
    temporary_buffer<uint8_t> _buff;
    const unit_size_t _alignment;
    disk_offset_t _disk_write_offset; // disk offset that corresponds to _buff.begin()
    range<size_t> _unflushed_data; // range of unflushed bytes in _buff
    size_t _zero_padded_end; // Optimization to skip padding before write if it is already done

public:
    // Represents buffer that will be written to a block_device at offset @p disk_aligned_write_offset. Total number of bytes appended cannot exceed @p aligned_max_size.
    to_disk_buffer(size_t aligned_max_size, unit_size_t alignment, disk_offset_t disk_aligned_write_offset)
    : _buff(decltype(_buff)::aligned(alignment, aligned_max_size))
    , _alignment(alignment)
    , _disk_write_offset(disk_aligned_write_offset)
    , _unflushed_data {0, 0}
    , _zero_padded_end(0) {
        assert(is_power_of_2(alignment));
        assert(mod_by_power_of_2(disk_aligned_write_offset, alignment) == 0);
        assert(mod_by_power_of_2(aligned_max_size, alignment) == 0);
        start_new_unflushed_data();
    }

    virtual ~to_disk_buffer() = default;

    // Clears buffer, leaving it in state as if it was just constructed
    void reset(disk_offset_t new_disk_aligned_write_offset) noexcept {
        assert(mod_by_power_of_2(new_disk_aligned_write_offset, _alignment) == 0);
        _disk_write_offset = new_disk_aligned_write_offset;
        _unflushed_data = {0, 0};
        _zero_padded_end = 0;
        start_new_unflushed_data();
    }

    /**
     * @brief Writes buffered (unflushed) data to disk
     *   IMPORTANT: using this buffer before call to flush_to_disk() completes is perfectly OK
     *
     * @param device output device
     * @param align_after_flush whether to align to beginning of the next unflushed data or set it to where
     *   the current unflushed data ends
     */
    future<> flush_to_disk(block_device device, bool align_after_flush) {
        prepare_unflushed_data_for_flush();
        // Data layout overview:
        // |.................|.........................|00000000000000000000000|
        // ^ real_write.beg  ^ _unflushed_data.beg     ^ _unflushed_data.end   ^ real_write.end
        //      (aligned)       (maybe unaligned)         (maybe unaligned)         (aligned)
        //                                             |<------ padding ------>|
        range real_write = {
            round_down_to_multiple_of_power_of_2(_unflushed_data.beg, _alignment),
            round_up_to_multiple_of_power_of_2(_unflushed_data.end, _alignment),
        };
        // Pad buffer with zeros till alignment
        if (_zero_padded_end != real_write.end) {
            range padding = {_unflushed_data.end, real_write.end};
            memset(_buff.get_write() + padding.beg, 0, padding.size());
            _zero_padded_end = padding.end;
        }

        decltype(_unflushed_data) next_unflushed_data;
        if (align_after_flush) {
            next_unflushed_data = {real_write.end, real_write.end};
        } else {
            next_unflushed_data = {_unflushed_data.end, _unflushed_data.end};
        }

        // Make sure the buffer is usable before returning from this function
        _unflushed_data = next_unflushed_data;
        if (bytes_left() > 0) {
            start_new_unflushed_data();
        }

        return device.write(_disk_write_offset + real_write.beg, _buff.get_write() + real_write.beg, real_write.size()).then([real_write](size_t written_bytes) {
            if (written_bytes != real_write.size()) {
                return make_exception_future<>(std::runtime_error("Partial write"));
                // TODO: maybe add some way to retry write, because once the buffer is corrupt nothing can be done now
            }

            return now();
        });
    }

protected:
    // May be called before the flushing previous fragment is
    virtual void start_new_unflushed_data() noexcept {}

    virtual void prepare_unflushed_data_for_flush() noexcept {}

public:
    virtual void append_bytes(const void* data, size_t len) noexcept {
        assert(len <= bytes_left());
        std::memcpy(_buff.get_write() + _unflushed_data.end, data, len);
        _unflushed_data.end += len;
    }

    // Returns maximum number of bytes that may be written to buffer without calling reset()
    size_t bytes_left() const noexcept { return _buff.size() - _unflushed_data.end; }

    virtual size_t bytes_left_after_flush_if_done_now(bool align_after_flush) const noexcept {
        if (not align_after_flush)
            return bytes_left();
        return _buff.size() - round_up_to_multiple_of_power_of_2(_unflushed_data.end, _alignment);
    }
};

} // namespace seastar::fs
