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
 * Copyright 2021 ScyllaDB
 */

#pragma once

#include <map>
#include <functional>

#include <seastar/http/request_parser.hh>
#include <seastar/core/seastar.hh>
#include <seastar/core/sstring.hh>
#include <seastar/net/api.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/queue.hh>
#include <seastar/core/when_all.hh>
#include <seastar/core/pipe.hh>

namespace seastar::experimental::websocket {

class server;
struct reply {
    //TODO: implement
};

/*!
 * \brief an error in handling a WebSocket connection
 */
class exception : std::exception {
    std::string _msg;
public:
    exception(std::string_view msg) : _msg(msg) {}
    const char* what() const noexcept {
        return _msg.c_str();
    }
};

struct FrameHeader {
    static constexpr uint8_t FIN = 7;
    static constexpr uint8_t RSV1 = 6; 
    static constexpr uint8_t RSV2 = 5; 
    static constexpr uint8_t RSV3 = 4;
    static constexpr uint8_t MASKED = 7;

    uint8_t fin : 1;
    uint8_t rsv1 : 1;
    uint8_t rsv2 : 1;
    uint8_t rsv3 : 1;
    uint8_t opcode : 4;
    uint8_t masked : 1;
    uint8_t length : 7;
    FrameHeader(char const *input) {
        this->fin = (input[0] >> FIN) & 1;
        this->rsv1 = (input[0] >> RSV1) & 1;
        this->rsv2 = (input[0] >> RSV2) & 1;
        this->rsv3 = (input[0] >> RSV3) & 1;
        this->opcode = input[0] & 0b1111;
        this->masked = (input[1] >> MASKED) & 1;
        this->length = (input[1] & 0b1111111);
    }
    // Returns length of the rest of the header.
    uint64_t getRestOfHeaderLength() {
        size_t nextReadLength = sizeof(uint32_t); // Masking key
        if (length == 126) {
            nextReadLength += sizeof(uint16_t);
        } else if (length == 127) {
            nextReadLength += sizeof(uint64_t);
        }
        return nextReadLength;
    }
    uint8_t get_fin() {return fin;}
    uint8_t get_rsv1() {return rsv1;}
    uint8_t get_rsv2() {return rsv2;}
    uint8_t get_rsv3() {return rsv3;}
    uint8_t get_opcode() {return opcode;}
    uint8_t get_masked() {return masked;}
    uint8_t get_length() {return length;}

    bool isOpcodeKnown() {
        //https://datatracker.ietf.org/doc/html/rfc6455#section-5.1
        return opcode < 0xA && !(opcode < 0x8 && opcode > 0x2);
    }
};



class connection_source_impl;

class websocket_parser {
    enum class parsing_state : uint8_t {
        flags_and_payload_data,
        payload_length_and_mask,
        payload
    };
    enum class connection_state : uint8_t {
        valid,
        closed,
        error
    };
    using consumption_result_type = consumption_result<char>;
    using buff_t = temporary_buffer<char>;
    // What parser is currently doing.
    parsing_state _state;
    // State of connection - can be valid, closed or should be closed 
    // due to error.
    connection_state _cstate;
    sstring _buffer;
    std::unique_ptr<FrameHeader> _header;
    uint64_t _payload_length;
    uint32_t _masking_key;
    buff_t _result;

    static future<consumption_result_type> dont_stop() {
        return make_ready_future<consumption_result_type>(continue_consuming{});
    }
    static future<consumption_result_type> stop(buff_t data) {
        return make_ready_future<consumption_result_type>(stop_consuming(std::move(data)));
    }

    // Removes mask from payload given in p.
    void remove_mask(buff_t & p, size_t n) {
        char *payload = p.get_write();
        for (uint64_t i = 0, j = 0; i < n; ++i, j = (j + 1) % 4) {
            payload[i] ^= static_cast<char>(((_masking_key << (j * 8)) >> 24));
        }
    } 
public:
    websocket_parser() : _state(parsing_state::flags_and_payload_data),
                         _cstate(connection_state::valid),
                         _payload_length(0), 
                         _masking_key(0) {}
    future<consumption_result_type> operator()(temporary_buffer<char> data);
    bool is_valid() { return _cstate == connection_state::valid; }
    bool eof() { return _cstate == connection_state::closed; }
    buff_t result() { return std::move(_result); }
};

/*!
 * \brief a WebSocket connection
 */
class connection : public boost::intrusive::list_base_hook<> {
    using buff_t = temporary_buffer<char>;
    using writer_ptr = std::unique_ptr<pipe_writer<buff_t>>;
    using reader_ptr = std::unique_ptr<pipe_reader<buff_t>>;

    /*!
     * \brief Implementation of connection's data source.
     */
    class connection_source_impl final : public data_source_impl {
        reader_ptr pip;
    public:
        connection_source_impl(reader_ptr && pip) : pip(std::move(pip)) {}

        virtual future<buff_t> get() override {
            return pip->read().then([this](std::optional<buff_t> o) {
                if (o) {
                    return make_ready_future<buff_t>(std::move(*o));
                }
                return make_ready_future<buff_t>(0);
            });
        }

        virtual future<> close() override {
            delete pip.release();
            return make_ready_future<>();
        }
    };

    static const size_t PIPE_SIZE = 1024;
    server& _server;
    connected_socket _fd;
    input_stream<char> _read_buf;
    output_stream<char> _write_buf;
    http_request_parser _http_parser;
    std::unique_ptr<reply> _resp;
    queue<std::unique_ptr<reply>> _replies{10};
    bool _done = false;

    writer_ptr _writer;
    input_stream<char> _input;
    websocket_parser _websocket_parser;
public:
    /*!
     * \param server owning \ref server
     * \param fd established socket used for communication
     */
    connection(server& server, connected_socket&& fd)
        : _server(server)
        , _fd(std::move(fd))
        , _read_buf(_fd.input())
        , _write_buf(_fd.output())
    {
        pipe<buff_t> pip{PIPE_SIZE};
        _writer = std::make_unique<pipe_writer<buff_t>>(std::move(pip.writer));
        _input = input_stream<char>{
            data_source{std::make_unique<connection_source_impl>(
            std::make_unique<pipe_reader<buff_t>>(std::move(pip.reader)))}};
        on_new_connection();
    }
    ~connection();
    input_stream<char>& input() {return _input;}

    /*!
     * \brief serve WebSocket protocol on a connection
     */
    future<> process();
    /*!
     * \brief close the socket
     */
    void shutdown();

protected:
    future<> read_loop();
    future<> read_one();
    future<> read_http_upgrade_request();
    future<> response_loop();
    void on_new_connection();
    future<> write_to_pipe(temporary_buffer<char>&& buf);
};

/*!
 * \brief a WebSocket server
 *
 * A server capable of establishing and serving connections
 * over WebSocket protocol.
 */
class server {
    std::vector<server_socket> _listeners;
    gate _task_gate;
    boost::intrusive::list<connection> _connections;
    std::map<std::string, std::function<future<>(temporary_buffer<char>&&, output_stream<char>&)>> handlers;
public:
    /*!
     * \brief listen for a WebSocket connection on given address
     * \param addr address to listen on
     */
    void listen(socket_address addr);
    /*!
     * \brief listen for a WebSocket connection on given address with custom options
     * \param addr address to listen on
     * \param lo custom listen options (\ref listen_options)
     */
    void listen(socket_address addr, listen_options lo);

    /*!
     * Stops the server and shuts down all active connections
     */
    future<> stop();

    bool is_handler_registered(std::string &name);

    void register_handler(std::string &&name, std::function<future<>(temporary_buffer<char>&&, output_stream<char>&)> _handler);

    friend class connection;
protected:
    void do_accepts(int which);
    future<> do_accept_one(int which);
};

}
