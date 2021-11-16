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

class connection_source_impl;

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
        connection_source_impl(reader_ptr && pip) 
            : pip(std::move(pip)) {}

        virtual future<buff_t> get() override {
            return pip->read().then([this](std::optional<buff_t> o) {
                if (o) {
                    return make_ready_future<buff_t>(std::move(*o));
                }
                return make_ready_future<buff_t>(0);
            });
        }

        virtual future<> close() override {
            //TODO
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
