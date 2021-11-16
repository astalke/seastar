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

#include <seastar/websocket/server.hh>
#include <seastar/util/log.hh>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>

namespace seastar::experimental::websocket {

static sstring magic_key_suffix = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
static sstring http_upgrade_reply_template =
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Sec-WebSocket-Accept: ";

static logger wlogger("websocket");

void server::listen(socket_address addr, listen_options lo) {
    _listeners.push_back(seastar::listen(addr, lo));
    do_accepts(_listeners.size() - 1);
}
void server::listen(socket_address addr) {
    listen_options lo;
    lo.reuse_address = true;
    return listen(addr, lo);
}

void server::do_accepts(int which) {
    // Waited on with the gate
    (void)try_with_gate(_task_gate, [this, which] {
        return keep_doing([this, which] {
            return try_with_gate(_task_gate, [this, which] {
                return do_accept_one(which);
            });
        }).handle_exception_type([](const gate_closed_exception& e) {});
    }).handle_exception_type([](const gate_closed_exception& e) {});
}

future<> server::do_accept_one(int which) {
    return _listeners[which].accept().then([this] (accept_result ar) mutable {
        auto conn = std::make_unique<connection>(*this, std::move(ar.connection));
        (void)try_with_gate(_task_gate, [conn = std::move(conn)]() mutable {
            return conn->process().handle_exception([conn = std::move(conn)] (std::exception_ptr ex) {
                wlogger.error("request error: {}", ex);
            });
        }).handle_exception_type([] (const gate_closed_exception& e) {});
    }).handle_exception_type([] (const std::system_error &e) {
        // We expect a ECONNABORTED when server::stop is called,
        // no point in warning about that.
        if (e.code().value() != ECONNABORTED) {
            wlogger.error("accept failed: {}", e);
        }
    }).handle_exception([] (std::exception_ptr ex) {
        wlogger.error("accept failed: {}", ex);
    });
}

future<> server::stop() {
    future<> tasks_done = _task_gate.close();
    for (auto&& l : _listeners) {
        l.abort_accept();
    }
    for (auto&& c : _connections) {
        c.shutdown();
    }
    return tasks_done;
}

connection::~connection() {
    _server._connections.erase(_server._connections.iterator_to(*this));
}

void connection::on_new_connection() {
    _server._connections.push_back(*this);
}

future<> connection::process() {
    return when_all(read_loop(), response_loop()).then(
            [] (std::tuple<future<>, future<>> joined) {
        try {
            std::get<0>(joined).get();
        } catch (...) {
            wlogger.debug("Read exception encountered: {}", std::current_exception());
        }
        try {
            std::get<1>(joined).get();
        } catch (...) {
            wlogger.debug("Response exception encountered: {}", std::current_exception());
        }
        return make_ready_future<>();
    });
}

static std::string sha1_base64(std::string_view source) {
    // CryptoPP insists on freeing the pointers by itself...
    // It's leaky, but `read_http_upgrade_request` is a one-shot operation
    // per handshake, so the real risk is not particularly great.
    CryptoPP::SHA1 sha1;
    std::string hash;
    CryptoPP::StringSource(reinterpret_cast<const CryptoPP::byte*>(source.data()), source.size(),
            true, new CryptoPP::HashFilter(sha1, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(hash), false)));
    return hash;
}

future<> connection::read_http_upgrade_request() {
    _http_parser.init();
    return _read_buf.consume(_http_parser).then([this] () mutable {
        if (_http_parser.eof()) {
            _done = true;
            return make_ready_future<>();
        }
        std::unique_ptr<httpd::request> req = _http_parser.get_parsed_request();
        if (_http_parser.failed()) {
            throw websocket::exception("Incorrect upgrade request");
        }

        sstring upgrade_header = req->get_header("Upgrade");
        if (upgrade_header != "websocket") {
            throw websocket::exception("Upgrade header missing");
        }
        sstring sec_key = req->get_header("Sec-Websocket-Key");
        sstring sec_version = req->get_header("Sec-Websocket-Version");

        sstring sha1_input = sec_key + magic_key_suffix;

        wlogger.debug("Sec-Websocket-Key: {}, Sec-Websocket-Version: {}", sec_key, sec_version);

        std::string sha1_output = sha1_base64(sha1_input);
        wlogger.debug("SHA1 output: {} of size {}", sha1_output, sha1_output.size());

        return _write_buf.write(http_upgrade_reply_template).then([this, sha1_output = std::move(sha1_output)] {
            return _write_buf.write(sha1_output);
        }).then([this] {
            return _write_buf.write("\r\n\r\n", 4);
        }).then([this] {
            return _write_buf.flush();
        });
    });
}

struct frame_header {
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
    frame_header(char const *input) {
        this->fin = (input[0] >> FIN) & 1;
        this->rsv1 = (input[0] >> RSV1) & 1;
        this->rsv2 = (input[0] >> RSV2) & 1;
        this->rsv3 = (input[0] >> RSV3) & 1;
        this->opcode = input[0] & 0b1111;
        this->masked = (input[1] >> MASKED) & 1;
        this->length = (input[1] & 0b1111111);
    }
    // Returns length of the rest of the header.
    uint64_t get_rest_of_header_length() {
        size_t next_read_length = sizeof(uint32_t); // Masking key
        if (length == 126) {
            next_read_length += sizeof(uint16_t);
        } else if (length == 127) {
            next_read_length += sizeof(uint64_t);
        }
        return next_read_length;
    }
    void debug() {
        wlogger.info("Header: {} {} {} {} {} {} {}", get_fin(), get_rsv1(), 
                get_rsv2(), get_rsv3(), get_opcode(), 
                get_masked(), get_length());
    }
    uint8_t get_fin() {return fin;}
    uint8_t get_rsv1() {return rsv1;}
    uint8_t get_rsv2() {return rsv2;}
    uint8_t get_rsv3() {return rsv3;}
    uint8_t get_opcode() {return opcode;}
    uint8_t get_masked() {return masked;}
    uint8_t get_length() {return length;}

    bool is_opcode_known() {
        //https://datatracker.ietf.org/doc/html/rfc6455#section-5.1
        return opcode < 0xA && !(opcode < 0x8 && opcode > 0x2);
    }
};

class frame_content {
    frame_header header;
    temporary_buffer<char> payload;
public:
    frame_content(frame_header header, temporary_buffer<char> payload) : header(header), payload(std::move(payload)) {}
};

future<> connection::read_one() {
    return _read_buf.read_exactly(2).then([this] (temporary_buffer<char> headBuf) {
        if (headBuf.size() < 2) { //FIXME: Magic numbers
            this->_done = true;
            throw websocket::exception("Connection closed.");
        } else {
            frame_header header {headBuf.get()};
            // https://datatracker.ietf.org/doc/html/rfc6455#section-5.1
            // We must close the connection if data isn't masked.
            if (!header.masked) {
                throw websocket::exception("RSVX is not 0.");
            }
            // RSVX must be 0
            if (header.rsv1 | header.rsv2 | header.rsv3) {
                throw websocket::exception("Frame not masked.");
            }
            // Opcode must be known.
            if (!header.is_opcode_known()) {
                throw websocket::exception("Unknown opcode.");
            } 
            header.debug();
            return seastar::make_ready_future<frame_header>(header);
        }
    }).then([this](frame_header header) { 
        return _read_buf.read_exactly(header.get_rest_of_header_length()).then(
                [this, header = std::move(header)](temporary_buffer<char> buf) mutable {
            if (buf.size() < header.get_rest_of_header_length()) {
                this->_done = true;
                throw websocket::exception("Connection closed.");
            } else {
                uint64_t payload_length = header.length;
                uint32_t masking_key;
                size_t offset = 0;
                char const *input = buf.get();
                if (header.length == 126) {
                    payload_length = be16toh(*(uint16_t const *)(input + offset));
                    offset += sizeof(uint16_t);
                } else if (header.length == 127) {
                    payload_length = be64toh(*(uint64_t const *)(input + offset));
                    offset += sizeof(uint64_t);
                }
                masking_key = be32toh(*(uint32_t const *)(input + offset));
                temporary_buffer<char> data = _read_buf.read_exactly(payload_length).get();
                if (data.size() < payload_length) {
                    this->_done = true;
                    throw websocket::exception("Connection closed.");
                } else {
                    temporary_buffer<char> _payload = data.clone();
                    char *payload = _payload.get_write();
                    for (uint64_t i = 0, j = 0; i < payload_length; ++i, j = (j + 1) % 4) {
                        payload[i] ^= static_cast<char>(((masking_key << (j * 8)) >> 24));
                    }
                    return write_to_pipe(std::move(_payload));
                }
            }        
            return seastar::make_ready_future<>();
        });
    });
}

future<> connection::read_loop() {
    return read_http_upgrade_request().then([this] {
        return do_until([this] {return _done;}, [this] {
            return read_one();
        });
    }).then_wrapped([this] (future<> f) {
        if (f.failed()) {
            wlogger.error("Failure: {}", f.get_exception());
        }
        return _replies.push_eventually({});
    }).finally([this] {
        return _read_buf.close();
    });
}

future<> connection::response_loop() {
    return do_until([this] {return _done;}, [this] {
        return input().read().then([this](temporary_buffer<char> buf) {
            // FIXME: implement
            wlogger.info("Loop: {} {}", buf.get(), buf.size());
            return this->_server.handlers["echo"](std::move(buf), _write_buf);
        });
    });
}

void connection::shutdown() {
    wlogger.debug("Shutting down");
    _fd.shutdown_input();
    _fd.shutdown_output();
}

future<> connection::write_to_pipe(temporary_buffer<char>&& buf) {
    return _writer->write(std::move(buf));
}

bool server::is_handler_registered(std::string &name) {
    return handlers.find(name) != handlers.end();
}

void server::register_handler(std::string &&name, std::function<future<>(temporary_buffer<char>&&, output_stream<char>&)> _handler) {
    handlers[name] = _handler;
}


}
