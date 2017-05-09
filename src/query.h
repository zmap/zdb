/*
 * ZDB Copyright 2017 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <cstdint>
#include <memory>

#include <grpc++/server.h>

#include "configuration.h"
#include "utility.h"
#include "inbound.h"

namespace zdb {

struct QueryServer {
    std::unique_ptr<zsearch::QueryService::Service> impl;
    std::unique_ptr<grpc::Server> server;

    QueryServer() = default;
    QueryServer(QueryServer&&) = default;
    QueryServer(const QueryServer&) = delete;

    ~QueryServer() {
        if (server != nullptr) {
            server.reset();
        }
    }
};
std::unique_ptr<QueryServer> make_query_server(uint16_t port,
                                               StoreContext* store_ctx);

}  // namespace zdb
