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
#include "inbound.h"
#include "macros.h"
#include "utility.h"

namespace zdb {

struct AdminServer {
    std::unique_ptr<zsearch::AdminService::Service> impl;
    std::unique_ptr<grpc::Server> server;

    AdminServer() = default;
    AdminServer(AdminServer&&) = default;
    AdminServer(const AdminServer&) = delete;

    ~AdminServer() {
        if (server != nullptr) {
            server.reset();
        }
    }
};

std::unique_ptr<AdminServer> make_admin_server(uint16_t port,
                                               StoreContext* store_ctx,
                                               KafkaContext* kafka_ctx);

}  // namespace zdb
