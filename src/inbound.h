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

#ifndef ZDB_INBOUND_H
#define ZDB_INBOUND_H

#include <atomic>
#include <memory>
#include <string>
#include <vector>

#include "zsearch_definitions/search.pb.h"

#include "anonymous_store.h"
#include "configuration.h"
#include "context.h"
#include "kafka_connection.h"
#include "macros.h"
#include "store.h"

namespace zdb {

struct InboundResult {
    bool success;
    std::string serialized;
};

class InboundHandler {
  public:
    virtual InboundResult handle(const std::string& serialized) = 0;
};

struct InboundOptions {
    size_t threads;
    size_t thread_id_offset;
    std::vector<std::unique_ptr<InboundHandler>> handlers;
    KafkaConsumerConnection* incoming;
    KafkaProducerConnection* outgoing;
};

class KafkaTopicPruneHandler : public PruneHandler {
  public:
    KafkaTopicPruneHandler(KafkaProducerConnection*);
    KafkaTopicPruneHandler(const KafkaTopicPruneHandler&) = default;
    ~KafkaTopicPruneHandler();

    void handle_pruned(const StoreResult& pruned) override;
    void handle_pruned(const AnonymousResult& pruned) override;

  private:
    void handle_serialized(const std::string& s);

    KafkaProducerConnection* m_kafka;
};

class GroupingPruneHandler : public PruneHandler {
  public:
    enum GroupOn {
        GROUP_IP,
        GROUP_DOMAIN,
    };

    GroupingPruneHandler();
    GroupingPruneHandler(GroupOn group_target);
    GroupingPruneHandler(const GroupingPruneHandler&);
    ~GroupingPruneHandler();

    void handle_pruned(const StoreResult& pruned) override;
    void handle_pruned(const AnonymousResult& pruned) override;

    void set_underlying_handler(std::shared_ptr<PruneHandler> impl) {
        m_impl = std::move(impl);
    }

  private:
    void do_prune();

    GroupOn m_group_target = GROUP_IP;

    uint32_t m_ip = 0;
    std::string m_domain;

    std::shared_ptr<PruneHandler> m_impl = nullptr;
    bool m_have_latest = false;
    StoreResult m_latest;
};

std::vector<InboundOptions> configure_inbound(ConfigValues* config_values,
                                              StoreContext* store_ctx,
                                              KafkaContext* kafka_ctx);

void process_inbound(KafkaConsumerConnection* recv_topic,
                     KafkaProducerConnection* delta_topic,
                     InboundHandler* handler,
                     std::atomic<int>& server_state);

}  // namespace zdb

#endif /* ZDB_INBOUND_H */
