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

#include "kafka_connection.h"
#include "kafka_topic_delta_handler.h"
#include "store.h"

namespace zdb {

KafkaTopicDeltaHandler::KafkaTopicDeltaHandler(KafkaProducerConnection* kafka)
        : m_kafka(kafka) {}

KafkaTopicDeltaHandler::~KafkaTopicDeltaHandler() = default;

void KafkaTopicDeltaHandler::handle_delta(const StoreResult& res) {
    if (res.delta.delta_type() == zsearch::DeltaType::DT_NO_CHANGE) {
        return;
    }
    auto serialized = res.delta.SerializeAsString();
    handle_serialized(serialized);
}
void KafkaTopicDeltaHandler::handle_delta(const AnonymousResult& res) {
    if (res.delta.delta_type() == zsearch::AnonymousDelta::DT_RESERVED) {
        return;
    }
    auto serialized = res.delta.SerializeAsString();
    handle_serialized(serialized);
}

void KafkaTopicDeltaHandler::handle_serialized(const std::string& s) {
    KafkaResult result = m_kafka->produce_blocking(s, 100);
    assert(result.status == KafkaResult::Status::OK);
}

}  // namespace zdb
