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

#ifndef ZDB_SRC_KAFKA_TOPIC_DELTA_HANDLER_H
#define ZDB_SRC_KAFKA_TOPIC_DELTA_HANDLER_H

#include "delta_handler.h"
#include "macros.h"

namespace zdb {

class KafkaTopicDeltaHandler : public DeltaHandler {
 public:
  KafkaTopicDeltaHandler(KafkaProducerConnection*);
  ~KafkaTopicDeltaHandler();

  void handle_delta(const StoreResult& res) override;
  void handle_delta(const AnonymousResult& res) override;

  const std::string& topic() const;

 private:
  void handle_serialized(const std::string& s);

  KafkaProducerConnection* m_kafka;

  DISALLOW_COPY_ASSIGN(KafkaTopicDeltaHandler);
};

}  // namespace zdb

#endif /* ZDB_SRC_KAFKA_TOPIC_DELTA_HANDLER_H */
