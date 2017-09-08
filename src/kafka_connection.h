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

#ifndef ZDB_SRC_KAFKA_TOPIC_H
#define ZDB_SRC_KAFKA_TOPIC_H

#include <string>

#include <librdkafka/rdkafkacpp.h>

namespace zdb {

struct KafkaResult {
  enum class Status {
    OK,
    WOULD_BLOCK,
    ERROR,
  };
  Status status = Status::ERROR;
  std::string data;
  std::string error;

  KafkaResult();
  KafkaResult(const KafkaResult&);
  KafkaResult(KafkaResult&&);
  ~KafkaResult();

  KafkaResult& operator=(const KafkaResult&);
};

enum class KafkaClientType {
  UNKNOWN,
  PRODUCER,
  CONSUMER,
};

class KafkaConnection {
 public:
  KafkaConnection();

  bool connect(const std::string& brokers,
               const std::string& topic,
               const std::string& client_id);

  bool connected() const { return m_connected; };

  virtual KafkaClientType client_type() const = 0;

  const std::string& topic_name() const { return m_topic_name; }

  virtual ~KafkaConnection();

 protected:
  RdKafka::Conf* m_conf = nullptr;
  RdKafka::Conf* m_tconf = nullptr;

  void delete_conf_objects();

 private:
  virtual bool connect_impl(const std::string& brokers,
                            const std::string& topic,
                            const std::string& client_id) = 0;

  std::string m_topic_name;
  bool m_connected = false;

  KafkaConnection(const KafkaConnection&) = delete;
};

class KafkaConsumerConnection : public KafkaConnection {
 public:
  KafkaConsumerConnection();
  ~KafkaConsumerConnection();

  KafkaClientType client_type() const override {
    return KafkaClientType::CONSUMER;
  }

  KafkaResult consume();

 private:
  virtual bool connect_impl(const std::string& brokers,
                            const std::string& topic,
                            const std::string& client_id) override;

  RdKafka::KafkaConsumer* m_consumer = nullptr;
  RdKafka::Topic* m_topic = nullptr;

  KafkaConsumerConnection(const KafkaConsumerConnection&) = delete;
};

class KafkaProducerConnection : public KafkaConnection {
 public:
  KafkaProducerConnection();
  ~KafkaProducerConnection();

  KafkaClientType client_type() const override {
    return KafkaClientType::PRODUCER;
  }

  KafkaResult produce(const std::string& msg);
  KafkaResult produce_blocking(const std::string& msg, size_t max_attempts);

 private:
  virtual bool connect_impl(const std::string& brokers,
                            const std::string& topic,
                            const std::string& client_id) override;

  RdKafka::Producer* m_producer = nullptr;
  RdKafka::Topic* m_topic = nullptr;
};

}  // namespace zdb

#endif /* ZDB_SRC_KAFKA_TOPIC_H */
