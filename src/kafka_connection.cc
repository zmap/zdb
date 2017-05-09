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

#include <cassert>
#include <memory>

#include <unistd.h>

#include <librdkafka/rdkafkacpp.h>

#include "zmap/logger.h"

#include "macros.h"

namespace zdb {

KafkaResult::KafkaResult() = default;
KafkaResult::KafkaResult(const KafkaResult&) = default;
KafkaResult::KafkaResult(KafkaResult&&) = default;
KafkaResult::~KafkaResult() = default;

KafkaResult& KafkaResult::operator=(const KafkaResult&) = default;

KafkaConnection::KafkaConnection() = default;
KafkaConnection::~KafkaConnection() {
    delete_conf_objects();
}

bool KafkaConnection::connect(const std::string& brokers,
                              const std::string& topic,
                              const std::string& client_id) {
    if (m_connected) {
        return true;
    }
    std::string err_string;
    m_topic_name = topic;
    m_conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);
    m_tconf = RdKafka::Conf::create(RdKafka::Conf::CONF_TOPIC);
    if (!m_conf || !m_tconf) {
        return false;
    }
    if (m_conf->set("client.id", client_id, err_string) !=
        RdKafka::Conf::CONF_OK) {
        log_error("kafka", "could not set client.id: %s", err_string.c_str());
    }
    if (m_conf->set("log_level", "7", err_string) != RdKafka::Conf::CONF_OK) {
        log_error("kafka", "could not set log level: %s", err_string.c_str());
        return false;
    }
    if (m_conf->set("log.connection.close", "false", err_string) !=
        RdKafka::Conf::CONF_OK) {
        log_error("kafka", "could not set log.connection.close=false: %s",
                  err_string.c_str());
        return false;
    }
    if (m_conf->set("metadata.broker.list", brokers, err_string) !=
        RdKafka::Conf::CONF_OK) {
        log_error("kafka", "Brokers: %s, %s\n", brokers.c_str(),
                  err_string.c_str());
        return false;
    }
    if (m_conf->set("partition.assignment.strategy", "roundrobin",
                    err_string) != RdKafka::Conf::CONF_OK) {
        log_error("kafka", "could not set partition.assignment.strategy: %s",
                  err_string.c_str());
        return false;
    }
    if (m_conf->set("fetch.message.max.bytes", "2000048", err_string) !=
        RdKafka::Conf::CONF_OK) {
        log_error("kafka", "could not set fetch.message.max.bytes: %s",
                  err_string.c_str());
        return false;
    }
    if (m_conf->set("message.max.bytes", "1000000000", err_string) !=
        RdKafka::Conf::CONF_OK) {
        log_error("kafka", "could not set message.max.bytes: %s",
                  err_string.c_str());
        return false;
    }
    if (m_conf->set("receive.message.max.bytes", "1000000000", err_string) !=
        RdKafka::Conf::CONF_OK) {
        log_error("kafka", "could not set receive.message.max.bytes: %s",
                  err_string.c_str());
        return false;
    }
    if (m_conf->set("group.id", "zdb2", err_string) != RdKafka::Conf::CONF_OK) {
        log_error("kafka", "could not set group.id: %s", err_string.c_str());
        return false;
    }
    if (m_conf->set("api.version.request", "true", err_string) != RdKafka::Conf::CONF_OK) {
        log_error("kafka", "could not set api.version.request=true: %s", err_string.c_str());
        return false;
    }
    m_connected = connect_impl(brokers, topic, client_id);
    return m_connected;
}

void KafkaConnection::delete_conf_objects() {
    // No need to keep configs around
    if (m_tconf) {
        log_debug("kafka", "deleting tconf");
        delete m_tconf;
        m_tconf = nullptr;
    }
    if (m_conf) {
        log_debug("kafka", "deleting conf");
        delete m_conf;
        m_conf = nullptr;
    }
}

KafkaConsumerConnection::KafkaConsumerConnection() = default;
KafkaConsumerConnection::~KafkaConsumerConnection() {
    if (m_consumer) {
        log_debug("kafka", "closing consumer");
        // m_consumer->commitSync();
        // m_consumer->unsubscribe();
        m_consumer->close();
    }
    if (m_topic) {
        log_debug("kafka", "deleting consumer topic");
        delete m_topic;
        m_topic = nullptr;
    }
    if (m_consumer) {
        log_debug("kafka", "deleting consumer");
        delete m_consumer;
        m_consumer = nullptr;
    }
}

KafkaResult KafkaConsumerConnection::consume() {
    if (m_consumer == nullptr) {
        log_error("kafka", "not a consumer");
        return KafkaResult();  // Error
    }
    std::unique_ptr<RdKafka::Message> msg(m_consumer->consume(1000));

    KafkaResult ret;
    switch (msg->err()) {
        case RdKafka::ERR__TIMED_OUT:
            ret.status = KafkaResult::Status::WOULD_BLOCK;
            ret.error = "timeout";
            break;
        case RdKafka::ERR__TIMED_OUT_QUEUE:
            ret.status = KafkaResult::Status::WOULD_BLOCK;
            ret.error = "timeout";
            break;
        case RdKafka::ERR__PARTITION_EOF:
            ret.status = KafkaResult::Status::WOULD_BLOCK;
            ret.error = "eof";
            break;
        case RdKafka::ERR_LEADER_NOT_AVAILABLE:
            ret.status = KafkaResult::Status::WOULD_BLOCK;
            ret.error = "leader not available";
            break;
        case RdKafka::ERR_NOT_LEADER_FOR_PARTITION:
            ret.status = KafkaResult::Status::WOULD_BLOCK;
            ret.error = "partition leader not available";
            break;
        case RdKafka::ERR_NO_ERROR:
            ret.status = KafkaResult::Status::OK;
            ret.data.assign(static_cast<const char*>(msg->payload()),
                            msg->len());
            break;
        default:
            ret.status = KafkaResult::Status::ERROR;
            ret.error = msg->errstr();
            if (ret.error.empty()) {
                ret.error = "unknown";
            }
            break;
    }
    return ret;
}

bool KafkaConsumerConnection::connect_impl(const std::string& brokers,
                                           const std::string& topic,
                                           const std::string& client_id) {
    std::string err_string;
    std::vector<std::string> topics{topic};
    if (m_conf->set("offset.store.method", "broker", err_string) !=
        RdKafka::Conf::CONF_OK) {
        log_error("kafka", "could not set offset.store.method: %s",
                  err_string.c_str());
        return false;
    }
    if (m_tconf->set("auto.commit.enable", "true", err_string) !=
        RdKafka::Conf::CONF_OK) {
        log_error("kafka", "could not set auto.commit.enable: %s",
                  err_string.c_str());
        return false;
    }
    if (m_tconf->set("auto.offset.reset", "earliest", err_string) !=
        RdKafka::Conf::CONF_OK) {
        log_error("kafka", "could not set autooffset.reset: %s",
                  err_string.c_str());
        return false;
    }

    m_consumer = RdKafka::KafkaConsumer::create(m_conf, err_string);
    if (!m_consumer) {
        log_error("kafka", "%s\n", err_string.c_str());
        return false;
    }
    m_topic = RdKafka::Topic::create(m_consumer, topic, m_tconf, err_string);
    if (!m_topic) {
        log_error("kafka", "%s\n", err_string.c_str());
        return false;
    }

    if (m_consumer->subscribe(topics)) {
        log_error("kafka", "could not subscribe to topic: %s", topic.c_str());
        return false;
    }
    log_info("kafka", "consumer %s created", m_consumer->name().c_str());
    delete_conf_objects();
    return true;
}

KafkaProducerConnection::KafkaProducerConnection() = default;
KafkaProducerConnection::~KafkaProducerConnection() {
    while (m_producer && m_producer->outq_len() > 0) {
        log_debug("kafka", "flushing producer");
        m_producer->poll(1000);
    }
    if (m_topic) {
        log_debug("kafka", "deleting producer topic");
        delete m_topic;
        m_topic = nullptr;
    }
    if (m_producer) {
        log_debug("kafka", "deleting producer");
        delete m_producer;
        m_producer = nullptr;
    }
}

KafkaResult KafkaProducerConnection::produce(const std::string& msg) {
    if (m_producer == nullptr) {
        return KafkaResult();  // Consumers can't produce.
    }
    RdKafka::ErrorCode resp = m_producer->produce(
            m_topic, RdKafka::Topic::PARTITION_UA,
            RdKafka::Producer::RK_MSG_COPY, const_cast<char*>(msg.data()),
            msg.size(), nullptr, nullptr);
    m_producer->poll(0);
    KafkaResult ret;
    switch (resp) {
        case RdKafka::ERR_NO_ERROR:
            ret.status = KafkaResult::Status::OK;
            break;
        case RdKafka::ERR__QUEUE_FULL:
            ret.status = KafkaResult::Status::WOULD_BLOCK;
            break;
        default:
            ret.status = KafkaResult::Status::ERROR;
            ret.error = RdKafka::err2str(resp);
            break;
    }
    return ret;
}

KafkaResult KafkaProducerConnection::produce_blocking(const std::string& msg,
                                                      size_t max_attempts) {
    size_t attempts = 0;
    KafkaResult ret;
    while (attempts < max_attempts) {
        ret = produce(msg);
        ++attempts;
        if (ret.status == KafkaResult::Status::OK) {
            break;
        }
        sleep(1);
    }
    if (ret.status != KafkaResult::Status::OK) {
        log_error("kafka", "produce failed after %llu attempts (%d): %s",
                  attempts, static_cast<int>(ret.status), ret.error.c_str());
    }
    return ret;
}

bool KafkaProducerConnection::connect_impl(const std::string& brokers,
                                           const std::string& topic,
                                           const std::string& client_id) {
    std::string err_string;
    m_producer = RdKafka::Producer::create(m_conf, err_string);
    if (!m_producer) {
        log_error("kafka", "%s\n", err_string.c_str());
        return false;
    }
    m_topic = RdKafka::Topic::create(m_producer, topic, m_tconf, err_string);
    if (!m_topic) {
        log_error("kafka", "%s\n", err_string.c_str());
        return false;
    }
    log_info("kafka", "producer %s created", m_producer->name().c_str());
    delete_conf_objects();
    return true;
}

}  // namespace zdb
