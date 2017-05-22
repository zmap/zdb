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

#include "inbound.h"
#include <unistd.h>
#include <zmap/logger.h>

#include <sstream>
#include <memory>

#include "anonymous_store.h"
#include "kafka_connection.h"
#include "store.h"

using namespace zdb;
using namespace std;

template <typename key_type>
class StoreHandler : public InboundHandler {
  private:
    Store<key_type> m_store;

  public:
    StoreHandler(Store<key_type> store) : m_store(std::move(store)) {}

    StoreResult handle(const zsearch::Record& r) { return m_store.put(r); }

    InboundResult handle(const string& serialized) {
        zsearch::Record r;
        if (!r.ParseFromString(serialized)) {
            auto hex = hex_encode(serialized);
            log_warn("inbound", "unable to deserialize 0x%s", hex.c_str());
            return InboundResult{false, ""};
        }
        StoreResult res = m_store.put(r);
        if (!res.success) {
            key_type k = key_type::from_record(r);
            std::string key_str = k.print();
            log_error("inbound", "could not write record at key %s",
                      key_str.c_str());
            return InboundResult{false, ""};
        }
        if (res.delta.delta_type() == zsearch::DT_NO_CHANGE) {
            return InboundResult{true, ""};
        }
        return InboundResult{true, res.delta.SerializeAsString()};
    }
};

template <typename key_type>
class AnonHandler : public InboundHandler {
  private:
    AnonymousStore<key_type> m_store;

  public:
    AnonHandler(AnonymousStore<key_type>&& store) : m_store(std::move(store)) {}

    InboundResult handle(const string& serialized) {
        zsearch::AnonymousRecord r;
        if (!r.ParseFromString(serialized)) {
            return InboundResult{false, ""};
        }
        AnonymousResult res = m_store.put(r);
        if (!res.success) {
            return InboundResult{false, ""};
        }
        if (res.delta.delta_scope() ==
            zsearch::AnonymousDelta_DeltaScope_SCOPE_NO_CHANGE) {
            return InboundResult{true, ""};
        }
        return InboundResult{true, res.delta.SerializeAsString()};
    }
};

template <typename key_type>
class ExternalCertificateHandler : public InboundHandler {
  private:
    AnonymousStore<key_type> m_store;

  public:
    ExternalCertificateHandler(AnonymousStore<key_type>&& store)
            : m_store(std::move(store)) {}

    InboundResult handle(const string& serialized) {
        zsearch::ExternalCertificate r;
        if (!r.ParseFromString(serialized)) {
            return InboundResult{false, ""};
        }
        AnonymousResult res = m_store.put_external(r);
        if (!res.success) {
            return InboundResult{false, ""};
        }
        if (res.delta.delta_scope() ==
            zsearch::AnonymousDelta_DeltaScope_SCOPE_NO_CHANGE) {
            return InboundResult{true, ""};
        }
        return InboundResult{true, res.delta.SerializeAsString()};
    }
};

template <typename key_type>
class SCTHandler : public InboundHandler {
  private:
    AnonymousStore<key_type> m_store;

  public:
    SCTHandler(AnonymousStore<key_type>&& store) : m_store(std::move(store)) {}

    InboundResult handle(const string& serialized) {
        zsearch::SCT sct;
        if (!sct.ParseFromString(serialized)) {
            auto hex = hex_encode(serialized);
            log_error("sct handler", "could not serialize SCT record: %s",
                      hex.c_str());
            return InboundResult{false, ""};
        }
        AnonymousResult res = m_store.put_sct(sct);
        if (!res.success) {
            return InboundResult{false, ""};
        }
        if (res.delta.delta_scope() ==
            zsearch::AnonymousDelta_DeltaScope_SCOPE_NO_CHANGE) {
            return InboundResult{true, ""};
        }
        return InboundResult{true, res.delta.SerializeAsString()};
    }
};

template <typename key_type>
class ProcessedCertificateHandler : public InboundHandler {
  private:
    AnonymousStore<key_type> m_store;

  public:
    ProcessedCertificateHandler(AnonymousStore<key_type>&& store) : m_store(std::move(store)) {}

    InboundResult handle(const string& serialized) {
        zsearch::Certificate certificate;
        if (!certificate.ParseFromString(serialized)) {
            auto hex = hex_encode(serialized);
            log_error("processed_cert handler",
					"could not deserialize Certificate record: %s",
                    hex.c_str());
            return InboundResult{false, ""};
        }
        if (certificate.sha256fp().empty()) {
            auto hex = hex_encode(certificate.raw());
            log_error("processed_cert handler", "certificate had empty sha256fp: %s", hex.c_str());
            return InboundResult{true, ""};
	}
        AnonymousResult res = m_store.put_processed_cert(certificate);
        if (!res.success) {
            return InboundResult{false, ""};
        }
        if (res.delta.delta_scope() ==
            zsearch::AnonymousDelta_DeltaScope_SCOPE_NO_CHANGE) {
            return InboundResult{true, ""};
        }
        return InboundResult{true, res.delta.SerializeAsString()};
    }
};

static std::string hex_encode(const char* data, size_t len) {
    std::stringstream s;
    for (size_t i = 0; i < len; i++) {
        s << std::hex << static_cast<int>(data[i]);
    }
    return s.str();
}

void zdb::process_inbound(KafkaConsumerConnection* recv_topic,
                          KafkaProducerConnection* delta_topic,
                          InboundHandler* handler,
                          atomic<int>& server_state) {
    int failcount = 0;
    while (server_state != STATE_SHUTDOWN) {
        KafkaResult recv_result = recv_topic->consume();
        if (recv_result.status == KafkaResult::Status::OK) {
            // log_info("incoming", "handling incoming");
            InboundResult res = handler->handle(recv_result.data);
            if (res.success) {
                if (!res.serialized.empty()) {
                    // we have a delta we need to place in delta queue in kafka
                    // log_trace("inbound", "dealing with delta");
                    KafkaResult::Status status =
                            KafkaResult::Status::WOULD_BLOCK;
                    for (size_t attempts = 0;
                         status == KafkaResult::Status::WOULD_BLOCK;
                         ++attempts) {
                        if (attempts) {
                            log_info(
                                    "inbound",
                                    "%s internal queue full (%s), sleeping (try %llu)",
                                    recv_topic->topic_name().c_str(),
                                    recv_result.error.c_str(), attempts);
                            sleep(1);
                        }
                        auto result = delta_topic->produce_blocking(
                                res.serialized, 100);
                        status = result.status;
                        if (status == KafkaResult::Status::ERROR) {
                            log_fatal("inbound", "delta kafka error: %s",
                                      result.error.c_str());
                        }
                    }
                } else {
                    // log_trace("inbound", "no change");
                }
            } else {
                log_fatal("inbound", "error handling incoming record");
            }
            failcount = 0;
        } else if (recv_result.status == KafkaResult::Status::WOULD_BLOCK) {
            failcount++;
            if (failcount >= 100) {
                log_info("inbound", "empty queue %s, %s, sleeping",
                         recv_topic->topic_name().c_str(),
                         recv_result.error.c_str());
                sleep(10);
                failcount = 0;
            }
        } else {
            // Bad things happened
            log_fatal("inbound", "recv kafka error: %s",
                      recv_result.error.c_str());
        }
    }
    log_info("inbound", "%s thread shutting down.",
             recv_topic->topic_name().c_str());
}

template <typename conf_type>
InboundOptions make_partial_inbound_opts(const conf_type& c,
                                         size_t worker_thread_offset,
                                         KafkaConsumerConnection* incoming,
                                         KafkaProducerConnection* outgoing) {
    InboundOptions opt;
    opt.threads = c.worker_threads;
    opt.thread_id_offset = worker_thread_offset;
    opt.incoming = incoming;
    opt.outgoing = outgoing;
    return opt;
}

vector<InboundOptions> zdb::configure_inbound(ConfigValues* config_values,
                                              StoreContext* store_ctx,
                                              KafkaContext* kafka_ctx) {
    vector<InboundOptions> out;
    if (config_values->ipv4.enabled && config_values->ipv4.worker_threads > 0) {
        InboundOptions ipv4 = make_partial_inbound_opts(
                config_values->ipv4, 0, kafka_ctx->ipv4(),
                kafka_ctx->ipv4_deltas());
        for (size_t i = 0; i < ipv4.threads; ++i) {
            size_t tid = i + ipv4.thread_id_offset + 2;
            auto s = store_ctx->make_ipv4_store(tid);
            ipv4.handlers.emplace_back();
            ipv4.handlers.back().reset(new StoreHandler<IPv4Key>(std::move(s)));
        }
        out.push_back(std::move(ipv4));
    }
    if (config_values->domain.enabled &&
        config_values->domain.worker_threads > 0) {
        InboundOptions domain = make_partial_inbound_opts(
                config_values->domain, 0, kafka_ctx->domain(),
                kafka_ctx->domain_deltas());
        for (size_t i = 0; i < domain.threads; ++i) {
            size_t tid = i + domain.thread_id_offset + 2;
            auto s = store_ctx->make_domain_store(tid);
            domain.handlers.emplace_back();
            domain.handlers.back().reset(
                    new StoreHandler<DomainKey>(std::move(s)));
        }
        out.push_back(std::move(domain));
    }
    if (config_values->certificate.enabled &&
        config_values->certificate.worker_threads > 0) {
        InboundOptions certificate = make_partial_inbound_opts(
                config_values->certificate, 0, kafka_ctx->certificate(),
                kafka_ctx->certificates_to_process());

        for (size_t i = 0; i < certificate.threads; ++i) {
            size_t tid = i + certificate.thread_id_offset + 2;
            auto s = store_ctx->make_certificate_store(tid);
            certificate.handlers.emplace_back();
            certificate.handlers.back().reset(
                    new AnonHandler<HashKey>(std::move(s)));
        }
        out.push_back(std::move(certificate));
    }
    // additional queue associated with receiving certificates from external
    // sources e.g., certificate transparency logs and mozilla salesforce
    size_t external_certificate_offset = 0;
    if (config_values->external_certificate.enabled &&
        config_values->external_certificate.worker_threads > 0) {
        if (config_values->certificate.enabled) {
            external_certificate_offset +=
                    config_values->certificate.worker_threads;
        }
        InboundOptions external_certificate = make_partial_inbound_opts(
                config_values->external_certificate,
                external_certificate_offset, kafka_ctx->external_cert(),
                kafka_ctx->certificates_to_process());
        for (size_t i = 0; i < external_certificate.threads; ++i) {
            size_t tid = i + external_certificate.thread_id_offset + 2;
            auto s = store_ctx->make_certificate_store(tid);
            external_certificate.handlers.emplace_back();
            external_certificate.handlers.back().reset(
                    new ExternalCertificateHandler<HashKey>(std::move(s)));
        }
        out.push_back(std::move(external_certificate));
    }
    size_t sct_offset = external_certificate_offset;
    if (config_values->sct.enabled && config_values->sct.worker_threads > 0) {
        if (config_values->external_certificate.enabled) {
            sct_offset += config_values->external_certificate.worker_threads;
        }
        InboundOptions sct = make_partial_inbound_opts(
                config_values->sct, sct_offset, kafka_ctx->sct(),
                kafka_ctx->certificate_deltas());
        for (size_t i = 0; i < sct.threads; ++i) {
            size_t tid = i + sct.thread_id_offset + 2;
            auto s = store_ctx->make_certificate_store(tid);
            sct.handlers.emplace_back();
            sct.handlers.back().reset(new SCTHandler<HashKey>(std::move(s)));
        }
        out.push_back(std::move(sct));
    }
    size_t processed_cert_offset = sct_offset;
    if (config_values->processed_cert.enabled && config_values->processed_cert.worker_threads > 0) {
        if (config_values->sct.enabled) {
            processed_cert_offset += config_values->sct.worker_threads;
        }
        InboundOptions processed_cert = make_partial_inbound_opts(
                config_values->processed_cert, processed_cert_offset, kafka_ctx->processed_cert(),
                kafka_ctx->certificate_deltas());
        for (size_t i = 0; i < processed_cert.threads; ++i) {
            size_t tid = i + processed_cert.thread_id_offset + 2;
            auto s = store_ctx->make_certificate_store(tid);
            processed_cert.handlers.emplace_back();
            processed_cert.handlers.back().reset(new ProcessedCertificateHandler<HashKey>(std::move(s)));
        }
        out.push_back(std::move(processed_cert));
    }

    return out;
}

KafkaTopicPruneHandler::KafkaTopicPruneHandler(KafkaProducerConnection* kafka)
        : m_kafka(kafka) {}

KafkaTopicPruneHandler::~KafkaTopicPruneHandler() = default;

void KafkaTopicPruneHandler::handle_pruned(const StoreResult& pruned) {
    if (pruned.delta.delta_type() == zsearch::DeltaType::DT_NO_CHANGE) {
        return;
    }
    auto serialized = pruned.delta.SerializeAsString();
    handle_serialized(serialized);
}
void KafkaTopicPruneHandler::handle_pruned(const AnonymousResult& pruned) {
    if (pruned.delta.delta_type() == zsearch::AnonymousDelta::DT_RESERVED) {
        return;
    }
    auto serialized = pruned.delta.SerializeAsString();
    handle_serialized(serialized);
}

void KafkaTopicPruneHandler::handle_serialized(const std::string& s) {
    KafkaResult result = m_kafka->produce_blocking(s, 100);
    assert(result.status == KafkaResult::Status::OK);
}

GroupingPruneHandler::GroupingPruneHandler() = default;
GroupingPruneHandler::GroupingPruneHandler(GroupOn group_target)
        : m_group_target(group_target) {}
GroupingPruneHandler::GroupingPruneHandler(const GroupingPruneHandler&) =
        default;

GroupingPruneHandler::~GroupingPruneHandler() {
    do_prune();
}

void GroupingPruneHandler::handle_pruned(const StoreResult& pruned) {
    switch (m_group_target) {
        case GROUP_IP:
            if (pruned.delta.ip() != m_ip) {
                do_prune();
                m_ip = pruned.delta.ip();
            }
            break;
        case GROUP_DOMAIN:
            if (pruned.delta.domain() != m_domain) {
                do_prune();
                m_domain = pruned.delta.domain();
            }
            break;
        default:
            assert(false);
            break;
    }

    if (pruned.delta.delta_type() == zsearch::DeltaType::DT_NO_CHANGE) {
        return;
    }
    m_latest = pruned;
    m_have_latest = true;
}

void GroupingPruneHandler::handle_pruned(const AnonymousResult& pruned) {
    assert(m_impl);
    m_impl->handle_pruned(pruned);
}

void GroupingPruneHandler::do_prune() {
    if (!m_have_latest) {
        return;
    }
    assert(m_impl);
    m_impl->handle_pruned(m_latest);
    m_have_latest = false;
}
