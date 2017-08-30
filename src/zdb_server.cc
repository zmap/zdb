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

#include <algorithm>
#include <fstream>
#include <future>
#include <iostream>
#include <thread>
#include <vector>

#include <gflags/gflags.h>

#include <json/json.h>

#include <zmap/logger.h>

#include "admin.h"
#include "as_data.h"
#include "context.h"
#include "inbound.h"
#include "location.h"
#include "query.h"
#include "record.h"
#include "utility.h"

using namespace zdb;

#define ADMIN_SERVER_PORT 8080
#define QUERY_SERVER_PORT 9090

void sig_handler(int signo) {
    const char* signame;
    if (signo == SIGINT) {
        signame = "SIGINT";
    } else if (signo == SIGTERM) {
        signame = "SIGTERM";
    }
    zdb::server_state = STATE_SHUTDOWN;
    log_info("server", "received %s. serverstate => STATE_SHUTDOWN", signame);
}

DEFINE_string(config, "conf/test_conf.json", "path to configuration file");
DEFINE_string(log_file, "-", "file to log to (defaults to stderr)");
DEFINE_string(geolite_file, "geo.mmdb", "geolite file");
DEFINE_string(geo_file, "geo.mmdb", "full geo file");
DEFINE_string(as_file, "", "AS initial data (optional)");

DEFINE_string(kafka_brokers, "127.0.0.1:9092", "Kafka brokers CSV");

DEFINE_uint64(admin_port, 8080, "admin server port");
DEFINE_uint64(query_port, 9090, "query server port");

DEFINE_bool(syslog, false, "whether or not to additionally log to syslog");
DEFINE_bool(repair, false, "run a repair before opening the databases");

int main(int argc, char* argv[]) {
    zdb::server_state = STATE_OK;

    google::ParseCommandLineFlags(&argc, &argv, true);
    FILE* log_file = stderr;
    if (FLAGS_log_file != "-") {
        log_file = fopen(FLAGS_log_file.c_str(), "w+");
    }
    int log_to_syslog = 1 ? FLAGS_syslog : 0;
    if (log_file == nullptr) {
        log_init(stderr, ZLOG_TRACE, log_to_syslog, nullptr);
        log_fatal("server", "unable to open log file %s",
                  FLAGS_log_file.c_str());
    }
    if (int ret = log_init(log_file, ZLOG_TRACE, 0, nullptr)) {
        log_init(stderr, ZLOG_TRACE, log_to_syslog, nullptr);
        log_fatal("server", "unable to initiate logging (error code %d)", ret);
    }

    std::ifstream config_doc(FLAGS_config, std::ifstream::binary);
    if (!config_doc) {
        log_fatal("server", "unable to open configuration file %s",
                  FLAGS_config.c_str());
    }

    // Try to setup maxmind data
    log_info("server", "loading location data");
    std::unique_ptr<LocationContext> location_context(
            new LocationContext(FLAGS_geolite_file, FLAGS_geo_file));
    assert(location_context->is_open());

    // Try to set up AS data
    log_info("server", "initializing AS tree");
    std::unique_ptr<ASTree> as_tree(new ASTree);
    assert(as_tree);

    if (FLAGS_as_file != "") {
        log_info("server", "loading initial AS data from %s",
                 FLAGS_as_file.c_str());
        std::ifstream as_file(FLAGS_as_file);
        if (!as_file) {
            log_fatal("server", "could not open initial AS data");
        }
        bool did_update = as_tree->load_json(as_file);
        if (!did_update) {
            log_fatal("server", "parsing initial AS data failed");
        }
    }

    // Try to set up RocksDB
    log_info("server", "loading databases");
    Json::Value config_root;
    config_doc >> config_root;

    ConfigValues config_values;
    bool config_ok = ConfigValues::from_json(config_root, &config_values);
    if (!config_ok) {
        log_fatal("server", "unable to load values from configuration");
    }

    bool run_repair = FLAGS_repair;
    std::unique_ptr<DBContext> db_ctx =
            create_db_context_from_config_values(config_values);
    if (db_ctx == nullptr) {
        log_fatal("server", "unable to load databases");
    }

    if (!db_ctx->open_all()) {
      log_error("server", "unable to open databases");
      if (run_repair) {
        log_warn("server", "attempting rocksdb repair");
        if (!db_ctx->repair()) {
          log_fatal("server", "unable to repair rocksdb");
        }
        log_info("server", "repaired rocksdb, opening");
        if (!db_ctx->open_all()) {
          log_fatal("server", "could not open rocksdb after repairing");
        }
      } else {
        log_fatal("server", "could not open databases");
      }
    }

    std::unique_ptr<LockContext> lock_context =
            create_lock_context_from_config_values(config_values);
    if (lock_context == nullptr) {
        log_fatal("server", "unable to create locks");
    }

    std::unique_ptr<StoreContext> store_ctx(
            new StoreContext(std::move(db_ctx), std::move(lock_context),
                             std::move(location_context), std::move(as_tree)));
    if (!store_ctx) {
        log_fatal("server", "unabled to create stores");
    }

    std::unique_ptr<KafkaContext> kafka_ctx =
            create_kafka_context_from_config_values(FLAGS_kafka_brokers,
                                                    config_values);

    if (!kafka_ctx) {
        log_fatal("server", "unable to create kakfa connections");
    }

    DeltaContext delta_ctx(kafka_ctx.get());

    log_info("server", "registering signal handlers");
    if (signal(SIGINT, sig_handler) == SIG_ERR) {
        log_fatal("server", "unable to register SIGINT handler");
    }
    if (signal(SIGTERM, sig_handler) == SIG_ERR) {
        log_fatal("server", "unable to register SIGTERM handler");
    }

    std::vector<InboundOptions> queues =
            configure_inbound(&config_values, store_ctx.get(), kafka_ctx.get());

    std::vector<std::thread> threads;
    for (auto& queue : queues) {
        log_info("server", "starting %i threads for queue %s to %s",
                 queue.threads, queue.incoming->topic_name().c_str(),
                 queue.outgoing->topic_name().c_str());
        for (const auto& handler : queue.handlers) {
            threads.emplace_back(process_inbound, queue.incoming,
                                 queue.outgoing, handler.get(),
                                 std::ref(server_state));
        }
    }
    // make query and admin servers
    std::shared_ptr<QueryServer> query_server =
            make_query_server(FLAGS_query_port, store_ctx.get());
    std::shared_ptr<AdminServer> admin_server =
            make_admin_server(FLAGS_admin_port, store_ctx.get(), &delta_ctx);
    log_info("server", "launching admin thread bound to port %d",
             FLAGS_admin_port);
    std::thread admin_thread(
            [admin_server]() { admin_server->server->Wait(); });
    log_info("server", "launching query thread bound to port %d",
             FLAGS_query_port);
    std::thread query_thread(
            [query_server]() { query_server->server->Wait(); });

    while (server_state == STATE_OK) {
        sleep(3);
    }
    for (auto& t : threads) {
        t.join();
    }
    log_info("server", "shutting down query thread");
    query_server->server->Shutdown();
    query_thread.join();
    log_info("server", "shutting down admin thread");
    admin_server->server->Shutdown();
    admin_thread.join();

    return EXIT_SUCCESS;
}
