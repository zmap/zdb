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

#include <memory>
#include <string>

#include "delta_handler.h"
#include "macros.h"
#include "store.h"

namespace zdb {

class GroupingDeltaHandler : public DeltaHandler {
  public:
    enum GroupOn {
        GROUP_IP,
        GROUP_DOMAIN,
    };

    GroupingDeltaHandler();
    GroupingDeltaHandler(GroupOn group_target);
    ~GroupingDeltaHandler();

    void handle_delta(const StoreResult& res) override;
    void handle_delta(const AnonymousResult& res) override;

    void set_underlying_handler(std::unique_ptr<DeltaHandler> impl) {
        m_impl = std::move(impl);
    }

  private:
    void do_prune();

    GroupOn m_group_target = GROUP_IP;

    uint32_t m_ip = 0;
    std::string m_domain;

    std::unique_ptr<DeltaHandler> m_impl = nullptr;
    bool m_have_latest = false;
    StoreResult m_latest;

    DISALLOW_COPY_ASSIGN(GroupingDeltaHandler);
};

}  // namespace zdb
