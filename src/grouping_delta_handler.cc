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

#include "grouping_delta_handler.h"
#include "store.h"

namespace zdb {

GroupingDeltaHandler::GroupingDeltaHandler() = default;
GroupingDeltaHandler::GroupingDeltaHandler(GroupOn group_target)
    : m_group_target(group_target) {}

GroupingDeltaHandler::~GroupingDeltaHandler() {
  do_prune();
}

void GroupingDeltaHandler::handle_delta(const StoreResult& res) {
  switch (m_group_target) {
    case GROUP_IP:
      if (res.delta.ip() != m_ip) {
        do_prune();
        m_ip = res.delta.ip();
      }
      break;
    case GROUP_DOMAIN:
      if (res.delta.domain() != m_domain) {
        do_prune();
        m_domain = res.delta.domain();
      }
      break;
    default:
      assert(false);
      break;
  }

  if (res.delta.delta_type() == zsearch::DeltaType::DT_NO_CHANGE) {
    return;
  }
  m_latest = res;
  m_have_latest = true;
}

void GroupingDeltaHandler::handle_delta(const AnonymousResult& res) {
  assert(m_impl);
  m_impl->handle_delta(res);
}

void GroupingDeltaHandler::do_prune() {
  if (!m_have_latest) {
    return;
  }
  assert(m_impl);
  m_impl->handle_delta(m_latest);
  m_have_latest = false;
}

};  // namespace zdb
