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
#include "protocols.pb.h"
#include "zmap/logger.h"

using namespace zsearch;

namespace zdb {

std::string get_proto_name(int proto) {
  std::string s = Protocol_Name(static_cast<Protocol>(proto)).substr(6);
  std::transform(s.begin(), s.end(), s.begin(), ::tolower);
  return s;
}

std::string get_subproto_name(int proto, int subproto) {
  std::string s =
      Subprotocol_Name(static_cast<Subprotocol>(subproto)).substr(9);
  std::transform(s.begin(), s.end(), s.begin(), ::tolower);
  return s;
}

}  // namespace zdb
