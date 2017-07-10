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

#ifndef ZDB_SRC_CERTIFICATES_H
#define ZDB_SRC_CERTIFICATES_H

#include <ctime>
#include <set>
#include <string>

#include "zsearch_definitions/search.pb.h"

namespace zdb {

const std::string kUnknownTranslation = "unknown";

std::string translate_certificate_source(int source);

std::string translate_certificate_type(int type);

std::string translate_certificate_parse_status(int status);

std::string translate_zlint_lint_result_status(int result_status);

bool certificate_valid_at(const zsearch::Certificate& cert, std::time_t now);

void expire_status(zsearch::RootStoreStatus* expired);

bool certificate_has_ct_info(const zsearch::Certificate& c);

bool certificate_has_google_ct(const zsearch::Certificate& c);

bool certificate_has_valid_set(const zsearch::Certificate& c);

bool certificate_has_was_valid_set(const zsearch::Certificate& c);

bool certificate_is_or_was_trusted(const zsearch::Certificate& c);

void certificate_add_types_to_set(const zsearch::Certificate& c,
                                  std::set<std::string>* out);

bool certificate_has_ccadb(const zsearch::Certificate& c);

}  // namespace zdb

#endif /* ZDB_SRC_CERTIFICATES_H */
