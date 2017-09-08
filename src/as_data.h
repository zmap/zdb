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

#ifndef ZDB_AS_DATA_H
#define ZDB_AS_DATA_H

#include <atomic>
#include <fstream>
#include <list>
#include <memory>
#include <mutex>
#include <string>

#include <iptree/iptree.h>

#include "macros.h"
#include "zsearch_definitions/search.pb.h"

namespace zdb {

struct ASData {
  ASData() = default;

  iptree_node_t* iptree = nullptr;
  std::list<zsearch::ASAtom> atoms;
};

class ASTree {
 public:
  ASTree();

  // Loads a description of ASes from JSON, and builds a tree. Returns false
  // on error.
  bool load_json(std::ifstream& as_stream);

  size_t size() const;

  // The result of indexing into an ASTree.
  struct Lookup {
    Lookup() = default;
    Lookup(const Lookup&) = default;
    Lookup(Lookup&&);

    // True if the lookup was covered.
    bool found = false;

    // True if the lookup matched exactly (e.g. on a /32).
    bool exact = false;

    // Populated when `found = true`.
    zsearch::ASAtom as_atom;

    // Returns a "failed" lookup with `found = exact = false`.
    static const Lookup& failure();
  };

  class Handle {
   public:
    Lookup operator[](uint32_t ip) const;
    Lookup operator[](const std::string& ip) const;

   private:
    Handle(std::shared_ptr<ASData>* as_data_ptr);
    std::shared_ptr<ASData>* m_as_data_ptr;

    friend class ASTree;
  };

  Handle get_handle();

 private:
  std::shared_ptr<ASData> load_json_impl(std::ifstream& as_stream);

  std::shared_ptr<ASData> m_as_data;
  DISALLOW_COPY_ASSIGN(ASTree);
};

}  // namespace zdb

#endif /* ZDB_AS_DATA_H */
