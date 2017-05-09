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

#include "anonymous_store.h"

using namespace std;
using namespace zdb;

AnonymousResult::AnonymousResult() : success(false) {}

AnonymousResult::AnonymousResult(AnonymousResult&& rhs) : success(rhs.success) {
    delta.Swap(&rhs.delta);
}

AnonymousResult& AnonymousResult::operator=(AnonymousResult&& rhs) {
    success = rhs.success;
    delta.Swap(&rhs.delta);
    return *this;
}

AnonymousResult AnonymousResult::failure() {
    AnonymousResult out;
    return out;
}

AnonymousResult AnonymousResult::no_change() {
    AnonymousResult out;
    out.delta.set_delta_type(zsearch::AnonymousDelta_DeltaType_DT_UPDATE);
    out.delta.set_delta_scope(
            zsearch::AnonymousDelta_DeltaScope_SCOPE_NO_CHANGE);
    out.success = true;
    return out;
}