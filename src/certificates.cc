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

#include <cstdint>
#include <iostream>
#include <type_traits>

#include "certificates.h"
#include "util/strings.h"

namespace zdb {

namespace {

// TODO: Write function to apply a predicate to every CTServerStatus or
// RootStoreStatus, with the goal of reducing duplicated code in the
// certificate_has_X functions.

}  // namespace

std::string translate_certificate_source(int source) {
    switch (source) {
        case zsearch::CERTIFICATE_SOURCE_RESERVED:
            return "reserved";
        case zsearch::CERTIFICATE_SOURCE_UNKNOWN:
            return "unknown";
        case zsearch::CERTIFICATE_SOURCE_SCAN:
            return "scan";
        case zsearch::CERTIFICATE_SOURCE_CT:
            return "ct";
        case zsearch::CERTIFICATE_SOURCE_MOZILLA_SALESFORCE:
            return "mozilla_salesforce";
        case zsearch::CERTIFICATE_SOURCE_RESEARCH:
            return "research";
        case zsearch::CERTIFICATE_SOURCE_RAPID7:
            return "rapid7";
        case zsearch::CERTIFICATE_SOURCE_HUBBLE:
            return "hubble";
        case zsearch::CERTIFICATE_SOURCE_CT_CHAIN:
            return "ct_chain";
        default:
            return kUnknownTranslation;
    }
}

std::string translate_certificate_type(int type) {
    switch (type) {
        case zsearch::CERTIFICATE_TYPE_RESERVED:
            return "reserved";
        case zsearch::CERTIFICATE_TYPE_UNKNOWN:
            return "unknown";
        case zsearch::CERTIFICATE_TYPE_LEAF:
            return "leaf";
        case zsearch::CERTIFICATE_TYPE_INTERMEDIATE:
            return "intermediate";
        case zsearch::CERTIFICATE_TYPE_ROOT:
            return "root";
        default:
            return kUnknownTranslation;
    }
}

bool certificate_valid_at(const zsearch::Certificate& cert, std::time_t now) {
    // Compile-time checks on std::time_t
    static_assert(std::is_integral<time_t>::value, "time not an integer");
    static_assert(std::is_unsigned<time_t>::value ||
                          (sizeof(std::time_t) > sizeof(uint32_t)),
                  "signed 32-bit time value");
    static_assert(sizeof(std::time_t) >= sizeof(uint32_t),
                  "time not wide enough");

    uint32_t not_before = cert.not_valid_before();
    uint32_t not_after = cert.not_valid_after();
    return not_before < now && now < not_after;
}

void expire_status(zsearch::RootStoreStatus* expired) {
    // Update the status to reflect expiration. Expired certificates can't be
    // valid and have no trusted path.
    expired->set_trusted_path(false);
    expired->set_valid(false);
    return;
}

bool certificate_has_ct_info(const zsearch::Certificate& c) {
    const google::protobuf::Descriptor* ct_descriptor = c.ct().GetDescriptor();
    for (int i = 0; i < ct_descriptor->field_count(); ++i) {
        const google::protobuf::FieldDescriptor* ct_server_field =
                ct_descriptor->field(i);
        assert(ct_server_field);
        const google::protobuf::Descriptor* ct_server_descriptor =
                ct_server_field->message_type();
        if (!ct_server_descriptor) {
            continue;
        }
        if (ct_server_descriptor->name() != "CTServerStatus") {
            continue;
        }
        const google::protobuf::FieldDescriptor* index_field =
                ct_server_descriptor->FindFieldByName("index");
        if (!index_field) {
            continue;
        }
        google::protobuf::FieldDescriptor::Type index_type =
                index_field->type();
        if (index_type != google::protobuf::FieldDescriptor::TYPE_INT64) {
            continue;
        }
        const google::protobuf::Message& ct_server_msg =
                c.ct().GetReflection()->GetMessage(c.ct(), ct_server_field);
        int64_t ct_index = ct_server_msg.GetReflection()->GetInt64(
                ct_server_msg, index_field);
        if (ct_index > 0) {
            return true;
        }
    }
    return false;
}

bool certificate_has_google_ct(const zsearch::Certificate& c) {
    const google::protobuf::Descriptor* ct_descriptor = c.ct().GetDescriptor();
    for (int i = 0; i < ct_descriptor->field_count(); ++i) {
        const google::protobuf::FieldDescriptor* ct_server_field =
                ct_descriptor->field(i);
        assert(ct_server_field);
        const google::protobuf::Descriptor* ct_server_descriptor =
                ct_server_field->message_type();
        if (!ct_server_descriptor) {
            continue;
        }
        if (ct_server_descriptor->name() != "CTServerStatus") {
            continue;
        }
        if (!util::Strings::has_prefix("google", ct_server_field->name())) {
            continue;
        }
        const google::protobuf::FieldDescriptor* index_field =
                ct_server_descriptor->FindFieldByName("index");
        if (!index_field) {
            continue;
        }
        google::protobuf::FieldDescriptor::Type index_type =
                index_field->type();
        if (index_type != google::protobuf::FieldDescriptor::TYPE_INT64) {
            continue;
        }
        const google::protobuf::Message& ct_server_msg =
                c.ct().GetReflection()->GetMessage(c.ct(), ct_server_field);
        int64_t ct_index = ct_server_msg.GetReflection()->GetInt64(
                ct_server_msg, index_field);
        if (ct_index > 0) {
            return true;
        }
    }
    return false;
}

bool certificate_has_valid_set(const zsearch::Certificate& c) {
    const google::protobuf::Descriptor* validation_descriptor =
            c.validation().GetDescriptor();
    for (int i = 0; i < validation_descriptor->field_count(); ++i) {
        const google::protobuf::FieldDescriptor* root_store_status_field =
                validation_descriptor->field(i);
        assert(root_store_status_field);
        const google::protobuf::Descriptor* root_store_status_descriptor =
                root_store_status_field->message_type();
        if (!root_store_status_descriptor) {
            continue;
        }
        if (root_store_status_descriptor->name() != "RootStoreStatus") {
            continue;
        }
        const google::protobuf::FieldDescriptor* valid_field =
                root_store_status_descriptor->FindFieldByName("valid");
        if (!valid_field) {
            continue;
        }
        google::protobuf::FieldDescriptor::Type valid_type =
                valid_field->type();
        if (valid_type != google::protobuf::FieldDescriptor::TYPE_BOOL) {
            continue;
        }
        const google::protobuf::Message& root_store_status_msg =
                c.validation().GetReflection()->GetMessage(
                        c.validation(), root_store_status_field);
        bool valid = root_store_status_msg.GetReflection()->GetBool(
                root_store_status_msg, valid_field);
        if (valid) {
            return true;
        }
    }
    return false;
}

bool certificate_has_was_valid_set(const zsearch::Certificate& c) {
    const google::protobuf::Descriptor* validation_descriptor =
            c.validation().GetDescriptor();
    for (int i = 0; i < validation_descriptor->field_count(); ++i) {
        const google::protobuf::FieldDescriptor* root_store_status_field =
                validation_descriptor->field(i);
        assert(root_store_status_field);
        const google::protobuf::Descriptor* root_store_status_descriptor =
                root_store_status_field->message_type();
        if (!root_store_status_descriptor) {
            continue;
        }
        if (root_store_status_descriptor->name() != "RootStoreStatus") {
            continue;
        }
        const google::protobuf::FieldDescriptor* was_valid_field =
                root_store_status_descriptor->FindFieldByName("was_valid");
        if (!was_valid_field) {
            continue;
        }
        google::protobuf::FieldDescriptor::Type was_valid_type =
                was_valid_field->type();
        if (was_valid_type != google::protobuf::FieldDescriptor::TYPE_BOOL) {
            continue;
        }
        const google::protobuf::Message& root_store_status_msg =
                c.validation().GetReflection()->GetMessage(
                        c.validation(), root_store_status_field);
        bool was_valid = root_store_status_msg.GetReflection()->GetBool(
                root_store_status_msg, was_valid_field);
        if (was_valid) {
            return true;
        }
    }
    return false;
}

void certificate_add_types_to_set(const zsearch::Certificate& c,
                                  std::set<std::string>* out) {
    const google::protobuf::Descriptor* validation_descriptor =
            c.validation().GetDescriptor();
    for (int i = 0; i < validation_descriptor->field_count(); ++i) {
        const google::protobuf::FieldDescriptor* root_store_status_field =
                validation_descriptor->field(i);
        assert(root_store_status_field);
        const google::protobuf::Descriptor* root_store_status_descriptor =
                root_store_status_field->message_type();
        if (!root_store_status_descriptor) {
            continue;
        }
        if (root_store_status_descriptor->name() != "RootStoreStatus") {
            continue;
        }
        const google::protobuf::FieldDescriptor* certificate_type_field =
                root_store_status_descriptor->FindFieldByName("type");
        if (!certificate_type_field) {
            continue;
        }
        const google::protobuf::EnumDescriptor* certificate_type_descriptor =
                certificate_type_field->enum_type();
        if (!certificate_type_descriptor) {
            continue;
        }
        if (certificate_type_descriptor->name() != "CertificateType") {
            continue;
        }
        const google::protobuf::Message& root_store_status_msg =
                c.validation().GetReflection()->GetMessage(
                        c.validation(), root_store_status_field);

        const google::protobuf::EnumValueDescriptor*
                certificate_type_value_descriptor =
                        root_store_status_msg.GetReflection()->GetEnum(
                                root_store_status_msg, certificate_type_field);
        int cert_type = certificate_type_value_descriptor->number();
        if (cert_type == zsearch::CERTIFICATE_TYPE_RESERVED) {
            continue;
        }
        out->insert(translate_certificate_type(cert_type));
    }
    return;
}

bool certificate_has_ccadb(const zsearch::Certificate& c) {
    const zsearch::MozillaSalesForceStatus& ccadb = c.audit().mozilla();
    return ccadb.was_in() || ccadb.current_in();
}

}  // namespace zdb
