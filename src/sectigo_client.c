/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "certifier/sectigo_client.h"
#include <certifier/base64.h>
#include <certifier/certifier.h>
#include "certifier/code_utils.h"
#include "certifier/types.h"
#include "certifier/certifierclient.h"
#include "certifier/certifier_internal.h"
#include "certifier/http.h"
#include "certifier/log.h"
#include "certifier/parson.h"
#include "certifier/util.h"
#include "certifier/error.h"
#include "certifier/property_internal.h"

#include <errno.h>
#include <stdbool.h>
#include <pthread.h>

Certifier * get_sectigo_certifier_instance()
{
    static Certifier * certifier = NULL;

    if (certifier == NULL)
    {
        certifier = certifier_new();
        certifier_set_property(certifier, CERTIFIER_OPT_LOG_LEVEL, (void *) (size_t) 0);
        
        // Load Sectigo config file if it exists
        const char *cfg_filename = certifier_get_property(certifier, CERTIFIER_OPT_CFG_FILENAME);
        if (cfg_filename && access(cfg_filename, F_OK) == 0) {
            sectigo_load_cfg_file(certifier);
        }
    }
    return certifier;
}


SECTIGO_CLIENT_ERROR_CODE xc_sectigo_get_default_cert_param(sectigo_get_cert_param_t * params)
{
    Certifier * certifier = get_sectigo_certifier_instance();

    memset(params, 0, sizeof(sectigo_get_cert_param_t));

    void * param = NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_AUTH_TOKEN);
    params->auth_token = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_COMMON_NAME);
    params->common_name = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_GROUP_NAME);
    params->group_name = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_GROUP_EMAIL);
    params->group_email = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_ID);
    params->id = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_OWNER_FIRST_NAME);
    params->owner_first_name = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_OWNER_LAST_NAME);
    params->owner_last_name = param ? XSTRDUP((const char *)param) : NULL;
    
    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_EMPLOYEE_TYPE);
    params->employee_type = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_SERVER_PLATFORM);
    params->server_platform = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_PROJECT_NAME);
    params->project_name = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_BUSINESS_JUSTIFICATION);
    params->business_justification = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_SUBJECT_ALT_NAMES);
    params->subject_alt_names = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_IP_ADDRESSES);
    params->ip_addresses = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_CERT_TYPE);
    params->cert_type = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_OWNER_PHONE_NUMBER);
    params->owner_phone_number = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_OWNER_EMAIL);
    params->owner_email = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_URL);
    params->sectigo_url = param ? XSTRDUP((const char *)param) : NULL;

    param = certifier_get_property(certifier, CERTIFIER_OPT_SECTIGO_SENSITIVE);
    params->sensitive = param ? *((bool *)param) : false;

    return SECTIGO_CLIENT_SUCCESS;
}

CertifierError sectigo_client_request_certificate(CertifierPropMap * props, const unsigned char * csr,
const char * node_address, const char * certifier_id, char ** out_cert)
{
    Certifier *certifier = get_sectigo_certifier_instance();
    CertifierError rc = CERTIFIER_ERROR_INITIALIZER;
    JSON_Value *root_value = NULL;
    JSON_Object *root_obj = NULL;
    char *json_body = NULL;
    
    if (out_cert == NULL)
    {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg  = util_format_error_here("out cert cannot be null");
        return rc;
    }

    char auth_header[VERY_LARGE_STRING_SIZE * 4] = "";
    char tracking_header[LARGE_STRING_SIZE]      = "";
    char source_header[SMALL_STRING_SIZE]        = "";
    JSON_Object * parsed_json_object_value       = NULL;
    JSON_Value * parsed_json_root_value          = NULL;
    char * serialized_string                     = NULL;
    http_response * resp                         = NULL;
    const char * tracking_id                     = property_get(props, CERTIFIER_OPT_TRACKING_ID);
    const char * bearer_token                    = property_get(props, CERTIFIER_OPT_SECTIGO_AUTH_TOKEN);
    const char * source                          = property_get(props, CERTIFIER_OPT_SECTIGO_SOURCE);
    const char * sectigo_url                   = property_get(props, CERTIFIER_OPT_SECTIGO_URL);

    if (!bearer_token) {
        log_error("Missing CERTIFIER_OPT_SECTIGO_AUTH_TOKEN");
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg  = util_format_error_here("Bearer token is missing");
        goto cleanup;
    }
    if (!sectigo_url) {
        log_error("Missing CERTIFIER_OPT_SECTIGO_URL");
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg  = util_format_error_here("Sectigo URL is missing");
        goto cleanup;
    }
    if (!source) {
        log_error("Missing CERTIFIER_OPT_SECTIGO_SOURCE");
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg  = util_format_error_here("Source is missing");
        goto cleanup;
    }

    log_debug("Tracking ID is: %s\n", tracking_id);
    log_debug("Source ID is: %s\n", source);

    if (bearer_token != NULL) {
    snprintf(auth_header, sizeof(auth_header), "Authorization: %s", bearer_token);
    }
    snprintf(tracking_header, sizeof(tracking_header), "x-xpki-request-id: %s", tracking_id);
    snprintf(source_header, sizeof(source_header), "x-xpki-source: %s", source);

    const char *headers[] = {
        "Accept: */*",
        "Connection: keep-alive",
        "cache-control: no-cache",
        "Content-Type: application/json",
        source_header,
        tracking_header,
        "x-xpki-partner-id: comcast",
        auth_header,
        NULL
    };

    if (util_is_empty(source))
    {
        rc.application_error_code = CERTIFIER_ERR_EMPTY_OR_INVALID_PARAM_1;
        rc.application_error_msg  = util_format_error_here("CERTIFIER_OPT_SECTIGO_SOURCE must be set to a non-empty string!");
        goto cleanup;
    }

    CertifierError csr_rc = sectigo_generate_certificate_signing_request(certifier, &serialized_string);
    
    if (csr_rc.application_error_code != 0 || serialized_string == NULL) {
        rc.application_error_code = csr_rc.application_error_code;
        rc.application_error_msg = csr_rc.application_error_msg;
        goto cleanup;
    }

    // Take Mutex
    if (pthread_mutex_lock(&lock) != 0)
    {
        rc.application_error_code = 17;
        rc.application_error_msg = "sectigo_client_request_certificate: pthread_mutex_lock failed";
        goto cleanup;
    }
    // Give Mutex
    if (pthread_mutex_unlock(&lock) != 0)
    {
        rc.application_error_code = 18;
        rc.application_error_msg = "sectigo_client_request_certificate: pthread_mutex_unlock failed";
        goto cleanup;
    }

    sectigo_get_cert_param_t params;
    xc_sectigo_get_default_cert_param(&params);

    // Build JSON body
    root_value = json_value_init_object();
    root_obj = json_value_get_object(root_value);

    json_object_set_string(root_obj, "certificateSigningRequest", serialized_string);

    json_object_set_string(root_obj, "commonName", params.common_name ? params.common_name : "");
    json_object_set_string(root_obj, "groupName", params.group_name ? params.group_name : "");
    json_object_set_string(root_obj, "groupEmailAddress", params.group_email ? params.group_email : "");
    json_object_set_string(root_obj, "id", params.id ? params.id : "");
    json_object_set_string(root_obj, "ownerFirstName", params.owner_first_name ? params.owner_first_name : "");
    json_object_set_string(root_obj, "ownerLastName", params.owner_last_name ? params.owner_last_name : "");
    json_object_set_string(root_obj, "employeeType", params.employee_type ? params.employee_type : "");
    json_object_set_string(root_obj, "serverPlatform", params.server_platform ? params.server_platform : "");
    json_object_set_string(root_obj, "projectName", params.project_name ? params.project_name : "");
    json_object_set_string(root_obj, "businessJustification", params.business_justification ? params.business_justification : "");
    json_object_set_string(root_obj, "certificateType", params.cert_type ? params.cert_type : "");
    json_object_set_string(root_obj, "ownerPhoneNumber", params.owner_phone_number ? params.owner_phone_number : "");
    json_object_set_string(root_obj, "ownerEmailAddress", params.owner_email ? params.owner_email : "");
    json_object_set_string(root_obj, "certifierUrl", params.sectigo_url ? params.sectigo_url : "");
    json_object_set_value(root_obj, "sensitive", json_value_init_boolean(params.sensitive));
    // Always set subjectAltNames and ipAddresses, even if empty

    // subjectAltNames as array
    JSON_Value *san_array = json_value_init_array();
    JSON_Array *san_json_array = json_value_get_array(san_array);
    if (params.subject_alt_names && strlen(params.subject_alt_names) > 0) {
        char *san_copy = XSTRDUP(params.subject_alt_names);
        char *token = strtok(san_copy, ",");
        while (token) {
            json_array_append_value(san_json_array, json_value_init_string(token));
            token = strtok(NULL, ",");
        }
        XFREE(san_copy);
    }
    json_object_set_value(root_obj, "subjectAltNames", san_array);

    // ipAddresses as array
    JSON_Value *ip_array = json_value_init_array();
    JSON_Array *ip_json_array = json_value_get_array(ip_array);
    if (params.ip_addresses && strlen(params.ip_addresses) > 0) {
        char *ip_copy = XSTRDUP(params.ip_addresses);
        char *token = strtok(ip_copy, ",");
        while (token) {
            json_array_append_value(ip_json_array, json_value_init_string(token));
            token = strtok(NULL, ",");
        }
        XFREE(ip_copy);
    }
    
    json_object_set_value(root_obj, "ipAddresses", ip_array);
    json_body = json_serialize_to_string(root_value);

    resp = http_post(props, sectigo_url, headers, json_body);
    if (resp == NULL)
    {
        goto cleanup;
    }

    rc.application_error_code = resp->error;

    // Check for errors
    if (resp->error != 0)
    {
        rc.application_error_msg = util_format_curl_error("sectigo_client_request_certificate", resp->http_code, resp->error,
                                                          resp->error_msg, resp->payload, __FILE__, __LINE__);
        goto cleanup;
    }

    if (resp->payload == NULL)
    {
        log_error("ERROR: Failed to populate payload");
        goto cleanup;
    }

    parsed_json_root_value = json_parse_string_with_comments(resp->payload);
    if (json_value_get_type(parsed_json_root_value) != JSONObject)
    {
        rc.application_error_msg =
            util_format_curl_error("sectigo_client_request_certificate", resp->http_code, resp->error,
                                   "Could not parse JSON.  Expected it to be an array.", resp->payload, __FILE__, __LINE__);
        goto cleanup;
    }

    parsed_json_object_value = json_value_get_object(parsed_json_root_value);

    if (parsed_json_object_value == NULL)
    {
        rc.application_error_msg =
            util_format_curl_error("sectigo_client_request_certificate", resp->http_code, resp->error,
                                   "Could not parse JSON.  parsed_json_object_value is NULL!.", resp->payload, __FILE__, __LINE__);
        goto cleanup;
    }

cleanup:
    http_free_response(resp);

    if (parsed_json_root_value) json_value_free(parsed_json_root_value);

    XFREE(serialized_string);

    if (json_body) json_free_serialized_string(json_body);
    if (root_value) json_value_free(root_value);
    
    return rc;
}

SECTIGO_CLIENT_ERROR_CODE xc_sectigo_get_cert(sectigo_get_cert_param_t * params)
{
    Certifier *certifier = get_sectigo_certifier_instance();

    // Build JSON body
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_obj = json_value_get_object(root_value);

    // Add all parameters to JSON body using passed-in params
    if (params->common_name)
        json_object_set_string(root_obj, "commonName", params->common_name);
    if (params->group_name)
        json_object_set_string(root_obj, "groupName", params->group_name);
    if (params->group_email)
        json_object_set_string(root_obj, "groupEmailAddress", params->group_email);
    if (params->id)
        json_object_set_string(root_obj, "id", params->id);
    if (params->owner_first_name)
        json_object_set_string(root_obj, "ownerFirstName", params->owner_first_name);
    if (params->owner_last_name)
        json_object_set_string(root_obj, "ownerLastName", params->owner_last_name);
    if (params->employee_type)
        json_object_set_string(root_obj, "employeeType", params->employee_type);
    if (params->server_platform)
        json_object_set_string(root_obj, "serverPlatform", params->server_platform);
    if (params->project_name)
        json_object_set_string(root_obj, "projectName", params->project_name);
    if (params->business_justification)
        json_object_set_string(root_obj, "businessJustification", params->business_justification);
    
    // subjectAltNames as array
    JSON_Value *san_array = json_value_init_array();
    JSON_Array *san_json_array = json_value_get_array(san_array);
    if (params->subject_alt_names && strlen(params->subject_alt_names) > 0) {
        char *san_copy = XSTRDUP(params->subject_alt_names);
        char *token = strtok(san_copy, ",");
        while (token) {
            json_array_append_value(san_json_array, json_value_init_string(token));
            token = strtok(NULL, ",");
        }
        XFREE(san_copy);
    }
    json_object_set_value(root_obj, "subjectAltNames", san_array);

    // ipAddresses as array
    JSON_Value *ip_array = json_value_init_array();
    JSON_Array *ip_json_array = json_value_get_array(ip_array);
    if (params->ip_addresses && strlen(params->ip_addresses) > 0) {
        char *ip_copy = XSTRDUP(params->ip_addresses);
        char *token = strtok(ip_copy, ",");
        while (token) {
            json_array_append_value(ip_json_array, json_value_init_string(token));
            token = strtok(NULL, ",");
        }
        XFREE(ip_copy);
    }
    json_object_set_value(root_obj, "ipAddresses", ip_array);
    
    if (params->cert_type)
        json_object_set_string(root_obj, "certificateType", params->cert_type);
    if (params->owner_phone_number)
        json_object_set_string(root_obj, "ownerPhoneNumber", params->owner_phone_number);
    if (params->owner_email)
        json_object_set_string(root_obj, "ownerEmailAddress", params->owner_email);
    if (params->sectigo_url)
        json_object_set_string(root_obj, "certifierUrl", params->sectigo_url);
    
    // Generate CSR and add to body
    char *csr_pem = NULL;
    CertifierError csr_rc = sectigo_generate_certificate_signing_request(certifier, &csr_pem);
    if (csr_rc.application_error_code != 0 || csr_pem == NULL) {
        log_error("Failed to generate CSR: %s\n", csr_rc.application_error_msg);
        if (csr_pem) XFREE(csr_pem);
        json_value_free(root_value);
        return csr_rc.application_error_code;
    }
    json_object_set_string(root_obj, "certificateSigningRequest", csr_pem);

    // Serialize JSON body
    char *json_body = json_serialize_to_string(root_value);

    // Call the request function
    CertifierPropMap *props = certifier_get_prop_map(certifier);
    char *cert_output = NULL;
    CertifierError req_rc = sectigo_client_request_certificate(
        props,
        (unsigned char *)csr_pem,
        NULL, // node_address
        NULL, // certifier_id
        &cert_output
    );

    // Cleanup
    if (csr_pem) XFREE(csr_pem);
    if (json_body) json_free_serialized_string(json_body);
    if (root_value) json_value_free(root_value);

    return req_rc.application_error_code;
}
