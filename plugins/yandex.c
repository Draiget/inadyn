/* Plugin for Yandex DNS API
 *
 * Copyright (C) 2003-2004 Vlad Smetannikov <draiget@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, visit the Free Software Foundation
 * website at http://www.gnu.org/licenses/gpl-2.0.html or write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 */

#include <ddns.h>
#include <http.h>
#include "plugin.h"
#include "cJSON.h"

#define YA_HTTP_GET_REQUEST_INFO \
        "GET /api2/admin/dns/list?domain=%s HTTP/1.1\r\n" \
        "Host: pddimp.yandex.ru\r\n" \
        "PddToken: %s\r\n" \
        "User-Agent: %s\r\n\r\n"

#define YA_HTTP_POST_EDIT_INFO \
        "POST /api2/admin/dns/edit HTTP/1.1\r\n" \
        "Host: pddimp.yandex.ru\r\n" \
        "PddToken: %s\r\n" \
        "User-Agent: %s\r\n" \
        "Content-Type: application/x-www-form-urlencoded\r\n" \
        "Content-Length: %d\r\n\r\n" \
        "%s"

#define YA_HTTP_POST_ADD_INFO \
        "POST /api2/admin/dns/add HTTP/1.1\r\n" \
        "Host: pddimp.yandex.ru\r\n" \
        "PddToken: %s\r\n" \
        "User-Agent: %s\r\n" \
        "Content-Type: application/x-www-form-urlencoded\r\n" \
        "Content-Length: %d\r\n\r\n" \
        "%s"

static int request              (ddns_t       *ctx,   ddns_info_t *info, ddns_alias_t *alias);
static int response             (http_trans_t *trans, ddns_info_t *info, ddns_alias_t *alias);

static int update_record_entry  (int record_id, ddns_t *ctx, ddns_info_t *info, ddns_alias_t *alias);
static int create_record_entry  (ddns_t *ctx, ddns_info_t *info, ddns_alias_t *alias);

static void extract_subdomain   (char* subdomain, ddns_info_t *info, ddns_alias_t *alias);


static ddns_system_t plugin = {
        .name                   = "default@pdd.yandex.ru",

        .request                = (req_fn_t)request,
        .response               = (rsp_fn_t)response,

        .checkip_name           = "ipv4.icanhazip.com",
        .checkip_url            = "/",

        .server_name            = "pddimp.yandex.ru:443",
        .server_url             = "/api2/admin/dns/"
};

/* Request to update DNS entry */
static int request(ddns_t *ctx, ddns_info_t *info, ddns_alias_t *alias)
{
    int           record_id = 0, rc = 0, entry_operation = 1;
    http_t        client;
    http_trans_t  trans;

    do {
        TRY(http_construct(&client));

        http_set_port(&client, info->server_name.port);
        http_set_remote_name(&client, info->server_name.name);

        client.ssl_enabled = info->ssl_enabled;
        TRY(http_init(&client, "Sending Yandex entry id query request"));

        trans.req_len     = snprintf(ctx->request_buf, ctx->request_buflen,
                                     YA_HTTP_GET_REQUEST_INFO,
                                     info->creds.username,
                                     info->creds.password,
                                     info->user_agent);
        trans.req         = ctx->request_buf;
        trans.rsp         = ctx->work_buf;
        trans.max_rsp_len = ctx->work_buflen - 1;	/* Save place for a \0 at the end */

        logit(LOG_NOTICE, "ctx->request_buf [%s]", ctx->request_buf);

        rc  = http_transaction(&client, &trans);
        rc |= http_exit(&client);

        http_destruct(&client, 1);

        if (rc)
            break;

        TRY(http_status_valid(trans.status));

        cJSON* root = cJSON_Parse(trans.rsp_body);
        if (!root){
            logit(LOG_ERR, "YandexPDDImp invalid json response, parsing error!");
            continue;
        }

        char *requestResult = cJSON_GetObjectItem(root, "success")->valuestring;
        if (!strcmp(requestResult, "ok")) {
            cJSON *subdomains = cJSON_GetObjectItem(root, "records");
            int subdomainsCount = cJSON_GetArraySize(subdomains);
            for (int i = 0; i < subdomainsCount; i++) {
                cJSON *recordData = cJSON_GetArrayItem(subdomains, i);
                if (recordData) {
                    cJSON *recordFQDN = cJSON_GetObjectItem(recordData, "fqdn");
                    if (recordFQDN) {
                        // Full domain name is equals to our alias
                        logit(LOG_NOTICE, "Getting recordFQDN [%s] ...", recordFQDN->valuestring);
                        if (!strcmp(recordFQDN->valuestring, alias->name)) {
                            logit(LOG_NOTICE, "Getting request id ...");
                            record_id = cJSON_GetObjectItem(recordData, "record_id")->valueint;
                            logit(LOG_NOTICE, "YandexPDDImp request record id: %d", record_id);
                            entry_operation = 0;
                            break;
                        }
                    }
                }
            }

            if (!entry_operation){
                break;
            }

            logit(LOG_NOTICE, "YandexPDDImp domain entry not found [subdomains count - %d], performing to add new one", subdomainsCount);
        } else if (!strcmp(requestResult, "error")) {
            char *errorMsg = cJSON_GetObjectItem(root, "error")->valuestring;
            if (!strcmp(errorMsg, "no_auth")){
                logit(LOG_ERR, "YandexPDDImp no PddToken present, invalid or token has no permissions [token: %s]", info->creds.password);
                return RC_DYNDNS_RSP_NOTOK;
            }
            logit(LOG_ERR, "YandexPDDImp request error: %s", errorMsg);
        }

        logit(LOG_ERR, "YandexPDDImp domain entry not found");
        rc = RC_DYNDNS_RSP_NOTOK;
    }
    while (1);

    if (rc) {
        logit(LOG_ERR, "Get Yandex entry id query failed");
        return 0;
    }

    // Update - 0, or add new - 1
    if (!entry_operation){
        logit(LOG_NOTICE, "YandexPDDImp updating record ...");
        return update_record_entry(record_id, ctx, info, alias);
    }

    logit(LOG_NOTICE, "YandexPDDImp creating new record ...");
    return create_record_entry(ctx, info, alias);
}

static int update_record_entry (int record_id, ddns_t *ctx, ddns_info_t *info, ddns_alias_t *alias)
{
    logit(LOG_NOTICE, "Sending DNS update request to [%s at %d]", info->server_name.name, info->server_name.port);

    char subdomain[200];
    extract_subdomain(subdomain, info, alias);

    char yd_params[255];
    sprintf(yd_params, "domain=%s&subdomain=%s&record_id=%d&content=%s", info->creds.username, subdomain, record_id, alias->address );

    int ret = snprintf(ctx->request_buf, ctx->request_buflen,
                    YA_HTTP_POST_EDIT_INFO,
                    info->creds.password,
                    info->user_agent,
                    (int)strlen(yd_params),
                    yd_params);

    logit(LOG_NOTICE, "DNS update request data [%s]", ctx->request_buf);
    return ret;
}

static int create_record_entry (ddns_t *ctx, ddns_info_t *info, ddns_alias_t *alias)
{
    logit(LOG_NOTICE, "Sending DNS add request to [%s at %d]", info->server_name.name, info->server_name.port);

    char subdomain[200];
    extract_subdomain(subdomain, info, alias);

    char yd_params[255];
    sprintf(yd_params, "domain=%s&subdomain=%s&type=A&content=%s", info->creds.username, subdomain, alias->address );

    logit(LOG_NOTICE, "DNS add request params [%s]", yd_params);
    return snprintf(ctx->request_buf, ctx->request_buflen,
                    YA_HTTP_POST_ADD_INFO,
                    info->creds.password,
                    info->user_agent,
                    (int)strlen(yd_params),
                    yd_params);
}

static void extract_subdomain (char* subdomain, ddns_info_t *info, ddns_alias_t *alias)
{
    int cutPos = strstr(alias->name, info->creds.username) - alias->name;
    strncpy(subdomain, alias->name, cutPos);
    subdomain[cutPos - 1] = '\0';
}

/* Response to update DNS entry request */
static int response(http_trans_t *trans, ddns_info_t *UNUSED(info), ddns_alias_t *UNUSED(alias))
{
    if (trans->status == 0){
        logit(LOG_WARNING, "YandexPDDImp DNS update/add empty response, retry later!");
        return RC_DYNDNS_RSP_RETRY_LATER;
    }

    DO(http_status_valid(trans->status));

    cJSON* root = cJSON_Parse(trans->rsp_body);
    if (!root){
        logit(LOG_ERR, "YandexPDDImp invalid DNS update/add json response, parsing error!");
        return RC_DYNDNS_RSP_RETRY_LATER;
    }

    char *requestResult = cJSON_GetObjectItem(root, "success")->valuestring;
    if (!strcmp(requestResult, "error")) {
        char *errorMsg = cJSON_GetObjectItem(root, "error")->valuestring;
        logit(LOG_ERR, "YandexPDDImp DNS update/add error: %s", errorMsg);

        return RC_DYNDNS_RSP_NOTOK;
    }

    return RC_OK;
}

PLUGIN_INIT(plugin_init)
{
    plugin_register(&plugin);
}

PLUGIN_EXIT(plugin_exit)
{
    plugin_unregister(&plugin);
}
