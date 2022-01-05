/*******************************************************************************
 *   mod_bikeshed For Apache 2.2 & 2.4
 *   Copyright (C) 2012 G. Smith
 *   Initial release 0.1.0 - September 24, 2012
 *
 *   This is mod_avc by Günter Knauf (thanks Günter) modified to replace
 *   ServerTokens with what we want Apache to show in the server tokens/signature
 *   or remove the ServerTokens completely including from the header. 
 *   Token replacing parts of this module were based on mod_security2 by
 *   Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *   
 *   Why the mod_bikeshed name? It came from this mailing list thread here 
 *   discussing allowing the manipulations or removal of ServerTokens;
 *   http://marc.info/?l=apache-httpd-dev&m=116542448411598&w=2
 *
 *   Compiling: apxs -c mod_bikeshed.c
 *
 *   I personally feel it is a bad idea depending on why you want to do it. 
 *   Those who pay per byte can see some monitary savings on very busy servers.
 *   Those wanting to obscure their server for security reasons should remember
 *   that security through obscurity is no real security at all. I still see 
 *   requests for this feature though and wanted to try my hand at modifying
 *   a module to fit a different purpose.
 *
 *******************************************************************************
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 *******************************************************************************
*/

#define BIKESHED_MODULE_VERSION "0.1.1"

#include "apr_pools.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(bikeshed);
#endif

#if AP_MODULE_MAGIC_AT_LEAST(20051115,4)
#  define bikeshed_get_server_version ap_get_server_banner
#else
#  define bikeshed_get_server_version ap_get_server_version
#endif 

module AP_MODULE_DECLARE_DATA bikeshed_module;

typedef struct {
    int bikeshed_tokens_replace;
    int bikeshed_add_banner;
    char *bikeshed_tokens_string;
} bikeshed_srv_config;

/* Initialize the module */
static int bikeshed_post_config(apr_pool_t * p, apr_pool_t * plog, apr_pool_t * ptemp,
                         server_rec * s)
{
    char *original_server_version = NULL;
    int a = 0;
    bikeshed_srv_config *svrcfg = 
      (bikeshed_srv_config *)ap_get_module_config(s->module_config, 
                                                  &bikeshed_module);

    ap_add_version_component(p, "mod_bikeshed/" BIKESHED_MODULE_VERSION );

    if (svrcfg->bikeshed_tokens_replace) {

      original_server_version = (char *)bikeshed_get_server_version();

      if (original_server_version == NULL) {
          ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, s,
                       "Apache returned null as signature " 
                         "and should not have.");
          return -1;
      }

      if ((strcasecmp(svrcfg->bikeshed_tokens_string, "none") == 0)) {
          a = 1;
          strcpy(original_server_version, "");
      }
      else {
          strcpy(original_server_version, svrcfg->bikeshed_tokens_string);
      }

      /* Did it really change? */
      original_server_version = (char *)bikeshed_get_server_version();
      if ((a == 0) && ((original_server_version == NULL) || 
         (strcmp(original_server_version, svrcfg->bikeshed_tokens_string) != 0))) 
      {
              ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, s, 
                       "Failed to change server signature to \"%s\".", 
                         svrcfg->bikeshed_tokens_string);
              return 0;
      }
    } 

    return OK;
}

/* Create server config data structure */
static void *bikeshed_create_srv_config(apr_pool_t *p, server_rec *s)
{
    bikeshed_srv_config *svrcfg = apr_pcalloc(p, 
                                              sizeof(bikeshed_srv_config));
    /* Set the defaults */
    svrcfg->bikeshed_tokens_replace = 1;
    return svrcfg;
}

static const char *set_flag_slot(cmd_parms *cmd, void *dummy, int arg)
{
    bikeshed_srv_config *svrcfg =
      (bikeshed_srv_config *) ap_get_module_config(cmd->server->module_config, &bikeshed_module);
    int offset = (int)(long)cmd->info;
    char *struct_ptr = (char *)svrcfg;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);

    if (err != NULL) {
        return err;
    }

    *(int *)(struct_ptr + offset) = arg ? 1 : 0;

    return NULL;
}

static const char *set_string_slot(cmd_parms *cmd, void *dummy, const char *arg)
{
    bikeshed_srv_config *svrcfg =
        (bikeshed_srv_config *) ap_get_module_config(cmd->server->module_config,
                                                     &bikeshed_module);
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    int offset = (int)(long)cmd->info;

    if (err != NULL) {
        return err;
    }
    
    if (arg) {
        *(const char **)((char *)svrcfg + offset) = apr_pstrdup(cmd->pool, arg);
    }

    return NULL;
}

/* The module command table */
static const command_rec bikeshed_cmds[] =
{
    AP_INIT_FLAG("BikeShedTokensReplace", set_flag_slot,
        (void *)APR_OFFSETOF(bikeshed_srv_config, bikeshed_tokens_replace),
        RSRC_CONF, "Set On/Off to switch bikeshed string display"),
    AP_INIT_FLAG("BikeShedAddBanner", set_flag_slot,
        (void *)APR_OFFSETOF(bikeshed_srv_config, bikeshed_add_banner),
        RSRC_CONF, "Set On/Off to switch add module banner to replaced "
                   "server signature"),
    AP_INIT_TAKE1("BikeShedTokensString", set_string_slot,
        (void *)APR_OFFSETOF(bikeshed_srv_config, bikeshed_tokens_string),
        RSRC_CONF, "The string to replace the server tokens/signature with"
                   "or 'None' to disable ServerTokens"),
    {NULL}
};

/* Register hooks */
static void bikeshed_register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(bikeshed_post_config, NULL, NULL, APR_HOOK_REALLY_LAST);
}

module AP_MODULE_DECLARE_DATA bikeshed_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    bikeshed_create_srv_config, /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    bikeshed_cmds,              /* command apr_table_t */
    bikeshed_register_hooks     /* register hooks */
};

