#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_log.h"
#include "vpopmail.h"
#include "vauth.h"

typedef struct
{
  int VH_active;
} vpopmail_vhost_conf_rec;


module vpopmail_vhost_module;

static void *
vpopmail_vhost_create_conf (pool * p, server_rec * s)
{
  vpopmail_vhost_conf_rec *conf;
  conf = (vpopmail_vhost_conf_rec *) ap_pcalloc (p, sizeof (conf));
  conf->VH_active = 0;
}

static const char *vpopmail_vhost_set (cmd_parms * cmd, void *dummy, int vpopmail_status)
{
  int VH_active_l;
  char *nesto;

  vpopmail_vhost_conf_rec *conf;
  conf = (vpopmail_vhost_conf_rec *) ap_get_module_config (cmd->server->
							   module_config,
							   &vpopmail_vhost_module);

  if (vpopmail_status == 1)
    conf->VH_active = 1;
  return NULL;
}

static const command_rec vpopmail_vhost_cmds[] = {
  {"VpopMailVirtualHost", vpopmail_vhost_set,NULL,RSRC_CONF, FLAG,
   "VpopMail Virtual domains"},
  {NULL}
};



static void *
vpopmail_vhost_merge_conf (pool * p, void *parent_cfg, void *child_cfg)
{
  vpopmail_vhost_conf_rec *parent = (vpopmail_vhost_conf_rec *) parent_cfg;
  vpopmail_vhost_conf_rec *child = (vpopmail_vhost_conf_rec *) child_cfg;
  vpopmail_vhost_conf_rec *conf;

  conf = (vpopmail_vhost_conf_rec *) ap_pcalloc (p,
						 sizeof
						 (vpopmail_vhost_conf_rec));
  if (child->VH_active == 0)
    {
      conf->VH_active = parent->VH_active;
    }
  else
    {
      conf->VH_active = child->VH_active;
    }
  return (void *) conf;
}


static void *
vpopmail_vhost_main (request_rec * r, const char *name, const char *uri)
{
  char *buf;
  char *buf2;
  char *user;
  char *domain;
  struct vqpasswd *vpw = (struct vqpasswd *)malloc(sizeof (vpw));
  
  buf2=(char *)ap_pcalloc(r->pool,strlen(name));
  memset(buf2,0x0,strlen(name));
  user=(char *)ap_pcalloc(r->pool,strlen(name));
  memset(user,0x0,strlen(name));
  domain=(char *)ap_pcalloc(r->pool,strlen(name));
  memset(domain,0x0,strlen(name));
  
//  snprintf(buf2,strlen(name) + 1,"%s",name); /* \0 I guess :) */
  strcpy(buf2,name);
  user = ap_pstrdup(r->pool,strtok(buf2,"."));
  domain = ap_pstrdup (r->pool,name + strlen(user) + 1) ; /* dot ;) */
  buf = malloc (1000);
  memset (buf, 0x0, 1000);
  buf = ap_pstrdup (r->pool,"/www");

    
  if((vpw = vauth_getpw( user, domain)) == NULL)
  {
    r->filename=strdup("/usr/local/httpd/htdocs");
  ap_log_error (APLOG_MARK, APLOG_ERR, r->server, "no such user %s",r->hostname);
  }
  else
  {
  r->filename = strdup(vpw->pw_dir); 
  }

  if (r->filename)
    {
      r->filename = ap_pstrcat (r->pool, r->filename, buf, uri, NULL);
    }
  else
    {
      r->filename = ap_pstrcat (r->pool, buf, uri, NULL);
    }  
}

static int
vpopmail_vhost_translate (request_rec * r)
{
  const char *name, *uri;
  vpopmail_vhost_conf_rec *conf;
  conf =
    (vpopmail_vhost_conf_rec *) ap_get_module_config (r->server->
						      module_config,
						      &vpopmail_vhost_module);
  if (conf->VH_active != 1)
    return DECLINED;

  name = ap_get_server_name (r);

  vpopmail_vhost_main (r, name, r->uri);

  return OK;

}


module MODULE_VAR_EXPORT vpopmail_vhost_module = {
  STANDARD_MODULE_STUFF,
  NULL,				/* initializer */
  NULL,				/* dir config creater */
  NULL,				/* dir merger --- default is to override */
  vpopmail_vhost_create_conf,	/* server config */
  vpopmail_vhost_merge_conf,	/* merge server configs */
  vpopmail_vhost_cmds,		/* command table */
  NULL,				/* handlers */
  vpopmail_vhost_translate,	/* filename translation */
  NULL,				/* check_user_id */
  NULL,				/* check auth */
  NULL,				/* check access */
  NULL,				/* type_checker */
  NULL,				/* fixups */
  NULL,				/* logger */
  NULL,				/* header parser */
  NULL,				/* child_init */
  NULL,				/* child_exit */
  NULL				/* post read-request */
};
