

#ifndef __KERBEROS5_H
# define __KERBEROS5_H

# include <Python.h>
# include <krb5.h>

/**
 * Store the kerberos status.
 */

typedef struct {
  char                  flag;
  char                  *service;
  krb5_context          context;
  krb5_principal        princ;
  krb5_creds            creds;
  krb5_ccache           ccache;
  krb5_cc_cursor        cursor;
  krb5_get_init_creds_opt opts;
  krb5_keytab           keytab;
  krb5_error_code       krbret;
} pykrb_data_t;

/**
 * krb_data flags value
 */

#define HAVE_CONTEXT    (1 << 0)
#define HAVE_PRINC      (1 << 1)
#define HAVE_CRED       (1 << 2)
#define HAVE_KEYTAB     (1 << 3)
#define HAVE_CACHE      (1 << 4)
#define HAVE_AUTH       (1 << 5)
#define HAVE_TICKET     (1 << 6)
#define HAVE_CURSOR     (1 << 7)


#define PYKRB_PASSWORD_REJECTED         "Password change rejected"
#define PYKRB_OUTDATED_CREDENTIAL       "Outdated credentials"

/**
 * Python option to module function. Each option correspond to a keyword.
 */

typedef struct {
  char          *config;
  char          *realm;
  int           ident_service;
  char          *hostname;
  char          *auth_service;
  char          *keytab;
} pykrb_option_t;

/**
 * Utility function declaration.
 */

static char     pykrb_new_context(pykrb_data_t *kd, pykrb_option_t *opt);
static char     pykrb_error(pykrb_data_t *kd);
static void     pykrb_free(pykrb_data_t *kd);
static char     pykrb_init_auth(pykrb_data_t *kd,
                                char const * const username,
                                pykrb_option_t *opt);

static char     pykrb_new_principal(pykrb_data_t *kd,
                                    char const * const name,
                                    pykrb_option_t *opt);
static void     pykrb_clear_principal(pykrb_data_t *kd);
static void     pykrb_clear_creds(pykrb_data_t *kd);
static char     pykrb_save_cache(pykrb_data_t *kd);

static char     pykrb_get_krbtgt_creds(pykrb_data_t *kd);

#endif /* !_KERBEROS5_H */
