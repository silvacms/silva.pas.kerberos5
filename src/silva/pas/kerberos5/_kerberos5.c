

#include "_kerberos5.h"

/**
 * Allocate a new kerberos contexte, and setup options.
 */

static char     pykrb_new_context(pykrb_data_t *kd, pykrb_option_t *opt) {
  if (!(kd->flag & HAVE_CONTEXT)) {
    if ((kd->krbret = krb5_init_context(&(kd->context))))
      return pykrb_error(kd);
    kd->flag |= HAVE_CONTEXT;
    if (opt->config) {
      char  *arr[2] = { opt->config, NULL, };

      if ((kd->krbret = krb5_set_config_files(kd->context, arr)))
        return pykrb_error(kd);
    }
    if (opt->realm &&
        (kd->krbret = krb5_set_default_realm(kd->context, opt->realm)))
      return pykrb_error(kd);
  }
  return 0;
}

/**
 * Prepare a new principal name.
 */

static char     pykrb_new_principal(pykrb_data_t *kd,
                                    char const * const name,
                                    pykrb_option_t *opt) {
  if (kd->flag & HAVE_PRINC)
    pykrb_clear_principal(kd);
  // FIXME ident_service must be an boolean
  if (opt->ident_service && opt->hostname) {
    kd->krbret = krb5_sname_to_principal(kd->context,
                                         opt->hostname,
                                         name,
                                         KRB5_NT_SRV_HST,
                                         &(kd->princ));
  } else {
    kd->krbret = krb5_parse_name(kd->context,
                                 name,
                                 &(kd->princ));
  };
  if (kd->krbret) {
    pykrb_error(kd);
    return 1;
  }
  kd->flag |= HAVE_PRINC;
  return 0;
}

/**
 * Clear current principal name.
 */

static void     pykrb_clear_principal(pykrb_data_t *kd)
{
  pykrb_clear_creds(kd);
  if (kd->flag & HAVE_CACHE) {
    krb5_cc_destroy(kd->context, kd->ccache);
    kd->flag &= ~HAVE_CACHE;
  }
  if (kd->flag & HAVE_PRINC) {
    krb5_free_principal(kd->context, kd->princ);
    kd->flag &= ~HAVE_PRINC;
  }
}

/**
 * Clear authentification credential.
 */

static void     pykrb_clear_creds(pykrb_data_t *kd)
{
  if (kd->flag & HAVE_CRED) {
    krb5_free_cred_contents(kd->context, &(kd->creds));
    kd->flag &= ~HAVE_CRED;
  }
}


/**
 * Prepare Kerberos data for authentification.
 */

extern krb5_cc_ops krb5_mcc_ops;

static char     pykrb_init_auth(pykrb_data_t *kd, char const * const username,
                                pykrb_option_t *opt) {
  if (pykrb_new_context(kd, opt))
    return 1;
  kd->krbret = krb5_cc_register(kd->context, &krb5_mcc_ops, FALSE);
  if (kd->krbret != KRB5_CC_TYPE_EXISTS) {
    pykrb_error(kd);
    return 1;
  }
  if (pykrb_new_principal(kd, username, opt))
    return 1;
  if (opt->auth_service) {
    kd->service = PyMem_Malloc(strlen(opt->auth_service) + 1);
    strcpy(kd->service, opt->auth_service);
  }
  krb5_get_init_creds_opt_init(&(kd->opts));
  memset(&(kd->creds), 0, sizeof(krb5_creds));
  return 0;
}

/**
 * Clear kerberos data before finish.
 */

static void     pykrb_free(pykrb_data_t *kd)
{
  pykrb_clear_principal(kd);
  if (kd->flag & HAVE_CONTEXT)
    krb5_free_context(kd->context);
  kd->flag = 0;
}

/**
 * Make an exception.
 */

static PyObject *PyKrb_Error;
static PyObject *PyKrb_PasswordExpired;
static PyObject *PyKrb_PasswordChangeRejected;

static char     pykrb_error(pykrb_data_t *kd)
{
  const char    * msg = error_message(kd->krbret);

  if (!strcmp(msg, "Password has expired"))
    PyErr_SetString(PyKrb_PasswordExpired, msg);
  else
    PyErr_SetString(PyKrb_Error, msg);
  return 1;
}

/**
 * Save credential to a memory cache.
 */

static char     pykrb_save_cache(pykrb_data_t *kd)
{
  char      cache_name[L_tmpnam + 8];

  if (!(kd->flag & HAVE_CACHE)) {
    memset(cache_name, 0, sizeof(char) * (L_tmpnam + 8));
    strcpy(cache_name, "MEMORY:");
    (void) tmpnam(&cache_name[7]);
    kd->krbret = krb5_cc_resolve(kd->context, cache_name, &(kd->ccache));
    if (kd->krbret) {
      pykrb_error(kd);
      return 1;
    }
    kd->krbret = krb5_cc_initialize(kd->context, kd->ccache, kd->princ);
    if (kd->krbret) {
      pykrb_error(kd);
      return 1;
    }
    kd->flag |= HAVE_CACHE;
  }
  if (kd->flag & HAVE_CRED) {
    kd->krbret = krb5_cc_store_cred(kd->context, kd->ccache, &(kd->creds));
    if (kd->krbret) {
      pykrb_error(kd);
      return 1;
    }
  }
  return 0;
}

/**
 * Load credential of the Kerberos Ticket Granter from the cache.
 */

static char     pykrb_get_krbtgt_creds(pykrb_data_t *kd)
{
  time_t            now = time(0);
  krb5_principal    krbtgt;

  // FIXME : Gruiiik

  {
    char        * tmp, * myrealm;

    myrealm = kd->princ->realm.data;
    tmp = PyMem_Malloc(sizeof(char) * (9 + 2 * strlen(myrealm)));
    sprintf(tmp, "krbtgt/%s@%s", myrealm, myrealm);
    krb5_parse_name(kd->context, tmp, &krbtgt);
    PyMem_Free(tmp);
  }

  kd->krbret = krb5_cc_start_seq_get(kd->context,
                                     kd->ccache,
                                     &(kd->cursor));
  if (kd->krbret)
    return pykrb_error(kd);
  while (!(kd->krbret = krb5_cc_next_cred(kd->context,
                                          kd->ccache,
                                          &(kd->cursor),
                                          &(kd->creds)))) {
    kd->flag |= HAVE_CRED;
    if (krb5_principal_compare(kd->context,
                               kd->creds.server,
                               krbtgt) &&
        kd->creds.times.endtime > now)
      return 0;
    pykrb_clear_creds(kd);
  }
  if (kd->krbret != KRB5_CC_END)
    return pykrb_error(kd);
  krb5_cc_end_seq_get(kd->context, kd->ccache, &(kd->cursor));
  krb5_free_principal(kd->context, krbtgt);
  return -1;
}


/**************** Python Function ****************/

/**
 * Python function to return the default realm.
 */

static PyObject* pykrb_default_realm(PyObject *self, PyObject *args,
                                     PyObject *keywds) {
  pykrb_option_t opt;
  pykrb_data_t  kd;
  char *tmp;
  PyObject *rvalue;
  static char *kwlist[] = {"config",
                           "realm",
                           NULL, };

  memset(&kd, 0, sizeof(pykrb_data_t));
  memset(&opt, 0, sizeof(pykrb_option_t));
  if (!PyArg_ParseTupleAndKeywords(args, keywds, "|ss", kwlist,
                                   &(opt.config), &(opt.realm)) ||
      pykrb_new_context(&kd, &opt))
    return NULL;
  kd.krbret = krb5_get_default_realm(kd.context, &tmp);
  pykrb_free(&kd);
  if (kd.krbret) {
    pykrb_error(&kd);
    return NULL;
  }
  rvalue = Py_BuildValue("s", tmp);
  free(tmp);
  return rvalue;
}

static krb5_error_code pykrb_dummy_prompter(krb5_context ctx,
                                            void *data,
                                            const char *name,
                                            const char *banner,
                                            int num_prompts,
                                            krb5_prompt prompts[]) {
  int i;

  for (i = 0; i < num_prompts; i++) {
    strncpy(prompts[i].reply->data, data, strlen((char*) data));
    prompts[i].reply->length = strlen((char*) data);
  };
  return 0;
}

/**************** KerberosUser Python Class *********/

typedef struct {
  PyObject_HEAD
  pykrb_data_t  dt;
} pykrb_KerberosUserObject;


static int KerberosUser_init(pykrb_KerberosUserObject *self,
                             PyObject *args, PyObject *keywds) {
  pykrb_option_t opt;
  char           *username;
  char           *password = NULL;
  static char    *kwlist[] = {"username",
                              "config",
                              "realm",
                              "ident_service",
                              "hostname",
                              "auth_service",
                              "keytab",
                              "password",
                              NULL };

  memset(&opt, 0, sizeof(pykrb_option_t));
  memset(&(self->dt), 0, sizeof(pykrb_data_t));
  if (!PyArg_ParseTupleAndKeywords(args, keywds, "s|ssissss", kwlist,
                                   &username,
                                   &(opt.config),
                                   &(opt.realm),
                                   &(opt.ident_service),
                                   &(opt.hostname),
                                   &(opt.auth_service),
                                   &(opt.keytab),
                                   &password) ||
      pykrb_init_auth(&(self->dt), username, &opt)) {
    pykrb_free(&(self->dt));
    return -1;
  };

  self->dt.krbret = krb5_get_init_creds_password(self->dt.context,
                                                 &(self->dt.creds),
                                                 self->dt.princ,
                                                 NULL,
                                                 password ? pykrb_dummy_prompter : krb5_prompter_posix,
                                                 password ? password : NULL,
                                                 0,
                                                 self->dt.service,
                                                 &(self->dt.opts));
  if (self->dt.krbret) {
    pykrb_error(&(self->dt));
    pykrb_free(&(self->dt));
    return -1;
  };
  self->dt.flag |= HAVE_CRED;
  pykrb_save_cache(&(self->dt));
  pykrb_clear_creds(&(self->dt));
  return 0;
}

static void KerberosUser_dealloc(pykrb_KerberosUserObject *self) {
  pykrb_free(&(self->dt));
}

static PyObject * KerberosUser_get_principal(pykrb_KerberosUserObject *self) {
  char      * princ_name;
  PyObject  * rvalue;

  self->dt.krbret = krb5_unparse_name(self->dt.context,
                                      self->dt.princ,
                                      &princ_name);
  if (self->dt.krbret) {
    pykrb_error(&(self->dt));
    return NULL;
  };
  rvalue = Py_BuildValue("s", princ_name);
  free(princ_name);
  return rvalue;
}

static PyObject * KerberosUser_get_username(pykrb_KerberosUserObject *self) {
  char      * princ_name;
  PyObject  * rvalue;

  self->dt.krbret = krb5_unparse_name_flags(self->dt.context,
                                            self->dt.princ,
                                            KRB5_PRINCIPAL_UNPARSE_SHORT,
                                            &princ_name);
  if (self->dt.krbret) {
    pykrb_error(&(self->dt));
    return NULL;
  };
  rvalue = Py_BuildValue("s", princ_name);
  free(princ_name);
  return rvalue;
}

static PyObject * KerberosUser_is_valid(pykrb_KerberosUserObject *self)
{
  PyObject  * is_valid = Py_False;
  int       rvalue;

  rvalue = pykrb_get_krbtgt_creds(&(self->dt));
  if (rvalue == 1)
    return NULL;
  if (rvalue == 0) {
    pykrb_clear_creds(&(self->dt));
    is_valid = Py_True;
  };
  Py_INCREF(is_valid);
  return is_valid;
}

static PyObject * KerberosUser_change_password(pykrb_KerberosUserObject *self,
                                               PyObject * args) {
  char      * npassword;
  int       is_valid, r_int;
  PyObject  * rvalue;
  krb5_data r_code, r_string;

  if (!PyArg_ParseTuple(args, "s", &npassword))
    return NULL;

  is_valid = pykrb_get_krbtgt_creds(&(self->dt));
  if (is_valid == -1) {
    PyErr_SetString(PyKrb_Error, PYKRB_OUTDATED_CREDENTIAL);
    return NULL;
  };
  self->dt.krbret = krb5_change_password(self->dt.context,
                                         &(self->dt.creds),
                                         npassword,
                                         &r_int,
                                         &r_code,
                                         &r_string);
  pykrb_clear_creds(&(self->dt));
  if (self->dt.krbret) {
    pykrb_error(&(self->dt));
    return NULL;
  };
  if (!strncmp(r_code.data, PYKRB_PASSWORD_REJECTED, r_code.length)) {
    PyErr_SetString(PyKrb_PasswordChangeRejected, PYKRB_PASSWORD_REJECTED);
    return NULL;
  };
  rvalue = Py_BuildValue("s#", r_code.data, r_code.length);
  return rvalue;
};

static PyObject * KerberosUser_set_password_for(pykrb_KerberosUserObject *self,
                                                PyObject * args) {
  char          * npassword, * username;
  krb5_principal puser;
  int           is_valid, r_int;
  PyObject      * rvalue;
  krb5_data     r_code, r_string;

  if (!PyArg_ParseTuple(args, "ss", &username, &npassword))
    return NULL;

  is_valid = pykrb_get_krbtgt_creds(&(self->dt));
  if (is_valid == -1) {
    PyErr_SetString(PyKrb_Error, PYKRB_OUTDATED_CREDENTIAL);
    return NULL;
  };
  krb5_parse_name(self->dt.context, username, &puser);
  self->dt.krbret = krb5_set_password(self->dt.context,
                                      &(self->dt.creds),
                                      npassword,
                                      puser,
                                      &r_int,
                                      &r_code,
                                      &r_string);
  pykrb_clear_creds(&(self->dt));
  krb5_free_principal(self->dt.context, puser);
  if (self->dt.krbret) {
    pykrb_error(&(self->dt));
    return NULL;
  };
  if (!strncmp(r_code.data, PYKRB_PASSWORD_REJECTED, r_code.length)) {
    PyErr_SetString(PyKrb_PasswordChangeRejected, PYKRB_PASSWORD_REJECTED);
    return NULL;
  };
  rvalue = Py_BuildValue("s#", r_code.data, r_code.length);
  return rvalue;
};

/**************** Module Definition ****************/


static PyMethodDef KrbMethods[] = {
  {"default_realm", (PyCFunction) pykrb_default_realm,
   METH_VARARGS | METH_KEYWORDS, "Return the default REALM.", },
  {NULL, NULL, 0, NULL, },
};

static PyMethodDef KerberosUserMethods[] = {
  {"get_principal", (PyCFunction) KerberosUser_get_principal, METH_NOARGS,
   "Return the current principal." },
  {"get_username", (PyCFunction) KerberosUser_get_username, METH_NOARGS,
   "Return the current principal without the realm (if it is the default)." },
  {"is_valid", (PyCFunction) KerberosUser_is_valid, METH_NOARGS,
   "Return true is the user is valid." },
  {"change_password", (PyCFunction) KerberosUser_change_password, METH_VARARGS,
   "Change the current user password." },
  {"set_password_for", (PyCFunction) KerberosUser_set_password_for, METH_VARARGS,
   "Change password for the given user. (set_password_for('alfred', 'password'))."},
  {NULL, NULL, 0, NULL, },
};

static PyTypeObject pykrb_KerberosUserType = {
  PyObject_HEAD_INIT(NULL)
  0,                         /*ob_size*/
  "_kerberos5.KerberosUser",      /*tp_name*/
  sizeof(pykrb_KerberosUserObject), /*tp_basicsize*/
  0,                         /*tp_itemsize*/
  (destructor) KerberosUser_dealloc, /*tp_dealloc*/
  0,                         /*tp_print*/
  0,                         /*tp_getattr*/
  0,                         /*tp_setattr*/
  0,                         /*tp_compare*/
  0,                         /*tp_repr*/
  0,                         /*tp_as_number*/
  0,                         /*tp_as_sequence*/
  0,                         /*tp_as_mapping*/
  0,                         /*tp_hash */
  0,                         /*tp_call*/
  0,                         /*tp_str*/
  0,                         /*tp_getattro*/
  0,                         /*tp_setattro*/
  0,                         /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT,        /*tp_flags*/
  "An authenticated user to Kerberos", /* tp_doc */
  0,                     /* tp_traverse */
  0,                     /* tp_clear */
  0,                     /* tp_richcompare */
  0,                     /* tp_weaklistoffset */
  0,                     /* tp_iter */
  0,                     /* tp_iternext */
  KerberosUserMethods,       /* tp_methods */
  0,                         /* tp_members */
  0,                         /* tp_getset */
  0,                         /* tp_base */
  0,                         /* tp_dict */
  0,                         /* tp_descr_get */
  0,                         /* tp_descr_set */
  0,                         /* tp_dictoffset */
  (initproc) KerberosUser_init, /* tp_init */
  0,                         /* tp_alloc */
  PyType_GenericNew,         /* tp_new */
};

PyMODINIT_FUNC init_kerberos5(void) {
  PyObject  *module;

  /* Prepare KerberosUser Class */
  if (PyType_Ready(&pykrb_KerberosUserType) < 0)
    return;

  module = Py_InitModule("_kerberos5", KrbMethods);

  /* Add KerberosError Exception */
  PyKrb_Error = PyErr_NewException("_kerberos5.KerberosError", NULL, NULL);
  Py_INCREF(PyKrb_Error);
  PyModule_AddObject(module, "KerberosError", PyKrb_Error);

  /* Add KerberosPasswordExpired Exception */
  PyKrb_PasswordExpired = PyErr_NewException("_kerberos5.KerberosPasswordExpired", PyKrb_Error, NULL);
  Py_INCREF(PyKrb_PasswordExpired);
  PyModule_AddObject(module, "KerberosPasswordExpired", PyKrb_PasswordExpired);

  /* Add KerberosPasswordChangeRejected Exception */
  PyKrb_PasswordChangeRejected = PyErr_NewException("_kerberos5.KeberosPasswordChangeRejected", PyKrb_Error, NULL);
  Py_INCREF(PyKrb_PasswordChangeRejected);
  PyModule_AddObject(module, "KerberosPasswordChangeRejected", PyKrb_PasswordChangeRejected);

  /* Add KerberosUser Class */
  Py_INCREF(&pykrb_KerberosUserType);
  PyModule_AddObject(module, "KerberosUser", (PyObject*) &pykrb_KerberosUserType);
}

