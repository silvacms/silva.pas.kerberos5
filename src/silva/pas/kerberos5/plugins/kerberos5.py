# -*- coding: utf-8 -*-
# Copyright (c) 2011 Infrae. All rights reserved.
# See also LICENSE.txt
# $Id$

import logging

from AccessControl import ClassSecurityInfo
from App.class_init import InitializeClass

from zope.interface import Interface
from zope.interface import implementedBy
from silva.pas.kerberos5 import _kerberos5
from Products.PluggableAuthService.permissions import ManageUsers
from Products.PluggableAuthService.interfaces import plugins
from Products.PluggableAuthService.utils import classImplements
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PageTemplates.PageTemplateFile import PageTemplateFile

logger = logging.getLogger('silva.pas.kerberos5')


class IKerberos5Plugin(Interface):
    pass


def manage_addKerberos5Plugin(self, id, title='', RESPONSE=None ):
    """Add Kerberos 5 plugin.
    """
    plugin = Kerberos5Plugin(id, title)
    self._setObject(id, plugin)

    if RESPONSE is not None:
        RESPONSE.redirect('manage_workspace')


manage_addKerberos5PluginForm = PageTemplateFile(
    '../www/kerberos5AddForm', globals(), __name__="manage_addKerberos5PluginForm")


class Kerberos5Plugin(BasePlugin):
    """PAS plugin for kerberos 5.
    """
    meta_type = 'Silva Kerberos 5  Plugin'
    security = ClassSecurityInfo()

    manage_options = (({'label': 'Kerberos 5',
                        'action': 'manage_editKerberos5PluginForm'},
                       ) + BasePlugin.manage_options[:])

    def __init__(self, id, title=None):
        self._setId(id)
        self.title = title
        self._realm = _kerberos5.default_realm()
        self._config_file = None

    security.declareProtected(ManageUsers, 'manage_editKerberos5PluginForm')
    manage_editKerberos5PluginForm = PageTemplateFile(
        '../www/kerberos5EditForm', globals(), __name__="manage_editKerberos5PluginForm")

    security.declareProtected(ManageUsers, 'manage_editKerberos5Plugin')
    def manage_editKerberos5Plugin(self):
        """Edit settings.
        """
        if 'default_realm' in self.REQUEST:
            self._realm = _kerberos5.default_realm()
        else:
            self._realm = self.REQUEST.get('realm')
            self._config_file = self.REQUEST.get('config')
        self.REQUEST.RESPONSE.redirect('manage_workspace')

    def getRealm(self):
        return self._realm

    def getConfigFile(self):
        return self._config_file

    def authenticateCredentials(self, credentials):
        login = credentials.get('login')
        if login is not None:
            kwargs = {'username': login,
                      'password': credentials.get('password', '')}
            if self._realm:
                kwargs['realm'] = self._realm
            if self._config_file:
                kwargs['config'] = self._config_file
            try:
                user = _kerberos5.KerberosUser(**kwargs)
                if user.is_valid():
                    username = user.get_username()
                    principal = user.get_principal()
                    logger.info('Authentication succeed for "%s" (%s)' % (username, principal))
                    return (username, principal)
            except (_kerberos5.KerberosError, _kerberos5.KerberosPasswordExpired) as error:
                logger.info('Failed to authenticate "%s" (%s)' % (login, error.args[0]))
                pass
        return (None, None)


classImplements(Kerberos5Plugin,
                IKerberos5Plugin,
                plugins.IAuthenticationPlugin,
                *implementedBy(BasePlugin))


InitializeClass(Kerberos5Plugin)
