# -*- coding: utf-8 -*-
# Copyright (c) 2011 Infrae. All rights reserved.
# See also LICENSE.txt
# $Id$

from AccessControl import ClassSecurityInfo
from App.class_init import InitializeClass

from zope.interface import Interface
from zope.interface import implementedBy
# from silva.pas.kerberos5 import _kerberos5
from Products.PluggableAuthService.permissions import ManageUsers
from Products.PluggableAuthService.interfaces import plugins
from Products.PluggableAuthService.utils import classImplements
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PageTemplates.PageTemplateFile import PageTemplateFile

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

    security.declareProtected(ManageUsers, 'manage_editRadiusKerberos5Form')
    manage_editKerberos5PluginForm = PageTemplateFile(
        '../www/kerberos5EditForm', globals(), __name__="manage_editKerberos5PluginForm")


classImplements(Kerberos5Plugin,
                IKerberos5Plugin,
                plugins.IAuthenticationPlugin,
                *implementedBy(BasePlugin))


InitializeClass(Kerberos5Plugin)
