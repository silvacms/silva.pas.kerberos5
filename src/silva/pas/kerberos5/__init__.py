# -*- coding: utf-8 -*-
# Copyright (c) 2011 Infrae. All rights reserved.
# See also LICENSE.txt
# $Id$

from AccessControl.Permissions import manage_users as ManageUsers
from Products.PluggableAuthService import registerMultiPlugin

from silva.pas.kerberos5.plugins import kerberos5

registerMultiPlugin(kerberos5.Kerberos5Plugin.meta_type)


def initialize(context):
    context.registerClass(kerberos5.Kerberos5Plugin,
                          permission=ManageUsers,
                          constructors=
                          (kerberos5.manage_addKerberos5PluginForm,
                           kerberos5.manage_addKerberos5Plugin),
                          visibility=None,
                          icon="www/kerberos5.png")
