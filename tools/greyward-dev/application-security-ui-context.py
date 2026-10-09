#!/usr/bin/python3
"""Source reads and presentation-only history on the private probe bus."""
import os
from pathlib import Path

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib
from greyward_security_context.user_bus import SecurityContext, BUS_NAME, OBJECT_PATH
from greyward_security_context import local_activity
from greyward_security_context.telemetry import TelemetryError
from greyward_security_context.application_workflows import ApplicationSecurityWorkflows

if os.getuid() != 1002 or Path.home() != Path('/run/greyward-application-security-ui/home'):
    raise SystemExit('Private test account/unit required')
dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)


class PrivateReads(dbus.service.Object):
    def __init__(self, bus, path):
        super().__init__(bus, path)
        self._application_bus = bus
        self.application_workflows = ApplicationSecurityWorkflows()

    # Use the product's actual bounded methods and peer resolution. This
    # private presentation fixture has no replacement policy or fake grants.
    _application_actor = SecurityContext._application_actor
    _application_workflow = SecurityContext._application_workflow
    ListApplicationAccessGrants = SecurityContext.ListApplicationAccessGrants
    PreviewProtectedResource = SecurityContext.PreviewProtectedResource
    PreviewApplicationGrant = SecurityContext.PreviewApplicationGrant
    PreviewApplicationRevocation = SecurityContext.PreviewApplicationRevocation
    ApplyApplicationPolicy = SecurityContext.ApplyApplicationPolicy
    GetApplicationOperation = SecurityContext.GetApplicationOperation
    CancelApplicationOperation = SecurityContext.CancelApplicationOperation
    PrepareApplicationLaunch = SecurityContext.PrepareApplicationLaunch
    QueryTelemetry = SecurityContext.QueryTelemetry

    @dbus.service.method(BUS_NAME, in_signature='', out_signature='s')
    def GetLocalActivity(self):
        return SecurityContext.GetLocalActivity(self)

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s')
    def RecordLocalActivity(self, payload):
        return SecurityContext.RecordLocalActivity(self, payload)

    @dbus.service.method(BUS_NAME, in_signature='', out_signature='s')
    def ClearLocalActivity(self):
        return SecurityContext.ClearLocalActivity(self)

    @dbus.service.method(BUS_NAME, in_signature='', out_signature='s')
    def GetApplicationCoverage(self):
        return SecurityContext.GetApplicationCoverage(self)

    @dbus.service.method(BUS_NAME, in_signature='ubts', out_signature='s')
    def ListApplications(self, limit, has_revision, revision, after):
        return SecurityContext.ListApplications(self, limit, has_revision, revision, after)

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s')
    def GetApplication(self, installation_ref):
        return SecurityContext.GetApplication(self, installation_ref)

    @dbus.service.method(BUS_NAME, in_signature='ubts', out_signature='s')
    def ListProtectedResources(self, limit, has_revision, revision, after):
        return SecurityContext.ListProtectedResources(self, limit, has_revision, revision, after)

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s')
    def GetProtectedResource(self, resource_ref):
        return SecurityContext.GetProtectedResource(self, resource_ref)


bus = dbus.SessionBus()
name = dbus.service.BusName(BUS_NAME, bus=bus, do_not_queue=True)
service = PrivateReads(bus, OBJECT_PATH)
try:
    local_activity.migrate()
except TelemetryError:
    # Keep read failure observable through the typed API rather than losing
    # the private service name; the real runtime also reconciles separately.
    pass
GLib.MainLoop().run()
