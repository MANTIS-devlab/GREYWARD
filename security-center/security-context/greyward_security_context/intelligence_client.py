"""Fixed read-only provider; unavailable evidence stays unavailable."""
import json
def snapshot(filters=None):
    try:
        import dbus
        import dbus.mainloop
        bus=dbus.SystemBus(private=True, mainloop=dbus.mainloop.NULL_MAIN_LOOP)
        try:
            proxy=dbus.Interface(bus.get_object('systems.mantis.greyward.Intelligence1','/systems/mantis/greyward/Intelligence1',introspect=False),'systems.mantis.greyward.Intelligence1')
            value=json.loads(str(proxy.GetSnapshot(json.dumps(filters or {}),timeout=3)))
            if value.get('schema')!='greyward.intelligence/v1':raise ValueError('Unsupported intelligence schema')
            return value
        finally:bus.close()
    except Exception:
        return {'schema':'greyward.intelligence/v1','sensor':{'state':'UNAVAILABLE','detail':'The local behavioral evidence provider is unavailable.'},'events':[],'incidents':[]}
