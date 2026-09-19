import json
import os
import sys
from concurrent import futures
import grpc
sys.path.insert(0, "/tmp/greyward-opensnitch-proto")
import ui_pb2
import ui_pb2_grpc
LOG = "/tmp/greyward-opensnitch-events.jsonl"

def record(kind, data):
    with open(LOG, "a", encoding="utf-8") as output:
        output.write(json.dumps({"kind": kind, **data}, sort_keys=True) + "\n")

class GreywardControlPlane(ui_pb2_grpc.UIServicer):
    def Ping(self, request, context):
        record("node_ping", {"daemon_version": request.stats.daemon_version, "rules": request.stats.rules})
        return ui_pb2.PingReply(id=request.id)

    def Subscribe(self, request, context):
        record("node_subscribe", {"name": request.name, "version": request.version, "firewall_running": request.isFirewallRunning, "rules": len(request.rules)})
        return request

    def AskRule(self, request, context):
        event = {"protocol": request.protocol, "process_path": request.process_path, "process_id": request.process_id, "user_id": request.user_id, "destination_host": request.dst_host, "destination_ip": request.dst_ip, "destination_port": request.dst_port}
        decision = "allow" if request.process_path in ("/usr/bin/curl", "/usr/lib/systemd/systemd-resolved") else "deny"
        record("normalized_connection", {**event, "decision": decision})
        if decision == "allow":
            return ui_pb2.Rule(name="900-greyward-spike-allow-" + request.process_path.rsplit("/", 1)[-1], description="GREYWARD protocol spike persistent allow", enabled=True, precedence=True, action="allow", duration="always", operator=ui_pb2.Operator(type="simple", operand="process.path", data=request.process_path))
        return ui_pb2.Rule(name="901-greyward-spike-deny-other", description="GREYWARD protocol spike one-shot deny", enabled=True, precedence=True, action="deny", duration="once", operator=ui_pb2.Operator(type="simple", operand="true", data=""))

    def Notifications(self, request_iterator, context):
        for reply in request_iterator:
            record("notification_reply", {"id": reply.id, "code": reply.code, "data": reply.data})
        return

    def PostAlert(self, request, context):
        record("alert", {"what": request.what, "priority": request.priority})
        return ui_pb2.MsgResponse(id=request.id)

def main():
    sock = "/run/greyward-opensnitch-spike.sock"
    try:
        os.unlink(sock)
    except FileNotFoundError:
        pass
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    ui_pb2_grpc.add_UIServicer_to_server(GreywardControlPlane(), server)
    if server.add_insecure_port("unix:" + sock) != 1:
        raise RuntimeError("unable to bind " + sock)
    server.start()
    record("server_ready", {"socket": sock})
    server.wait_for_termination()

if __name__ == "__main__":
    main()