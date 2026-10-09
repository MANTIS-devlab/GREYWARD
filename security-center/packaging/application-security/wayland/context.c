/* GREYWARD private display connection. The broker supplies the pinned host
 * endpoint in its private mount namespace; this helper grants no file access. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <wayland-client.h>
#include "security-context-v1-client-protocol.h"
struct globals { struct wp_security_context_manager_v1 *manager; bool duplicate; };
static void global(void *data, struct wl_registry *registry, uint32_t name,
    const char *interface, uint32_t version) {
    struct globals *g = data;
    if (strcmp(interface, "wp_security_context_manager_v1")) return;
    if (g->manager || version < 1) { g->duplicate = true; return; }
    g->manager = wl_registry_bind(registry, name, &wp_security_context_manager_v1_interface, 1);
}
static void removed(void *data, struct wl_registry *registry, uint32_t name) {
    (void)data; (void)registry; (void)name;
}
static const struct wl_registry_listener listener = {global, removed};
int main(int argc, char **argv) {
    (void)argv;
    uid_t owner = getuid();
    if (argc != 1 || owner < 1000 || owner >= 60000 || geteuid() != owner) return 125;
    char context[256]; FILE *source = fopen("/proc/self/attr/current", "r");
    if (!source || !fgets(context, sizeof(context), source)) return 125;
    fclose(source); context[strcspn(context, "\n")] = '\0';
    if (strcmp(context, "greyward_guard_u:greyward_guard_r:greyward_guard_t:s0")
        && strcmp(context, "greyward_guard_u:greyward_guard_r:greyward_as_gateway_t:s0")) return 125;
    struct wl_display *display = wl_display_connect("/run/guard-host-wayland");
    if (!display) return 125;
    struct ucred peer; socklen_t size = sizeof(peer);
    if (getsockopt(wl_display_get_fd(display), SOL_SOCKET, SO_PEERCRED, &peer, &size)
        || size != sizeof(peer) || peer.uid != owner) return 125;
    struct globals g = {0}; struct wl_registry *registry = wl_display_get_registry(display);
    wl_registry_add_listener(registry, &listener, &g);
    if (wl_display_roundtrip(display) < 0 || !g.manager || g.duplicate) return 125;
    int listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0), closing[2];
    if (listen_fd < 0 || pipe2(closing, O_CLOEXEC)) return 125;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, "/work/host/context.sock");
    if (bind(listen_fd, (struct sockaddr *)&address, sizeof(address)) || listen(listen_fd, 4)) return 125;
    struct wp_security_context_v1 *security = wp_security_context_manager_v1_create_listener(g.manager, listen_fd, closing[0]);
    wp_security_context_v1_set_sandbox_engine(security, "systems.mantis.greyward");
    wp_security_context_v1_set_app_id(security, "isolated-nested-display");
    wp_security_context_v1_set_instance_id(security, "prepared-private-workload");
    wp_security_context_v1_commit(security);
    if (wl_display_roundtrip(display) < 0) return 125;
    close(listen_fd); close(closing[0]);
    if (puts("GREYWARD_PRIVATE_DISPLAY_READY_V1") < 0 || fflush(stdout)) return 125;
    /* No host clipboard/selection forwarding. Closing the supervisor's pipe
     * retires the listener; the owning cgroup terminates all existing clients. */
    struct pollfd lifetime = {.fd = STDIN_FILENO, .events = POLLIN | POLLHUP};
    while (poll(&lifetime, 1, -1) > 0) {
        if (lifetime.revents & (POLLHUP | POLLERR)) break;
        if (lifetime.revents & POLLIN) { char byte; if (read(STDIN_FILENO, &byte, 1) <= 0) break; }
    }
    close(closing[1]); wp_security_context_v1_destroy(security);
    wp_security_context_manager_v1_destroy(g.manager); wl_registry_destroy(registry);
    wl_display_disconnect(display); return 0;
}
