/* Private compositor protocol feasibility, never a generic launch/authority API. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <wayland-client.h>
#include "security-context-client.h"

#define BASE "/run/greyward-application-security-wayland"
#define MAX_GLOBALS 128
struct globals {
    struct wl_display *display;
    struct wl_registry *registry;
    struct wp_security_context_manager_v1 *manager;
    uint32_t security_name;
    unsigned count;
    char names[MAX_GLOBALS][128];
};

static void fail(const char *message) {
    fprintf(stderr, "Private Wayland probe failed: %s\n", message);
    exit(1);
}

static void global(void *data, struct wl_registry *registry, uint32_t name,
        const char *interface, uint32_t version) {
    struct globals *found = data;
    if (found->count >= MAX_GLOBALS || strlen(interface) >= 128)
        fail("unbounded registry");
    strcpy(found->names[found->count++], interface);
    if (!strcmp(interface, "wp_security_context_manager_v1")) {
        if (found->manager || version < 1) fail("ambiguous context manager");
        found->security_name = name;
        found->manager = wl_registry_bind(registry, name,
                &wp_security_context_manager_v1_interface, 1);
    }
}

static void removed(void *data, struct wl_registry *registry, uint32_t name) {
    (void)data; (void)registry; (void)name;
}
static const struct wl_registry_listener listener = {global, removed};

static bool has(const struct globals *found, const char *name) {
    for (unsigned i = 0; i < found->count; ++i)
        if (!strcmp(found->names[i], name)) return true;
    return false;
}

static void connect_display(struct globals *found, const char *socket_name) {
    memset(found, 0, sizeof(*found));
    found->display = wl_display_connect(socket_name);
    if (!found->display) fail("private connection unavailable");
    struct ucred peer;
    socklen_t length = sizeof(peer);
    if (getsockopt(wl_display_get_fd(found->display), SOL_SOCKET, SO_PEERCRED,
                &peer, &length) || length != sizeof(peer) || peer.uid != 1002)
        fail("wrong compositor peer");
    found->registry = wl_display_get_registry(found->display);
    wl_registry_add_listener(found->registry, &listener, found);
    if (wl_display_roundtrip(found->display) < 0) fail("registry unavailable");
}

int main(int argc, char **argv) {
    if (argc != 1 || !argv || getuid() != 1002 || geteuid() != 1002)
        fail("fixed separate account required");
    const char *runtime = getenv("XDG_RUNTIME_DIR");
    if (!runtime || strcmp(runtime, BASE "/runtime")) fail("wrong private runtime");
    char label[256];
    FILE *context_file = fopen("/proc/self/attr/current", "r");
    if (!context_file || !fgets(label, sizeof(label), context_file)) fail("missing context");
    fclose(context_file);
    label[strcspn(label, "\n")] = '\0';
    if (strcmp(label, "greyward_guard_u:greyward_guard_r:greyward_guard_t:s0"))
        fail("missing ordinary confined subject");
    struct globals ordinary, restricted, forged;
    connect_display(&ordinary, "wayland-0");
    if (!ordinary.manager || !has(&ordinary, "ext_session_lock_manager_v1") ||
            !has(&ordinary, "zwlr_screencopy_manager_v1")) fail("positive controls missing");
    int listening = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int close_pipe[2];
    if (listening < 0 || pipe2(close_pipe, O_CLOEXEC)) fail("private descriptors unavailable");
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, BASE "/runtime/restricted.sock");
    if (bind(listening, (struct sockaddr *)&address, sizeof(address)) || listen(listening, 4))
        fail("private listener unavailable");
    struct wp_security_context_v1 *context =
        wp_security_context_manager_v1_create_listener(ordinary.manager, listening, close_pipe[0]);
    wp_security_context_v1_set_sandbox_engine(context, "systems.mantis.greyward.experimental");
    wp_security_context_v1_set_app_id(context, "synthetic-protocol-probe");
    wp_security_context_v1_set_instance_id(context, "private-fixed-test");
    wp_security_context_v1_commit(context);
    if (wl_display_roundtrip(ordinary.display) < 0) fail("context commit rejected");
    close(listening);
    close(close_pipe[0]);
    connect_display(&restricted, "restricted.sock");
    const char *required[] = {"wl_shm", "wl_compositor", "wl_subcompositor",
        "wl_seat", "xdg_wm_base", "wl_data_device_manager"};
    for (unsigned i = 0; i < sizeof(required) / sizeof(*required); ++i)
        if (!has(&restricted, required[i])) fail("ordinary client capability missing");
    const char *denied[] = {"wp_security_context_manager_v1", "ext_session_lock_manager_v1",
        "zwlr_screencopy_manager_v1", "ext_data_control_manager_v1", "zwlr_data_control_manager_v1",
        "zwp_virtual_keyboard_manager_v1", "zwlr_virtual_pointer_manager_v1", "zwlr_layer_shell_v1",
        "ext_image_copy_capture_manager_v1", "ext_output_image_capture_source_manager_v1",
        "zwlr_foreign_toplevel_manager_v1", "ext_foreign_toplevel_list_v1"};
    unsigned positive_denied = 0;
    for (unsigned i = 0; i < sizeof(denied) / sizeof(*denied); ++i) {
        if (has(&restricted, denied[i])) fail("privileged interface leaked");
        if (has(&ordinary, denied[i])) ++positive_denied;
    }
    if (positive_denied < 5) fail("insufficient advertised privileged controls");
    // Absence from advertisement alone is insufficient: use the ordinary
    // connection's real global name to attempt an explicit forged bind.
    connect_display(&forged, "restricted.sock");
    struct wp_security_context_manager_v1 *spoof = wl_registry_bind(forged.registry,
        ordinary.security_name, &wp_security_context_manager_v1_interface, 1);
    if (!spoof || wl_display_roundtrip(forged.display) >= 0 ||
            wl_display_get_error(forged.display) != EPROTO) fail("forged privileged bind accepted");
    wl_display_disconnect(forged.display);
    wp_security_context_v1_destroy(context);
    wp_security_context_manager_v1_destroy(ordinary.manager);
    wl_registry_destroy(ordinary.registry);
    wl_display_disconnect(ordinary.display);
    if (wl_display_roundtrip(restricted.display) < 0) fail("creator exit lost established context");
    close(close_pipe[1]);
    // Existing clients are not revoked by listener expiry. No such promise.
    if (wl_display_roundtrip(restricted.display) < 0) fail("unexpected established-client revocation");
    wl_registry_destroy(restricted.registry);
    wl_display_disconnect(restricted.display);
    printf("{\"schema\":\"greyward.application-security.wayland-probe/v1\","
        "\"passed\":true,\"advertised_privileged_controls\":%u,"
        "\"forged_context_bind_rejected\":true,\"ordinary_data_device_present\":true,"
        "\"clipboard_isolation_claimed\":false,\"host_socket_denial_tested\":false}\n", positive_denied);
    return 0;
}
