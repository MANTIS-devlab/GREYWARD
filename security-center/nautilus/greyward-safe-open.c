#include <gio/gio.h>
#include <glib.h>
#include <nautilus-extension.h>

typedef struct _GreywardSafeOpen GreywardSafeOpen;
typedef struct _GreywardSafeOpenClass GreywardSafeOpenClass;
struct _GreywardSafeOpen { GObject parent_instance; };
struct _GreywardSafeOpenClass { GObjectClass parent_class; };

static void free_path(gpointer data, GClosure *closure)
{
    (void)closure;
    g_free(data);
}

static void greyward_safe_open_menu_provider_init(NautilusMenuProviderInterface *iface);
G_DEFINE_DYNAMIC_TYPE_EXTENDED(GreywardSafeOpen, greyward_safe_open, G_TYPE_OBJECT, 0,
                               G_IMPLEMENT_INTERFACE_DYNAMIC(NAUTILUS_TYPE_MENU_PROVIDER,
                                                             greyward_safe_open_menu_provider_init))

static void notify_user(const char *title, const char *detail)
{
    GError *error = NULL;
    GSubprocess *process = g_subprocess_new(G_SUBPROCESS_FLAGS_NONE, &error,
                                            "notify-send", title, detail, NULL);
    if (process) g_object_unref(process);
    g_clear_error(&error);
}

static void activate_safe_open(NautilusMenuItem *item, gpointer user_data)
{
    (void)item;
    const char *path = user_data;
    GError *error = NULL;
    GSubprocess *process = g_subprocess_new(G_SUBPROCESS_FLAGS_STDOUT_PIPE |
                                           G_SUBPROCESS_FLAGS_STDERR_PIPE, &error,
                                           "gdbus", "call", "--session",
                                           "--dest", "systems.mantis.greyward.SecurityContext1",
                                           "--object-path", "/systems/mantis/greyward/SecurityContext1",
                                           "--method", "systems.mantis.greyward.SecurityContext1.SafeOpen",
                                           path, NULL);
    if (!process) {
        notify_user("Safe Open unavailable", "Security Context did not accept the request.");
        g_clear_error(&error);
        return;
    }
    gchar *out = NULL, *err = NULL;
    if (!g_subprocess_communicate_utf8(process, NULL, NULL, &out, &err, &error))
        notify_user("Safe Open unavailable", "Security Context did not accept the request.");
    else if (g_subprocess_get_successful(process) && g_strstr_len(out, -1, "\"ok\":true"))
        notify_user("Safe Open", "The file was opened in a restricted context.");
    else
        notify_user("Safe Open refused", "The selected file could not be opened safely.");
    g_free(out); g_free(err); g_clear_error(&error); g_object_unref(process);
}

static void activate_security_context(NautilusMenuItem *item, gpointer user_data)
{
    (void)item;
    const char *path = user_data;
    GError *error = NULL;
    GSubprocess *process = g_subprocess_new(G_SUBPROCESS_FLAGS_NONE, &error,
                                            "greyward-file-context",
                                            path, NULL);
    if (!process) notify_user("Security Context unavailable", "GREYWARD file context could not be opened.");
    if (process) g_object_unref(process);
    g_clear_error(&error);
}
static void activate_scan(NautilusMenuItem *item, gpointer user_data)
{
    (void)item;
    const char *path = user_data;
    GError *error = NULL;
    GSubprocess *process = g_subprocess_new(G_SUBPROCESS_FLAGS_NONE, &error,
                                            "greyward-file-context", "--scan", path, NULL);
    if (!process) notify_user("GREYWARD Security", "The scan could not be started.");
    if (process) g_object_unref(process);
    g_clear_error(&error);
}
static GList *get_file_items(NautilusMenuProvider *provider, GList *files)
{
    (void)provider;
    if (g_list_length(files) != 1) return NULL;
    NautilusFileInfo *file = files->data;
    if (nautilus_file_info_get_file_type(file) != G_FILE_TYPE_REGULAR ||
        g_strcmp0(nautilus_file_info_get_uri_scheme(file), "file") != 0) return NULL;
    char *path = g_file_get_path(nautilus_file_info_get_location(file));
    if (!path) return NULL;
    NautilusMenuItem *item = nautilus_menu_item_new("Greyward::SafeOpen", "Open with Safe Open",
                                                     "Open this file in a disposable restricted context",
                                                     "security-high-symbolic");
    g_signal_connect_data(item, "activate", G_CALLBACK(activate_safe_open), path,
                          free_path, 0);
    NautilusMenuItem *context_item = nautilus_menu_item_new("Greyward::SecurityContext", "Security Context",
                                                            "View bounded GREYWARD context for this file",
                                                            "security-high-symbolic");
    g_signal_connect_data(context_item, "activate", G_CALLBACK(activate_security_context), g_strdup(path),
                          free_path, 0);
    NautilusMenuItem *scan_item = nautilus_menu_item_new("Greyward::Scan", "Scan with ClamAV",
                                                         "Scan this file with GREYWARD", "security-high-symbolic");
    g_signal_connect_data(scan_item, "activate", G_CALLBACK(activate_scan), g_strdup(path),
                          free_path, 0);
    GList *items = g_list_append(NULL, item);
    items = g_list_append(items, context_item);
    return g_list_append(items, scan_item);
}

static void greyward_safe_open_menu_provider_init(NautilusMenuProviderInterface *iface)
{ iface->get_file_items = get_file_items; }
static void greyward_safe_open_class_init(GreywardSafeOpenClass *klass) { (void)klass; }
static void greyward_safe_open_class_finalize(GreywardSafeOpenClass *klass) { (void)klass; }
static void greyward_safe_open_init(GreywardSafeOpen *self) { (void)self; }

void nautilus_module_initialize(GTypeModule *module) { greyward_safe_open_register_type(module); }
void nautilus_module_shutdown(void) {}
void nautilus_module_list_types(const GType **types, int *num_types)
{ static GType type; type = greyward_safe_open_get_type(); *types = &type; *num_types = 1; }

