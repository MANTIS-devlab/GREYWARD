/* GREYWARD protected Administration terminal. SPDX-License-Identifier: GPL-3.0-only
 * No clipboard, drag/drop, user configuration, bus, virtual input or output IPC.
 * ext-session-lock excludes ordinary surfaces/input until explicit return.
 * Root admission is separate; this process runs as the requesting account.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>
#include <cairo/cairo.h>
#include <pango/pangocairo.h>
#include <librsvg/rsvg.h>
#include <selinux/selinux.h>
#include <vterm.h>
#include <wayland-client.h>
#include <xkbcommon/xkbcommon.h>
#include "ext-session-lock-v1-client-protocol.h"
#include "greyward-admin-logo.h"

#define MAX_OUTPUTS 8
#define MAX_ARGS 128
#define MAX_REQUEST 16384
#define CONTEXT "greyward_admin_u:greyward_admin_r:greyward_admin_t:s0"
#define SELF "/usr/lib/greyward/application-security/administration/terminal"
#define CELL_WIDTH 11
#define CELL_HEIGHT 26
#define TERMINAL_TOP 128
#define TERMINAL_MARGIN 28
/* Match libvterm's default cells to the surrounding graphite surface. Explicit
 * ANSI backgrounds and reverse video retain their application-defined colors. */
#define SURFACE_RED 10
#define SURFACE_GREEN 12
#define SURFACE_BLUE 15
struct output {
    uint32_t name;
    struct wl_output *output;
    struct wl_surface *surface;
    struct ext_session_lock_surface_v1 *lock_surface;
    int width, height;
    double approve_x, approve_y;
    bool can_approve;
    double cancel_x, cancel_y;
};
struct frame { struct wl_buffer *buffer; void *pixels; size_t size; };
static struct wl_display *display;
static struct wl_compositor *compositor;
static struct wl_shm *shm;
static struct wl_seat *seat;
static struct wl_keyboard *keyboard;
static struct wl_pointer *pointer;
static struct output *pointer_output;
static double pointer_x, pointer_y;
static bool end_hover, approve_hover, cancel_hover;
static int repeat_rate, repeat_delay;
static uint32_t repeat_code;
static bool repeating, synthesizing_repeat;
static int64_t repeat_due;
static struct ext_session_lock_manager_v1 *manager;
static struct ext_session_lock_v1 *lock;
static struct output outputs[MAX_OUTPUTS];
static struct xkb_context *xkb;
static struct xkb_keymap *keymap;
static struct xkb_state *keys;
static VTerm *terminal;
static VTermScreen *screen;
static int pty_fd = -1, request_fd = 3, rows = 24, columns = 80;
static pid_t child;
static bool locked, reviewed, finished, exiting, dirty = true;
static bool paused;
static bool review_fits;
static unsigned live_frames;
static volatile sig_atomic_t interrupted;
static volatile sig_atomic_t pause_requested, resume_requested;
static volatile sig_atomic_t cache_requested;
static int64_t request_started;
static int64_t milliseconds(void);
static char request[MAX_REQUEST + MAX_ARGS + 2];
static char *arguments[MAX_ARGS + 3];
static int argument_count;
static const char *notice = "Press Enter to review and continue, or Escape to return to your desktop.";

static void stop(int sig) { (void)sig; interrupted = 1; }
static void pause_signal(int sig) { (void)sig; pause_requested = 1; }
static void resume_signal(int sig) { (void)sig; resume_requested = 1; }
static void cache_signal(int sig) { (void)sig; cache_requested = 1; }
static void fail(const char *message) { fprintf(stderr, "Administration unavailable: %s\n", message); exit(1); }
static void read_request(void) {
    struct stat st;
    if (fstat(request_fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 || st.st_mode & 0022 ||
        st.st_size < 1 || st.st_size > MAX_REQUEST + MAX_ARGS) fail("invalid prepared request");
    if (lseek(request_fd, 0, SEEK_SET) < 0) fail("request seek");
    ssize_t n = read(request_fd, request, sizeof(request) - 1);
    if (n != st.st_size || request[n-1] != '\0') fail("incomplete prepared request");
    for (ssize_t offset = 0; offset < n;) {
        if (argument_count >= MAX_ARGS) fail("too many arguments");
        char *arg = request + offset;
        size_t length = strlen(arg);
        for (size_t i = 0; i < length; i++) if ((unsigned char)arg[i] < 32 || arg[i] == 127) fail("request control character");
        arguments[++argument_count] = arg;
        offset += (ssize_t)length + 1;
    }
    arguments[0] = "/usr/bin/sudo";
}
static int run_sudo(const char *fixed) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (!pid) {
        close(request_fd);
        if (fixed) execl("/usr/bin/sudo", "sudo", fixed, (char *)NULL);
        else execv("/usr/bin/sudo", arguments);
        _exit(126);
    }
    int status;
    while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128;
}
static void console(void) {
    /* This PID remains the controlling-terminal session leader after bash exec;
     * timestamp_type=tty binds cache to its unchanged terminal/session identity. */
    read_request();
    close(4);
    unsetenv("WAYLAND_DISPLAY"); unsetenv("XDG_RUNTIME_DIR");
    if (run_sudo("-k") != 0 || run_sudo("-v") != 0) _exit(126);
    /* A lock/policy invalidation while PAM was still running cannot mint a
     * replacement ticket and execute the proposal after the invalidation. */
    if (cache_requested) { run_sudo("-K"); _exit(126); }
    int status = run_sudo(NULL);
    if (status != 0) { fprintf(stderr, "\nOperation failed (%d). No unrestricted fallback.\n", status); _exit(status); }
    close(request_fd);
    puts("\nAdministration. Authentication is cached here for two minutes.\n"
         "An existing root shell stays privileged until you exit it.\n"
         "Use exit to end this terminal, or Ctrl+Shift+Q to request closing it.\n");
    execl("/bin/bash", "bash", "--noprofile", "--norc", (char *)NULL);
    _exit(126);
}
static void release_buffer(void *data, struct wl_buffer *buffer) {
    struct frame *frame = data;
    wl_buffer_destroy(buffer); munmap(frame->pixels, frame->size); free(frame);
    if (live_frames) live_frames--;
}
static const struct wl_buffer_listener buffer_listener = { .release = release_buffer };
static void styled_text(cairo_t *cr, double x, double y, const char *value, int size, bool bold, bool mono) {
    PangoLayout *layout = pango_cairo_create_layout(cr);
    PangoFontDescription *font = pango_font_description_new();
    pango_font_description_set_family(font, mono ? "monospace" : "Inter");
    pango_font_description_set_absolute_size(font, size * PANGO_SCALE);
    pango_font_description_set_weight(font, bold ? PANGO_WEIGHT_SEMIBOLD : PANGO_WEIGHT_NORMAL);
    pango_layout_set_font_description(layout, font);
    pango_layout_set_text(layout, value, -1);
    cairo_move_to(cr, x, y); pango_cairo_show_layout(cr, layout);
    pango_font_description_free(font); g_object_unref(layout);
}
static void text(cairo_t *cr, double x, double y, const char *value, int size, bool bold) {
    styled_text(cr,x,y,value,size,bold,false);
}
static int paragraph(cairo_t *cr, double x, double y, double width, const char *value, int size) {
    PangoLayout *layout = pango_cairo_create_layout(cr);
    PangoFontDescription *font = pango_font_description_from_string("Inter");
    pango_font_description_set_absolute_size(font,size*PANGO_SCALE);
    pango_layout_set_font_description(layout,font);
    pango_layout_set_width(layout,(int)(width*PANGO_SCALE));
    pango_layout_set_wrap(layout,PANGO_WRAP_WORD_CHAR);
    pango_layout_set_spacing(layout,5*PANGO_SCALE);
    pango_layout_set_text(layout,value,-1);
    int height; pango_layout_get_pixel_size(layout,NULL,&height);
    cairo_move_to(cr,x,y); pango_cairo_show_layout(cr,layout);
    pango_font_description_free(font); g_object_unref(layout);
    return height;
}
static RsvgHandle *brand_logo;
static RsvgRectangle logo_ink;
static cairo_pattern_t *grain;
static void rounded(cairo_t *cr, double x, double y, double width, double height, double radius) {
    cairo_new_sub_path(cr);
    cairo_arc(cr,x+width-radius,y+radius,radius,-1.5707963268,0);
    cairo_arc(cr,x+width-radius,y+height-radius,radius,0,1.5707963268);
    cairo_arc(cr,x+radius,y+height-radius,radius,1.5707963268,3.1415926536);
    cairo_arc(cr,x+radius,y+radius,radius,3.1415926536,4.7123889804);
    cairo_close_path(cr);
}
static void texture(cairo_t *cr,double amount) {
    if(!grain){
        cairo_surface_t *tile=cairo_image_surface_create(CAIRO_FORMAT_RGB24,128,128);
        uint32_t *pixels=(uint32_t *)cairo_image_surface_get_data(tile);
        uint32_t seed=0x47524559;
        for(int i=0;i<128*128;i++){
            seed^=seed<<13;seed^=seed>>17;seed^=seed<<5;
            uint32_t shade=72+(seed%112);pixels[i]=(shade<<16)|(shade<<8)|shade;
        }
        cairo_surface_mark_dirty(tile);grain=cairo_pattern_create_for_surface(tile);
        cairo_pattern_set_extend(grain,CAIRO_EXTEND_REPEAT);cairo_surface_destroy(tile);
    }
    cairo_save(cr);cairo_set_source(cr,grain);cairo_paint_with_alpha(cr,amount);cairo_restore(cr);
}
static void material(cairo_t *cr,double x,double y,double width,double height,double radius,bool warning) {
    cairo_save(cr);
    rounded(cr,x,y+8,width,height,radius);cairo_set_source_rgba(cr,0,0,0,.24);cairo_fill(cr);
    rounded(cr,x,y,width,height,radius);cairo_clip(cr);
    cairo_pattern_t *p=cairo_pattern_create_linear(x,y,x+width*.45,y+height);
    if(warning){
        cairo_pattern_add_color_stop_rgb(p,0,.125,.079,.082);
        cairo_pattern_add_color_stop_rgb(p,1,.071,.056,.064);
    }else{
        cairo_pattern_add_color_stop_rgb(p,0,.12,.137,.153);
        cairo_pattern_add_color_stop_rgb(p,1,.058,.07,.085);
    }
    cairo_set_source(cr,p);cairo_paint(cr);cairo_pattern_destroy(p);texture(cr,.025);
    cairo_restore(cr);
    rounded(cr,x+.5,y+.5,width-1,height-1,radius);
    cairo_set_source_rgba(cr,warning?.85:.69,warning?.45:.77,warning?.44:.84,warning?.25:.20);
    cairo_set_line_width(cr,1);cairo_stroke(cr);
    cairo_save(cr);rounded(cr,x,y,width,height,radius);cairo_clip(cr);
    cairo_set_source_rgba(cr,.86,.91,.94,.13);cairo_rectangle(cr,x+radius,y,width-2*radius,1);cairo_fill(cr);
    cairo_restore(cr);
}
static void logo(cairo_t *cr,double x,double y,double size) {
    GError *error=NULL;
    if(!brand_logo){
        brand_logo=rsvg_handle_new_from_data(greyward_logo_svg,sizeof(greyward_logo_svg),&error);
        if(!brand_logo){if(error)g_error_free(error);fail("embedded branding unavailable");}
        RsvgRectangle canvas={0,0,1024,1024};
        if(!rsvg_handle_get_geometry_for_layer(brand_logo,NULL,&canvas,&logo_ink,NULL,&error)||logo_ink.width<=0||logo_ink.height<=0){
            if(error)g_error_free(error);
            fail("embedded branding geometry");
        }
    }
    double scale=size/(logo_ink.width>logo_ink.height?logo_ink.width:logo_ink.height);
    cairo_save(cr);
    cairo_translate(cr,x+(size-logo_ink.width*scale)/2,y+(size-logo_ink.height*scale)/2);
    cairo_scale(cr,scale,scale);cairo_translate(cr,-logo_ink.x,-logo_ink.y);
    RsvgRectangle viewport={0,0,1024,1024};
    if(!rsvg_handle_render_document(brand_logo,cr,&viewport,&error)){
        if(error)g_error_free(error);
        fail("embedded branding render");
    }
    cairo_restore(cr);
}
static void approval_button(cairo_t *cr,double x,double y,bool hover) {
    cairo_save(cr);rounded(cr,x,y,280,48,9);cairo_clip(cr);
    cairo_pattern_t *p=cairo_pattern_create_linear(0,y,0,y+48);
    cairo_pattern_add_color_stop_rgb(p,0,hover?.92:.84,hover?.95:.88,hover?.97:.91);
    cairo_pattern_add_color_stop_rgb(p,.48,hover?.79:.69,hover?.85:.77,hover?.89:.82);
    cairo_pattern_add_color_stop_rgb(p,1,hover?.72:.61,hover?.78:.69,hover?.83:.74);
    cairo_set_source(cr,p);cairo_paint(cr);cairo_pattern_destroy(p);texture(cr,.018);cairo_restore(cr);
    rounded(cr,x+.5,y+.5,279,47,9);cairo_set_source_rgba(cr,1,1,1,.44);cairo_set_line_width(cr,1);cairo_stroke(cr);
    cairo_set_source_rgb(cr,.055,.073,.092);text(cr,x+22,y+14,"Approve & authenticate",15,true);
    cairo_set_source_rgba(cr,.08,.11,.14,.16);rounded(cr,x+230,y+11,38,26,5);cairo_fill(cr);
    cairo_set_source_rgb(cr,.12,.17,.20);text(cr,x+236,y+18,"Enter",10,true);
}
static void defaults(VTerm *vt) {
    VTermColor foreground, background;
    vterm_color_rgb(&foreground,220,226,229);
    vterm_color_rgb(&background,SURFACE_RED,SURFACE_GREEN,SURFACE_BLUE);
    vterm_state_set_default_colors(vterm_obtain_state(vt),&foreground,&background);
    /* Legible ANSI colors on graphite; indexed/true-color escape sequences
     * retain their semantics. Black remains actual black when explicitly set. */
    static const uint8_t palette[16][3]={
        {0,0,0},{207,132,131},{157,199,170},{213,196,156},
        {142,174,211},{181,159,203},{151,197,205},{220,226,229},
        {105,119,127},{229,160,155},{185,223,191},{235,217,174},
        {177,204,234},{209,187,228},{181,223,229},{246,248,249}
    };
    for(int i=0;i<16;i++){
        VTermColor color;vterm_color_rgb(&color,palette[i][0],palette[i][1],palette[i][2]);
        vterm_state_set_palette_color(vterm_obtain_state(vt),i,&color);
    }
}
static void draw_cell(cairo_t *cr, VTermScreen *cells, int row, int col) {
    VTermScreenCell cell;
    if (!vterm_screen_get_cell(cells,(VTermPos){row,col},&cell) || cell.width < 1 || cell.chars[0] == UINT32_MAX) return;
    VTermColor fg=cell.fg,bg=cell.bg;
    vterm_screen_convert_color_to_rgb(cells,&fg); vterm_screen_convert_color_to_rgb(cells,&bg);
    if (cell.attrs.reverse) { VTermColor swap=fg;fg=bg;bg=swap; }
    double x=TERMINAL_MARGIN+col*CELL_WIDTH, y=TERMINAL_TOP+row*CELL_HEIGHT;
    /* Blank cells can carry an ANSI background (erase/full-screen tools). */
    /* Default cells reveal the continuous material, avoiding rectangular
     * patches around text. Explicit backgrounds still paint, including black. */
    if(bg.rgb.red!=SURFACE_RED||bg.rgb.green!=SURFACE_GREEN||bg.rgb.blue!=SURFACE_BLUE){
        cairo_set_source_rgb(cr,bg.rgb.red/255.0,bg.rgb.green/255.0,bg.rgb.blue/255.0);
        cairo_rectangle(cr,x,y,CELL_WIDTH*cell.width,CELL_HEIGHT);cairo_fill(cr);
    }
    if (!cell.chars[0]) return;
    char glyph[32]={0}; int offset=0;
    for (int i=0;i<VTERM_MAX_CHARS_PER_CELL && cell.chars[i];i++) {
        if (offset>24) break;
        offset+=g_unichar_to_utf8(cell.chars[i],glyph+offset);
    }
    cairo_set_source_rgb(cr,fg.rgb.red/255.0,fg.rgb.green/255.0,fg.rgb.blue/255.0);
    styled_text(cr,x,y+2,glyph,17,cell.attrs.bold,true);
}
static void paint(struct output *out) {
    if (!out->width || !out->height || live_frames >= MAX_OUTPUTS * 2) return;
    int width = out->width, height = out->height, stride = width * 4;
    if (width > 8192 || height > 8192 || width < 64 || height < 64) fail("unsupported output geometry");
    struct frame *frame = calloc(1, sizeof(*frame));
    if (!frame) fail("memory");
    frame->size = (size_t)stride * height;
    int fd = memfd_create("greyward-administration-pixels", MFD_CLOEXEC);
    if (fd < 0 || ftruncate(fd, frame->size)) fail("pixel buffer");
    frame->pixels = mmap(NULL, frame->size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (frame->pixels == MAP_FAILED) fail("pixel mapping");
    /* Wayland's server imports SHM with a writable mapping. Only this dedicated
     * pixel type is shared with the trusted display; no terminal/PTTY memory,
     * request, configuration or authentication descriptor is exported. */
    struct wl_shm_pool *pool = wl_shm_create_pool(shm, fd, frame->size);
    frame->buffer = wl_shm_pool_create_buffer(pool, 0, width, height, stride, WL_SHM_FORMAT_XRGB8888);
    close(fd); wl_shm_pool_destroy(pool);
    wl_buffer_add_listener(frame->buffer, &buffer_listener, frame); live_frames++;
    cairo_surface_t *surface = cairo_image_surface_create_for_data(frame->pixels, CAIRO_FORMAT_RGB24, width, height, stride);
    cairo_t *cr = cairo_create(surface);
    out->can_approve=false;
    cairo_set_source_rgb(cr,SURFACE_RED/255.0,SURFACE_GREEN/255.0,SURFACE_BLUE/255.0); cairo_paint(cr);
    texture(cr,.012);
    cairo_pattern_t *gradient = cairo_pattern_create_linear(0,0,0,110);
    cairo_pattern_add_color_stop_rgb(gradient,0,.09,.105,.12);
    cairo_pattern_add_color_stop_rgb(gradient,1,.039,.047,.059);
    cairo_set_source(cr,gradient); cairo_rectangle(cr,0,0,width,110); cairo_fill(cr); cairo_pattern_destroy(gradient);
    cairo_set_source_rgba(cr,.74,.81,.84,.20); cairo_rectangle(cr,0,109,width,1);cairo_fill(cr);
    logo(cr,30,25,58);
    cairo_set_source_rgb(cr,.70,.77,.81);text(cr,112,18,"GREYWARD",11,true);
    cairo_set_source_rgb(cr,.91,.58,.57);text(cr,110,36,"Administration",30,true);
    cairo_set_source_rgb(cr,.59,.66,.71);text(cr,112,77,"Privileged workspace",12,false);
    if(width>=1000){
        cairo_set_source_rgb(cr,.78,.83,.85);text(cr,width-372,28,"Protected input",14,true);
        cairo_set_source_rgb(cr,.61,.69,.72);text(cr,width-372,55,"Ctrl+Alt+F12 to verify  ·  Clipboard off",13,false);
    }
    if (!reviewed) {
        bool acknowledged = getenv("GREYWARD_ADMIN_WARNING_ACKNOWLEDGED") != NULL;
        double card_width=width-64; if(card_width>1000)card_width=1000;
        double left=(width-card_width)/2, y=153;
        cairo_set_source_rgb(cr,.91,.94,.95);text(cr,left,y,"Review administrative access",32,true);
        cairo_set_source_rgb(cr,.64,.72,.76);
        y+=53; y+=paragraph(cr,left,y,card_width,"You requested sudo. GREYWARD opens this protected Administration console to keep your password and elevated access separate from ordinary applications. Review the request, then authenticate here.",16)+30;
        double risk_top=y;
        const char *risk=acknowledged
            ? "Elevated commands can read your protected files, change or disable security controls, and damage the system. Code you run here can use this authority."
            : "Elevated commands can read or expose protected files, including credentials; change or disable GREYWARD's security controls; and delete data or damage the system. Programs and scripts you run here may use this authority, including malicious code.";
        /* Measure wrapped copy before filling its bounded material panel. */
        cairo_save(cr);cairo_rectangle(cr,0,0,0,0);cairo_clip(cr);
        int risk_height=paragraph(cr,left+24,y+55,card_width-48,risk,16);
        cairo_restore(cr);
        material(cr,left,y,card_width,risk_height+80,12,true);
        cairo_set_source_rgb(cr,.93,.64,.61);text(cr,left+24,y+20,"Administration can change your protections",17,true);
        cairo_set_source_rgb(cr,.83,.81,.81);paragraph(cr,left+24,y+55,card_width-48,risk,16);
        y=risk_top+risk_height+106;
        cairo_set_source_rgb(cr,.64,.72,.76);
        y+=paragraph(cr,left,y,card_width,"Sudo authentication is cached for two minutes in this console only. Expiry does not end a running root shell or command: exit it to end its privileges.",14)+26;
        double operation_top=y;
        int shown=argument_count<13?argument_count:12;
        material(cr,left,y,card_width,84+shown*26,12,false);
        cairo_set_source_rgb(cr,.67,.74,.78);text(cr,left+24,y+18,"YOUR REQUEST  /  Arguments shown individually",12,true);
        cairo_set_source_rgb(cr,.91,.94,.96);styled_text(cr,left+24,y+47,"/usr/bin/sudo",18,true,true);
        review_fits = argument_count < 13 && height > operation_top+shown*26+225 && width >= 720;
        for (int i = 1; i <= argument_count && i < 13; i++) {
            char label[MAX_REQUEST + 32]; snprintf(label,sizeof(label),"%d: \"%s\"",i,arguments[i]);
            PangoLayout *measure = pango_cairo_create_layout(cr);
            PangoFontDescription *font = pango_font_description_from_string("monospace 16px");
            pango_layout_set_font_description(measure, font); pango_layout_set_text(measure, label, -1);
            int extent; pango_layout_get_pixel_size(measure, &extent, NULL);
            review_fits &= extent <= card_width - 64;
            pango_font_description_free(font); g_object_unref(measure);
            cairo_save(cr);cairo_rectangle(cr,left+24,operation_top,card_width-48,84+shown*26);cairo_clip(cr);
            styled_text(cr,left+24,operation_top+49+i*26,label,16,false,true);cairo_restore(cr);
        }
        if(review_fits&&milliseconds()-request_started<=120000){
            y=operation_top+shown*26+112;
            out->approve_x=left;out->approve_y=y;out->can_approve=true;
            approval_button(cr,left,y,approve_hover);
            out->cancel_x=left+296;out->cancel_y=y;
            material(cr,left+296,y,150,48,9,false);
            if(cancel_hover){rounded(cr,left+296,y,150,48,9);cairo_set_source_rgba(cr,.75,.83,.90,.09);cairo_fill(cr);}
            cairo_set_source_rgb(cr,.84,.89,.93);text(cr,left+314,y+14,"Cancel",15,true);
            cairo_set_source_rgb(cr,.56,.65,.72);text(cr,left+408,y+18,"Esc",10,false);
        }
        notice = milliseconds()-request_started>120000 ? "Request expired. Press Escape and request Administration again."
            : review_fits ? "Enter: approve this request (valid for two minutes)  ·  Escape: cancel"
            : "Request cannot be displayed completely. Escape to return; open sudo -i and type the operation inside.";
    } else if (screen) {
        for (int row=0;row<rows;row++)for(int col=0;col<columns;col++)draw_cell(cr,screen,row,col);
        VTermPos cursor; vterm_state_get_cursorpos(vterm_obtain_state(terminal),&cursor);
        cairo_set_source_rgba(cr,.80,.85,.86,.4);cairo_rectangle(cr,TERMINAL_MARGIN+cursor.col*CELL_WIDTH,TERMINAL_TOP+cursor.row*CELL_HEIGHT,CELL_WIDTH,CELL_HEIGHT);cairo_fill(cr);
    }
    cairo_set_source_rgb(cr,.045,.055,.066);cairo_rectangle(cr,0,height-60,width,60);cairo_fill(cr);
    cairo_set_source_rgba(cr,.70,.78,.82,.16);cairo_rectangle(cr,0,height-60,width,1);cairo_fill(cr);
    cairo_set_source_rgb(cr,.67,.75,.79);paragraph(cr,28,height-45,width-220,notice,13);
    cairo_set_source_rgb(cr,end_hover?.24:.085,end_hover?.12:.103,end_hover?.13:.12);
    rounded(cr,width-164,height-44,144,32,7);cairo_fill_preserve(cr);
    cairo_set_source_rgba(cr,.75,.82,.85,.20);cairo_stroke(cr);
    cairo_set_source_rgb(cr,.85,.88,.89);text(cr,width-144,height-37,"End session",14,true);
    cairo_destroy(cr);cairo_surface_flush(surface);cairo_surface_destroy(surface);
    wl_surface_attach(out->surface,frame->buffer,0,0);
    wl_surface_damage(out->surface,0,0,width,height);wl_surface_commit(out->surface);
}
static void output_write(const char *bytes, size_t size, void *data) {
    (void)data;
    if (pty_fd < 0 || size > 4096) return;
    ssize_t n = write(pty_fd,bytes,size);
    if (n < 0 && errno != EAGAIN && errno != EINTR) interrupted = 1;
}
static void start_console(void) {
    if (write(4,"REVIEWED\n",9) != 9) { exiting = true; return; }
    struct winsize size = {.ws_row=rows,.ws_col=columns};
    child = forkpty(&pty_fd,NULL,NULL,&size);
    if (child < 0) fail("private terminal");
    if (!child) {
        int flags = fcntl(request_fd,F_GETFD);
        if (flags < 0 || fcntl(request_fd,F_SETFD,flags & ~FD_CLOEXEC)) _exit(126);
        execl(SELF,"terminal","--console",(char *)NULL);_exit(126);
    }
    close(request_fd);request_fd=-1;
    fcntl(pty_fd,F_SETFL,fcntl(pty_fd,F_GETFL)|O_NONBLOCK);
    terminal=vterm_new(rows,columns);if (!terminal)fail("terminal allocation");
    defaults(terminal);
    vterm_set_utf8(terminal,1);vterm_output_set_callback(terminal,output_write,NULL);
    screen=vterm_obtain_screen(terminal);vterm_screen_enable_altscreen(screen,1);
    vterm_screen_reset(screen,1);reviewed=true;
    notice="Ctrl+Shift+Q: end Administration  ·  exit: close shell  ·  Clipboard sharing is disabled";
}
static void map_keys(void *data, struct wl_keyboard *kb, uint32_t format, int32_t fd, uint32_t size) {
    (void)data;(void)kb;
    if (format != WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1 || size > 1024*1024 || !size) {close(fd);return;}
    char *map=mmap(NULL,size,PROT_READ,MAP_PRIVATE,fd,0);
    if(map==MAP_FAILED){close(fd);return;}
    if(map[size-1]){munmap(map,size);close(fd);return;}
    if(keys)xkb_state_unref(keys);
    if(keymap)xkb_keymap_unref(keymap);
    keymap=xkb_keymap_new_from_string(xkb,map,XKB_KEYMAP_FORMAT_TEXT_V1,0);
    keys=keymap?xkb_state_new(keymap):NULL;munmap(map,size);close(fd);
}
static void enter(void *d,struct wl_keyboard *k,uint32_t serial,struct wl_surface *s,struct wl_array *a){(void)d;(void)k;(void)serial;(void)s;(void)a;}
static int64_t milliseconds(void){struct timespec now;clock_gettime(CLOCK_MONOTONIC,&now);return (int64_t)now.tv_sec*1000+now.tv_nsec/1000000;}
static void leave(void *d,struct wl_keyboard *k,uint32_t serial,struct wl_surface *s){(void)d;(void)k;(void)serial;(void)s;repeating=false;}
static void key(void *d,struct wl_keyboard *k,uint32_t serial,uint32_t time,uint32_t code,uint32_t state) {
    (void)d;(void)k;(void)serial;(void)time;
    if(state==WL_KEYBOARD_KEY_STATE_RELEASED&&repeat_code==code)repeating=false;
    if(state!=WL_KEYBOARD_KEY_STATE_PRESSED||!keys||!locked)return;
    xkb_keysym_t sym=xkb_state_key_get_one_sym(keys,code+8);
    bool ctrl=xkb_state_mod_name_is_active(keys,XKB_MOD_NAME_CTRL,XKB_STATE_MODS_EFFECTIVE);
    bool shift=xkb_state_mod_name_is_active(keys,XKB_MOD_NAME_SHIFT,XKB_STATE_MODS_EFFECTIVE);
    bool alt=xkb_state_mod_name_is_active(keys,XKB_MOD_NAME_ALT,XKB_STATE_MODS_EFFECTIVE);
    if(!reviewed){
        if(sym==XKB_KEY_Escape)exiting=true;
        if(sym==XKB_KEY_Return && review_fits){
            if(milliseconds()-request_started>120000){notice="Request expired. Press Escape and request Administration again.";dirty=true;}
            else start_console();
        }
    }else if(finished){if(sym==XKB_KEY_Return||sym==XKB_KEY_Escape)exiting=true;}
    else if(ctrl&&shift&&(sym==XKB_KEY_Q||sym==XKB_KEY_q)){
        if(!strcmp(notice,"Press Ctrl+Shift+Q again to end Administration and interrupt its commands."))exiting=true;
        else notice="Press Ctrl+Shift+Q again to end Administration and interrupt its commands.";
    }else{
        if(!synthesizing_repeat&&repeat_rate>0&&xkb_keymap_key_repeats(keymap,code+8)){
            repeat_code=code;repeat_due=milliseconds()+repeat_delay;repeating=true;
        }
        VTermModifier mod=(ctrl?VTERM_MOD_CTRL:0)|(alt?VTERM_MOD_ALT:0)|(shift?VTERM_MOD_SHIFT:0);
        VTermKey vk=VTERM_KEY_NONE;
        switch(sym){case XKB_KEY_Return:vk=VTERM_KEY_ENTER;break;case XKB_KEY_BackSpace:vk=VTERM_KEY_BACKSPACE;break;
        case XKB_KEY_Tab:vk=VTERM_KEY_TAB;break;case XKB_KEY_Escape:vk=VTERM_KEY_ESCAPE;break;
        case XKB_KEY_Up:vk=VTERM_KEY_UP;break;case XKB_KEY_Down:vk=VTERM_KEY_DOWN;break;
        case XKB_KEY_Left:vk=VTERM_KEY_LEFT;break;case XKB_KEY_Right:vk=VTERM_KEY_RIGHT;break;
        case XKB_KEY_Home:vk=VTERM_KEY_HOME;break;case XKB_KEY_End:vk=VTERM_KEY_END;break;
        case XKB_KEY_Delete:vk=VTERM_KEY_DEL;break;case XKB_KEY_Page_Up:vk=VTERM_KEY_PAGEUP;break;case XKB_KEY_Page_Down:vk=VTERM_KEY_PAGEDOWN;break;}
        if(vk!=VTERM_KEY_NONE)vterm_keyboard_key(terminal,vk,mod);
        else {uint32_t point=xkb_keysym_to_utf32(sym);if(point)vterm_keyboard_unichar(terminal,point,mod);}
    }
    dirty=true;
}
static void modifiers(void *d,struct wl_keyboard *k,uint32_t serial,uint32_t depressed,uint32_t latched,uint32_t locked_mod,uint32_t group){(void)d;(void)k;(void)serial;if(keys)xkb_state_update_mask(keys,depressed,latched,locked_mod,0,0,group);}
static void repeat(void *d,struct wl_keyboard *k,int32_t rate,int32_t delay){(void)d;(void)k;repeat_rate=rate>60?60:rate;repeat_delay=delay<100?100:delay;if(rate<=0)repeating=false;}
static const struct wl_keyboard_listener keyboard_listener={map_keys,enter,leave,key,modifiers,repeat};
static void pointer_motion(void *d,struct wl_pointer *p,uint32_t time,wl_fixed_t x,wl_fixed_t y){
    (void)d;(void)p;(void)time;pointer_x=wl_fixed_to_double(x);pointer_y=wl_fixed_to_double(y);
    bool hover=pointer_output&&pointer_x>=pointer_output->width-164&&pointer_x<=pointer_output->width-20&&pointer_y>=pointer_output->height-44&&pointer_y<=pointer_output->height-12;
    if(hover!=end_hover){end_hover=hover;dirty=true;}
    hover=pointer_output&&pointer_output->can_approve&&pointer_x>=pointer_output->approve_x&&pointer_x<=pointer_output->approve_x+280&&pointer_y>=pointer_output->approve_y&&pointer_y<=pointer_output->approve_y+48;
    if(hover!=approve_hover){approve_hover=hover;dirty=true;}
    hover=pointer_output&&pointer_output->can_approve&&pointer_x>=pointer_output->cancel_x&&pointer_x<=pointer_output->cancel_x+150&&pointer_y>=pointer_output->cancel_y&&pointer_y<=pointer_output->cancel_y+48;
    if(hover!=cancel_hover){cancel_hover=hover;dirty=true;}
}
static void pointer_enter(void *d,struct wl_pointer *p,uint32_t serial,struct wl_surface *s,wl_fixed_t x,wl_fixed_t y){
    (void)serial;pointer_output=NULL;for(int i=0;i<MAX_OUTPUTS;i++)if(outputs[i].surface==s)pointer_output=&outputs[i];pointer_motion(d,p,0,x,y);
}
static void pointer_leave(void *d,struct wl_pointer *p,uint32_t serial,struct wl_surface *s){(void)d;(void)p;(void)serial;(void)s;pointer_output=NULL;end_hover=false;approve_hover=false;cancel_hover=false;dirty=true;}
static void pointer_button(void *d,struct wl_pointer *p,uint32_t serial,uint32_t time,uint32_t button,uint32_t state){
    (void)d;(void)p;(void)serial;(void)time;
    if(button==0x110&&state==WL_POINTER_BUTTON_STATE_RELEASED&&locked&&!reviewed&&cancel_hover&&pointer_output&&pointer_output->can_approve)exiting=true;
    if(button==0x110&&state==WL_POINTER_BUTTON_STATE_RELEASED&&locked&&!reviewed&&approve_hover&&pointer_output&&pointer_output->can_approve){
        if(milliseconds()-request_started>120000)notice="Request expired. Press Escape and request Administration again.";
        else start_console();
        dirty=true;
    }
    if(button==0x110&&state==WL_POINTER_BUTTON_STATE_RELEASED&&end_hover){
        if(!reviewed||finished||!strcmp(notice,"Press Ctrl+Shift+Q again to end Administration and interrupt its commands."))exiting=true;
        else notice="Press Ctrl+Shift+Q again to end Administration and interrupt its commands.";
        dirty=true;
    }
}
static void pointer_axis(void *d,struct wl_pointer *p,uint32_t time,uint32_t axis,wl_fixed_t value){(void)d;(void)p;(void)time;(void)axis;(void)value;}
static void pointer_frame(void *d,struct wl_pointer *p){(void)d;(void)p;}
static void pointer_source(void *d,struct wl_pointer *p,uint32_t source){(void)d;(void)p;(void)source;}
static void pointer_stop(void *d,struct wl_pointer *p,uint32_t time,uint32_t axis){(void)d;(void)p;(void)time;(void)axis;}
static void pointer_discrete(void *d,struct wl_pointer *p,uint32_t axis,int32_t discrete){(void)d;(void)p;(void)axis;(void)discrete;}
static const struct wl_pointer_listener pointer_listener={.enter=pointer_enter,.leave=pointer_leave,.motion=pointer_motion,.button=pointer_button,.axis=pointer_axis,.frame=pointer_frame,.axis_source=pointer_source,.axis_stop=pointer_stop,.axis_discrete=pointer_discrete};
static void capabilities(void *d,struct wl_seat *s,uint32_t caps){
    (void)d;
    if((caps&WL_SEAT_CAPABILITY_KEYBOARD)&&!keyboard){keyboard=wl_seat_get_keyboard(s);wl_keyboard_add_listener(keyboard,&keyboard_listener,NULL);}
    if((caps&WL_SEAT_CAPABILITY_POINTER)&&!pointer){pointer=wl_seat_get_pointer(s);wl_pointer_add_listener(pointer,&pointer_listener,NULL);}
}
static void seat_name(void *d,struct wl_seat *s,const char *name){(void)d;(void)s;(void)name;}
static const struct wl_seat_listener seat_listener={capabilities,seat_name};
static void configure(void *data,struct ext_session_lock_surface_v1 *s,uint32_t serial,uint32_t width,uint32_t height){
    struct output *out=data;out->width=width;out->height=height;ext_session_lock_surface_v1_ack_configure(s,serial);
    if(!reviewed){columns=(width-2*TERMINAL_MARGIN)/CELL_WIDTH;rows=(height-TERMINAL_TOP-80)/CELL_HEIGHT;if(columns<20)columns=20;if(rows<5)rows=5;}
    paint(out);dirty=true;
}
static const struct ext_session_lock_surface_v1_listener surface_listener={configure};
static void make_surface(struct output *out){out->width=out->height=0;out->surface=wl_compositor_create_surface(compositor);out->lock_surface=ext_session_lock_v1_get_lock_surface(lock,out->surface,out->output);ext_session_lock_surface_v1_add_listener(out->lock_surface,&surface_listener,out);}
static void global(void *d,struct wl_registry *reg,uint32_t name,const char *interface,uint32_t version){
    (void)d;
    if(!strcmp(interface,wl_compositor_interface.name))compositor=wl_registry_bind(reg,name,&wl_compositor_interface,4);
    else if(!strcmp(interface,wl_shm_interface.name))shm=wl_registry_bind(reg,name,&wl_shm_interface,1);
    else if(!strcmp(interface,wl_seat_interface.name)&&!seat){seat=wl_registry_bind(reg,name,&wl_seat_interface,version<7?version:7);wl_seat_add_listener(seat,&seat_listener,NULL);}
    else if(!strcmp(interface,ext_session_lock_manager_v1_interface.name))manager=wl_registry_bind(reg,name,&ext_session_lock_manager_v1_interface,1);
    else if(!strcmp(interface,wl_output_interface.name))for(int i=0;i<MAX_OUTPUTS;i++)if(!outputs[i].output){outputs[i].name=name;outputs[i].output=wl_registry_bind(reg,name,&wl_output_interface,1);if(lock)make_surface(&outputs[i]);break;}
}
static void remove_global(void *d,struct wl_registry *reg,uint32_t name){(void)d;(void)reg;for(int i=0;i<MAX_OUTPUTS;i++)if(outputs[i].name==name){if(outputs[i].lock_surface)ext_session_lock_surface_v1_destroy(outputs[i].lock_surface);if(outputs[i].surface)wl_surface_destroy(outputs[i].surface);wl_output_destroy(outputs[i].output);memset(&outputs[i],0,sizeof(outputs[i]));}}
static const struct wl_registry_listener registry_listener={global,remove_global};
static void secure(void *d,struct ext_session_lock_v1 *l){
    (void)d;(void)l;locked=true;dirty=true;
    if(write(4,"READY\n",6)!=6)exiting=true;
}
static void rejected(void *d,struct ext_session_lock_v1 *l){(void)d;(void)l;exiting=true;}
static const struct ext_session_lock_v1_listener lock_listener={secure,rejected};
static void release_surface(void) {
    if(locked)ext_session_lock_v1_unlock_and_destroy(lock);
    else if(lock)ext_session_lock_v1_destroy(lock);
    lock=NULL;locked=false;
    for(int i=0;i<MAX_OUTPUTS;i++)if(outputs[i].surface){
        ext_session_lock_surface_v1_destroy(outputs[i].lock_surface);
        wl_surface_destroy(outputs[i].surface);outputs[i].lock_surface=NULL;outputs[i].surface=NULL;
    }
    wl_display_flush(display);wl_display_roundtrip(display);
}
static void acquire_surface(void) {
    lock=ext_session_lock_manager_v1_lock(manager);ext_session_lock_v1_add_listener(lock,&lock_listener,NULL);
    for(int i=0;i<MAX_OUTPUTS;i++)if(outputs[i].output)make_surface(&outputs[i]);
}
static void invalidate_cache(void) {
    pid_t pid=fork();
    if(!pid){close_range(3,UINT_MAX,0);execl("/usr/bin/sudo","sudo","-K",(char *)NULL);_exit(126);}
    if(pid>0){int status;while(waitpid(pid,&status,0)<0 && errno==EINTR){}}
}
int main(int argc,char **argv){
    char *context=NULL;
    if(getuid()<1000||getuid()!=geteuid()||getcon(&context)||strcmp(context,CONTEXT))fail("prepared administrator subject required");
    freecon(context);signal(SIGTERM,stop);signal(SIGINT,stop);signal(SIGPIPE,SIG_IGN);
    signal(SIGUSR1,pause_signal);signal(SIGUSR2,resume_signal);
    signal(SIGURG,cache_signal);
    if(argc==2&&!strcmp(argv[1],"--console")){console();return 126;}
    if(argc!=1)fail("invalid entry");
    close_range(5, UINT_MAX, 0);
    read_request();request_started=milliseconds();xkb=xkb_context_new(XKB_CONTEXT_NO_FLAGS);if(!xkb)fail("keymap context");
    display=wl_display_connect(NULL);if(!display){perror("Protected display connection");fail("protected display unavailable");}
    struct wl_registry *registry=wl_display_get_registry(display);wl_registry_add_listener(registry,&registry_listener,NULL);
    if(wl_display_roundtrip(display)<0||!compositor||!shm||!manager||!seat)fail("protected protocols unavailable");
    acquire_surface();
    while(!exiting&&!interrupted){
        static time_t heartbeat;
        time_t now=time(NULL);
        if(heartbeat!=now){heartbeat=now;if(write(4,"LIVE\n",5)!=5)exiting=true;}
        if(cache_requested){cache_requested=0;if(child>0)kill(child,SIGURG);invalidate_cache();}
        if(pause_requested && !paused){
            repeating=false;
            pause_requested=0;if(child>0)kill(child,SIGURG);invalidate_cache();release_surface();paused=true;
            if(write(4,"PAUSED\n",7)!=7)exiting=true;
        }
        if(resume_requested && paused){resume_requested=0;paused=false;acquire_surface();dirty=true;}
        if(repeating&&!paused&&milliseconds()>=repeat_due){
            synthesizing_repeat=true;key(NULL,keyboard,0,0,repeat_code,WL_KEYBOARD_KEY_STATE_PRESSED);synthesizing_repeat=false;
            repeat_due=milliseconds()+1000/repeat_rate;
        }
        if(dirty){for(int i=0;i<MAX_OUTPUTS;i++)if(outputs[i].surface)paint(&outputs[i]);dirty=false;}
        while(wl_display_prepare_read(display)!=0)if(wl_display_dispatch_pending(display)<0)goto done;
        wl_display_flush(display);
        struct pollfd fds[2]={{wl_display_get_fd(display),POLLIN,0},{pty_fd,POLLIN,0}};
        int count=poll(fds,pty_fd>=0?2:1,repeating?16:100);
        if(count<0){wl_display_cancel_read(display);if(errno==EINTR)continue;break;}
        if(fds[0].revents&POLLIN){if(wl_display_read_events(display)<0)break;wl_display_dispatch_pending(display);}else wl_display_cancel_read(display);
        if(fds[0].revents&(POLLERR|POLLHUP))break;
        if(pty_fd>=0&&fds[1].revents&(POLLIN|POLLHUP)){
            char bytes[8192];ssize_t size=read(pty_fd,bytes,sizeof(bytes));
            if(size>0){vterm_input_write(terminal,bytes,size);vterm_screen_flush_damage(screen);dirty=true;}
            else if(size==0||(size<0&&errno==EIO)){finished=true;close(pty_fd);pty_fd=-1;notice="Administration finished. Press Enter or Escape to return to your desktop.";dirty=true;}
        }
    }
done:
    /* The root owner tears down the private workload and cache after return.
     * A compositor disconnect never starts or exports another terminal. */
    invalidate_cache();
    release_surface();
    wl_display_flush(display);wl_display_roundtrip(display);wl_display_disconnect(display);
    if(pty_fd>=0)close(pty_fd);
    if(terminal)vterm_free(terminal);
    if(keys)xkb_state_unref(keys);
    if(keymap)xkb_keymap_unref(keymap);
    xkb_context_unref(xkb);
    if(brand_logo)g_object_unref(brand_logo);
    if(grain)cairo_pattern_destroy(grain);
    return locked?0:1;
}
