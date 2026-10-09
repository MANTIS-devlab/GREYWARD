/* Focused native renderer regression: no Wayland seat or admission involved.
 * Compile with the generated lock protocol and the terminal's normal libraries.
 * SPDX-License-Identifier: GPL-3.0-only */
#define main administration_entry
#include "../security-center/packaging/application-security/administration/terminal.c"
#undef main
#include <assert.h>

static uint32_t pixel(cairo_surface_t *surface,int col) {
    cairo_surface_flush(surface);
    unsigned char *data=cairo_image_surface_get_data(surface);
    /* Below the glyph baseline, within the cell's background. */
    return *(uint32_t *)(data+(TERMINAL_TOP+CELL_HEIGHT-1)*cairo_image_surface_get_stride(surface)+(TERMINAL_MARGIN+col*CELL_WIDTH+1)*4)&0xffffff;
}
int main(void) {
    VTerm *vt=vterm_new(2,20);defaults(vt);vterm_set_utf8(vt,1);
    VTermScreen *cells=vterm_obtain_screen(vt);vterm_screen_reset(cells,1);
    cairo_surface_t *surface=cairo_image_surface_create(CAIRO_FORMAT_RGB24,300,200);
    cairo_t *cr=cairo_create(surface);
    cairo_set_source_rgb(cr,SURFACE_RED/255.0,SURFACE_GREEN/255.0,SURFACE_BLUE/255.0);cairo_paint(cr);
    const char *input="A\033[40mB \033[0mC\033[7mD\033[0m\033[44m\033[K";
    vterm_input_write(vt,input,strlen(input));vterm_screen_flush_damage(cells);
    for(int col=0;col<20;col++)draw_cell(cr,cells,0,col);
    assert(pixel(surface,0)==0x0a0c0f); /* Default text preserves canvas. */
    assert(pixel(surface,1)==0);       /* Explicit ANSI black retained. */
    assert(pixel(surface,2)==0);       /* Space background retained. */
    assert(pixel(surface,3)==0x0a0c0f); /* SGR reset returns to obsidian. */
    assert(pixel(surface,4)==0xdce2e5); /* Reverse video retained. */
    assert(pixel(surface,5)==pixel(surface,19)&&pixel(surface,5)!=0x0a0c0f);
    assert(((pixel(surface,5)>>16)&255)>100); /* Readable themed ANSI blue. */
    vterm_input_write(vt,"\033[0m\033[2J",8);vterm_screen_flush_damage(cells);
    cairo_set_source_rgb(cr,SURFACE_RED/255.0,SURFACE_GREEN/255.0,SURFACE_BLUE/255.0);cairo_paint(cr);
    for(int col=0;col<20;col++)draw_cell(cr,cells,0,col);
    assert(pixel(surface,0)==0x0a0c0f&&pixel(surface,19)==0x0a0c0f);
    /* Default cells also preserve a textured material, not flat rectangles. */
    cairo_set_source_rgb(cr,.1,.2,.3);cairo_paint(cr);
    draw_cell(cr,cells,0,0);assert(pixel(surface,0)==0x19334c);
    const char *true_color="\033[48;2;18;52;86mX";
    vterm_input_write(vt,true_color,strlen(true_color));vterm_screen_flush_damage(cells);
    draw_cell(cr,cells,0,5);assert(pixel(surface,5)==0x123456);
    cairo_set_source_rgb(cr,0,0,0);cairo_paint(cr);
    logo(cr,20,10,58);assert(brand_logo&&cairo_status(cr)==CAIRO_STATUS_SUCCESS);
    cairo_surface_flush(surface);
    int visible=0;
    for(int y=10;y<68;y++)for(int x=20;x<78;x++){
        uint32_t value=*(uint32_t *)(cairo_image_surface_get_data(surface)+y*cairo_image_surface_get_stride(surface)+x*4)&0xffffff;
        if(value>0x303030)visible++;
    }
    assert(visible>400); /* Canonical artwork really paints at the requested size. */
    g_object_unref(brand_logo);brand_logo=NULL;
    cairo_destroy(cr);cairo_surface_destroy(surface);vterm_free(vt);
    puts("Administration renderer: default, ANSI black, blank/erased cells, reset and reverse video PASS");
    return 0;
}
