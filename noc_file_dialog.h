/* noc_file_dialog library
 *
 * Copyright (c) 2015 Guillaume Chereau <guillaume@noctua-software.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

/* A portable library to create open and save dialogs on linux, osx and
 * windows.
 *
 * The library define a single function : noc_file_dialog_open.
 * With three different implementations.
 *
 * Usage:
 *
 * The library does not automatically select the implementation, you need to
 * define one of those macros before including this file:
 *
 *  NOC_FILE_DIALOG_GTK
 *  NOC_FILE_DIALOG_WIN32
 *  NOC_FILE_DIALOG_OSX
 */

enum {
    NOC_FILE_DIALOG_OPEN    = 1 << 0,   // Create an open file dialog.
    NOC_FILE_DIALOG_SAVE    = 1 << 1,   // Create a save file dialog.
    NOC_FILE_DIALOG_DIR     = 1 << 2,   // Open a directory.
    NOC_FILE_DIALOG_OVERWRITE_CONFIRMATION = 1 << 3,
};

// There is a single function defined.

/* flags            : union of the NOC_FILE_DIALOG_XXX masks.
 * filters          : a list of strings separated by '\0' of the form:
 *                      "name1 reg1 name2 reg2 ..."
 *                    The last value is followed by two '\0'.  For example,
 *                    to filter png and jpeg files, you can use:
 *                      "png\0*.png\0jpeg\0*.jpeg\0"
 *                    You can also separate patterns with ';':
 *                      "jpeg\0*.jpg;*.jpeg\0"
 *                    All patterns must be of the form "*.ext".
 *                    Set to NULL for no filter.
 * default_path     : the default file to use or NULL.
 * default_name     : the default file name to use or NULL.
 *
 * The function return a C string.  There is no need to free it, as it is
 * managed by the library.  The string is valid until the next call to
 * no_dialog_open.  If the user canceled, the return value is NULL.
 */
const char *noc_file_dialog_open(int flags,
                                 const char *filters,
                                 const char *default_path,
                                 const char *default_name);

#ifdef NOC_FILE_DIALOG_IMPLEMENTATION

#include <stdlib.h>
#include <string.h>

static char *g_noc_file_dialog_ret = NULL;
static int noc_file_dialog_free_ret_registered = 0;

static void noc_file_dialog_free_ret(void)
{
    free(g_noc_file_dialog_ret);
    g_noc_file_dialog_ret = NULL;
}

static void noc_file_dialog_set_ret(char *str)
{
    if (!noc_file_dialog_free_ret_registered) {
        atexit(&noc_file_dialog_free_ret);
    }

    free(g_noc_file_dialog_ret);

    g_noc_file_dialog_ret = str;
}

#ifdef NOC_FILE_DIALOG_GTK

#include <gtk/gtk.h>

const char *noc_file_dialog_open(int flags,
                                 const char *filters,
                                 const char *default_path,
                                 const char *default_name)
{
    GtkWidget *dialog;
    GtkFileFilter *filter;
    GtkFileChooser *chooser;
    GtkFileChooserAction action;
    gint res;
    char buf[128], *patterns;

    action = flags & NOC_FILE_DIALOG_SAVE ? GTK_FILE_CHOOSER_ACTION_SAVE :
                                            GTK_FILE_CHOOSER_ACTION_OPEN;
    if (flags & NOC_FILE_DIALOG_DIR)
        action = GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER;

    gtk_init_check(NULL, NULL);
    dialog = gtk_file_chooser_dialog_new(
            flags & NOC_FILE_DIALOG_SAVE ? "Save File" : "Open File",
            NULL,
            action,
            "_Cancel", GTK_RESPONSE_CANCEL,
            "_Open", GTK_RESPONSE_ACCEPT,
            NULL );
    chooser = GTK_FILE_CHOOSER(dialog);
    if (flags & NOC_FILE_DIALOG_OVERWRITE_CONFIRMATION)
        gtk_file_chooser_set_do_overwrite_confirmation(chooser, TRUE);

    if (default_path)
        gtk_file_chooser_set_filename(chooser, default_path);
    if (default_name)
        gtk_file_chooser_set_current_name(chooser, default_name);

    while (filters && *filters) {
        filter = gtk_file_filter_new();
        gtk_file_filter_set_name(filter, filters);
        filters += strlen(filters) + 1;

        // Split the filter pattern with ';'.
        strcpy(buf, filters);
        buf[strlen(buf)] = '\0';
        for (patterns = buf; *patterns; patterns++)
            if (*patterns == ';') *patterns = '\0';
        patterns = buf;
        while (*patterns) {
            gtk_file_filter_add_pattern(filter, patterns);
            patterns += strlen(patterns) + 1;
        }

        gtk_file_chooser_add_filter(chooser, filter);
        filters += strlen(filters) + 1;
    }

    res = gtk_dialog_run(GTK_DIALOG(dialog));

    free(g_noc_file_dialog_ret);
    g_noc_file_dialog_ret = NULL;

    if (res == GTK_RESPONSE_ACCEPT)
        g_noc_file_dialog_ret = gtk_file_chooser_get_filename(chooser);
    gtk_widget_destroy(dialog);
    while (gtk_events_pending()) gtk_main_iteration();
    return g_noc_file_dialog_ret;
}

#endif

#ifdef NOC_FILE_DIALOG_WIN32

#include <windows.h>
#include <commdlg.h>
#define CINTERFACE
#include <ShlObj.h>
#include <ShObjIdl.h>

// free result when done.
static WCHAR *GetWideString(const char *utf8_string) {
    int num_chars;
    WCHAR *buf = NULL;
    int good = 0;
    UINT codepage = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;

    num_chars = MultiByteToWideChar(codepage, flags, utf8_string, -1, NULL, 0);
    if (num_chars == 0) {
        goto done;
    }

    buf = (WCHAR *)malloc(num_chars * sizeof *buf);
    if (!buf) {
        goto done;
    }

    if (MultiByteToWideChar(codepage, flags, utf8_string, -1, buf, num_chars) == 0) {
        goto done;
    }

    good=1;

done:;

    if (!good) {
        free(buf);
        buf = NULL;
    }

    return buf;
}

// free result when done.
static char *GetUTF8String(const WCHAR *wide_string) {
    int num_bytes;
    char *buf = NULL;
    int good = 0;
    UINT codepage = CP_UTF8;
    DWORD flags = WC_ERR_INVALID_CHARS;

    num_bytes = WideCharToMultiByte(codepage, flags, wide_string, -1, NULL, 0, NULL, NULL);
    if (num_bytes == 0) {
        goto done;
    }

    buf = (char *)malloc(num_bytes);
    if (!buf) {
        goto done;
    }

    if (WideCharToMultiByte(codepage, flags, wide_string, -1, buf, num_bytes, NULL, NULL) == 0) {
        // unplausible... didn't it just succeed??
        goto done;
    }

    good=1;

done:;

    if(!good) {
        free(buf);
        buf = NULL;
    }

    return buf;
}

const char *noc_file_dialog_open(int flags,
    const char *filters,
    const char *default_path,
    const char *default_name)
{
    (void)default_path, (void)default_name;

    if (flags & NOC_FILE_DIALOG_DIR) {
        IFileDialog *f = NULL;
        const char *r = NULL;
        DWORD o;
        IShellItem *s = NULL;
        WCHAR *result_w = NULL;
        char *result_utf8 = NULL;
        IShellFolder *sf = NULL;

        // http://stackoverflow.com/questions/8269696/
        // https://msdn.microsoft.com/en-us/library/windows/desktop/bb775075%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
        // https://msdn.microsoft.com/en-us/library/windows/desktop/ff934858.aspx?f=255&MSPPError=-2147217396

        if (FAILED(CoCreateInstance(&CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER, &IID_IFileDialog, (void **)&f))) {
            goto done;
        }

        f->lpVtbl->GetOptions(f,&o);
        f->lpVtbl->SetOptions(f,o | FOS_PICKFOLDERS);

        if (default_path) {
            WCHAR *default_path_w = NULL;
            IShellItem *default_path_item = NULL;

            // If anything goes wrong here, rather than crapping out
            // entirely, just skip this bit.

            default_path_w = GetWideString(default_path);
            if (!default_path_w) {
                goto default_path_done;
            }

            if (FAILED(SHCreateItemFromParsingName(default_path_w, NULL, &IID_IShellItem, (void **)&default_path_item))) {
                goto default_path_done;
            }

            f->lpVtbl->SetFolder(f, default_path_item);

        default_path_done:;
            if (default_path_item) {
                default_path_item->lpVtbl->Release(default_path_item);
                default_path_item = NULL;
            }

            free(default_path_w);
            default_path_w = NULL;
        }

        if (FAILED(f->lpVtbl->Show(f, NULL))) {
            goto done;
        }

        if (FAILED(f->lpVtbl->GetResult(f, &s))) {
            goto done;
        }

        if (FAILED(s->lpVtbl->GetDisplayName(s, SIGDN_DESKTOPABSOLUTEPARSING, &result_w))) {
            goto done;
        }

        result_utf8 = GetUTF8String(result_w);
        if (!result_utf8) {
            goto done;
        }

        noc_file_dialog_set_ret(result_utf8);
        result_utf8 = NULL;

        r = g_noc_file_dialog_ret;

    done:;
        if(f) {
            f->lpVtbl->Release(f);
            f = NULL;
        }

        if (s) {
            s->lpVtbl->Release(s);
            s = NULL;
        }

        CoTaskMemFree(result_w);
        result_w = NULL;

        if (sf) {
            sf->lpVtbl->Release(sf);
            sf = NULL;
        }

        free(result_utf8);
        result_utf8 = NULL;

        return r;
    } else {
        OPENFILENAMEA ofn;       // common dialog box structure
        char szFile[260];       // buffer for file name
        int ret;

        ZeroMemory(&ofn, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.lpstrFile = szFile;
        ofn.lpstrFile[0] = '\0';
        ofn.nMaxFile = sizeof(szFile);
        ofn.lpstrFilter = filters;
        ofn.nFilterIndex = 1;
        ofn.lpstrFileTitle = NULL;
        ofn.nMaxFileTitle = 0;
        ofn.lpstrInitialDir = default_path;
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

        if (flags & NOC_FILE_DIALOG_OPEN)
            ret = GetOpenFileName(&ofn);
        else
            ret = GetSaveFileName(&ofn);

        noc_file_dialog_set_ret(ret ? strdup(szFile) : NULL);

        return g_noc_file_dialog_ret;
    }
}

#endif

#ifdef NOC_FILE_DIALOG_OSX

#include <AppKit/AppKit.h>

const char *noc_file_dialog_open(int flags,
                                 const char *filters,
                                 const char *default_path,
                                 const char *default_name)
{
    NSURL *url;
    const char *utf8_path;
    NSSavePanel *panel;
    NSOpenPanel *open_panel;
    NSMutableArray *types_array;
    NSURL *default_url;
    char buf[128], *patterns;

    (void)default_name;
    
    // XXX: I don't know about memory management with cococa, need to check
    // if I leak memory here.
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];

    if (flags & (NOC_FILE_DIALOG_OPEN | NOC_FILE_DIALOG_DIR)) {
        panel = open_panel = [NSOpenPanel openPanel];
    } else {
        panel = [NSSavePanel savePanel];
    }

    if (flags & NOC_FILE_DIALOG_DIR) {
        [open_panel setCanChooseDirectories:YES];
        [open_panel setCanChooseFiles:NO];
    }

    if (default_path) {
        default_url = [NSURL fileURLWithPath:
            [NSString stringWithUTF8String:default_path]];
        [panel setDirectoryURL:default_url];
        [panel setNameFieldStringValue:default_url.lastPathComponent];
    }

    if (filters) {
        types_array = [NSMutableArray array];
        while (*filters) {
            filters += strlen(filters) + 1; // skip the name
            // Split the filter pattern with ';'.
            strcpy(buf, filters);
            buf[strlen(buf) + 1] = '\0';
            for (patterns = buf; *patterns; patterns++)
                if (*patterns == ';') *patterns = '\0';
            patterns = buf;
            while (*patterns) {
                assert(strncmp(patterns, "*.", 2) == 0);
                patterns += 2; // Skip the "*."
                [types_array addObject:[NSString stringWithUTF8String: patterns]];
                patterns += strlen(patterns) + 1;
            }
            filters += strlen(filters) + 1;
        }
        [panel setAllowedFileTypes:types_array];
    }

    noc_file_dialog_set_ret(NULL);
    
    if ( [panel runModal] == NSModalResponseOK ) {
        url = [panel URL];
        utf8_path = [[url path] UTF8String];

        noc_file_dialog_set_ret(strdup(utf8_path));
    }

    [pool release];
    return g_noc_file_dialog_ret;
}
#endif


#endif
