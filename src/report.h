#ifndef VT_REPORT_H
#define VT_REPORT_H
#include "protocol.h"
int vt_report_upload(const VTConfig *c,const char *path,const char *logical_name);
int vt_report_collect(const VTConfig *c);
void vt_report_network_shutdown(void);
int vt_report_network_init(void);
int vt_http_download(const char *url,const char *path);
const char *vt_report_last_error(void);
void vt_screen_message(const char *message);
#endif
