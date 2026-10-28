#ifndef VT_PROTOCOL_H
#define VT_PROTOCOL_H
#include <stddef.h>
#define VT_DIR "ux0:data/vitatunnel"
#define VT_CONFIG VT_DIR "/config.ini"
#define VT_STATE VT_DIR "/state.txt"
#define VT_VPK VT_DIR "/pending.vpk"
#define VT_MANIFEST VT_DIR "/manifest.txt"
#define VT_CA "app0:cacert.pem"
#define VT_MAXLOG (256*1024)
typedef struct {
  char owner[80], repo[80], branch[80], title_id[16];
  char token[192], log_dir[256], log_file[256];
  int upload_logs, upload_core, auto_launch;
} VTConfig;
typedef struct {
  char version[64], title_id[16], vpk_url[600], sha256[65];
} VTManifest;
int vt_read_config(const char *path, VTConfig *cfg);
int vt_read_manifest(const char *path, VTManifest *mf);
int vt_valid_slug(const char *s);
int vt_valid_titleid(const char *s);
int vt_valid_sha256(const char *s);
int vt_valid_vpk_url(const char *url);
int vt_valid_logpath(const char *path);
int vt_sha256_file(const char *path, char out[65]);
int vt_mkdir(void);
int vt_read_text(const char *path, char *out, size_t max);
int vt_write_text(const char *path, const char *s);
#endif
