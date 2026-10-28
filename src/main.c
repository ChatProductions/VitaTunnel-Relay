#include "protocol.h"
#include "report.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <zip.h>
#include <strings.h>
#include "vpk_installer.h"
#include <vita2d.h>
#include <psp2/ctrl.h>
#include <psp2/appmgr.h>
#include <psp2/io/stat.h>
#include <psp2/apputil.h>
#include <psp2/power.h>
#include <psp2/kernel/processmgr.h>

// No resident module: all network and file access occurs only while VitaTunnel is foreground.
static vita2d_pgf *font;
static char state[320]="Starting...";
static int stage=0;
void vt_screen_message(const char *msg){
  snprintf(state,sizeof(state),"%s",msg);
  if(!font)return;
  vita2d_start_drawing();
  vita2d_clear_screen();
  vita2d_draw_rectangle(0,0,960,544,0xFF161B27);
  vita2d_draw_rectangle(0,0,960,75,0xFF455C9B);
  vita2d_pgf_draw_text(font,38,49,0xFFFFFFFF,1.45f,"VitaTunnel   0.1.2");
  vita2d_pgf_draw_text(font,38,130,0xFFFFFFFF,1.05f,"Secure GitHub build / diagnostic relay");
  vita2d_pgf_draw_text(font,38,195,0xFFE0F5FF,1.1f,state);
  vita2d_pgf_draw_text(font,38,263,0xFF9FC0CE,0.9f,"Open this app to sync. Nothing runs in the background.");
  vita2d_pgf_draw_text(font,38,306,0xFF9FC0CE,0.9f,"Diagnostics: configured directories only, no PC access.");
  vita2d_pgf_draw_text(font,38,425,0xFFEBDBB2,0.85f,"SQUARE: retry    CIRCLE: exit    SELECT: details");
  vita2d_pgf_draw_text(font,38,467,0xFFBECADC,0.83f,"Configuration: ux0:data/vitatunnel/config.ini");
  vita2d_end_drawing();vita2d_swap_buffers();
  sceKernelPowerTick(0);
}
static void err_state(const char *title,int error){
  char buf[200];snprintf(buf,sizeof(buf),"%s  (error %d / 0x%08X)",title,error,(unsigned)error);
  vt_screen_message(buf);
}
static void first_config(void){
  const char *tmpl=
    "# VitaTunnel config - configure once in VitaShell. NEVER share your token.\n"
    "owner=YOUR_GITHUB_NAME\n"
    "repo=YOUR_RELAY_REPOSITORY\n"
    "branch=main\n"
    "title_id=OPENCE001\n"
    "# Optional GitHub fine-grained token, Contents: Read/Write on THIS repo only.\n"
    "# Leave blank to disable uploading diagnostics.\n"
    "token=\n"
    "log_dir=ux0:data/open-ce/logs\n"
    "log_file=\n"
    "upload_logs=1\n"
    "upload_core=0\n"
    "auto_launch=1\n";
  FILE *f=fopen(VT_CONFIG,"rb");if(f){fclose(f);return;}
  vt_write_text(VT_CONFIG,tmpl);
}
static int version_is_same(const VTManifest *m){
  char old[128];if(vt_read_text(VT_STATE,old,sizeof(old))<0)return 0;
  size_t n=strcspn(old,"\r\n");old[n]=0;
  return strcmp(old,m->version)==0;
}
static int validate_sfo_title(const unsigned char *blob,size_t n,const char *expected){
  if(n<20)return -1;
  unsigned int magic,keys,data,count;
  memcpy(&magic,blob,4);memcpy(&keys,blob+8,4);memcpy(&data,blob+12,4);memcpy(&count,blob+16,4);
  if(magic!=0x46535000||count>200||20U+count*16U>n||keys>=n||data>=n)return -2;
  for(unsigned i=0;i<count;i++){
    const unsigned char *e=blob+20+i*16;unsigned short ko;unsigned doff,plen;
    memcpy(&ko,e,2);memcpy(&plen,e+4,4);memcpy(&doff,e+12,4);
    if(keys+(size_t)ko>=n||data+(size_t)doff>=n)continue;
    const char *key=(const char*)blob+keys+ko;
    size_t kmax=n-(keys+ko);
    if(memchr(key,0,kmax)==NULL)continue;
    if(strcmp(key,"TITLE_ID"))continue;
    const char *value=(const char*)blob+data+doff;
    size_t avail=n-(data+doff);
    if(plen>avail||plen<9)return -3;
    char id[16]={0};memcpy(id,value,9);
    return !strcmp(id,expected)?0:-4;
  }
  return -5;
}
static int validate_package_title(const char *vpk,const char *expected){
  int zerr=0;zip_t *z=zip_open(vpk,ZIP_RDONLY,&zerr);
  if(!z)return -30;
  // ZIP entry must be at root; reject wrapped/ambiguous packages.
  zip_stat_t info;
  if(zip_stat(z,"sce_sys/param.sfo",0,&info)<0 || info.size>131072 || info.size<20){zip_close(z);return -31;}
  zip_file_t *f=zip_fopen(z,"sce_sys/param.sfo",0);if(!f){zip_close(z);return -32;}
  unsigned char *b=malloc((size_t)info.size);if(!b){zip_fclose(f);zip_close(z);return -33;}
  zip_int64_t n=zip_fread(f,b,info.size);
  zip_fclose(f);zip_close(z);
  int r=n==(zip_int64_t)info.size?validate_sfo_title(b,(size_t)n,expected):-34;
  free(b);return r;
}
static void report_progress(int pct,const char *msg){(void)pct;vt_screen_message(msg?msg:"Installing...");}
static int sync_once(void){
  VTConfig cfg;VTManifest mf;char url[620],hash[65];int r;
  vt_mkdir();first_config();
  r=vt_read_config(VT_CONFIG,&cfg);
  if(r<0){vt_screen_message("Edit config.ini in VitaShell, then press SQUARE.");return r;}
  vt_screen_message("Checking previously generated diagnostics...");
  r=vt_report_network_init();if(r<0){err_state(r==-77?"CA bundle missing or unreadable":"Networking initialization failed",r);return r;}
  if(cfg.token[0]&&cfg.upload_logs){
    int sent=vt_report_collect(&cfg);
    if(sent<0)err_state("Diagnostic upload failed; continuing",sent);
  }
  snprintf(url,sizeof(url),"https://raw.githubusercontent.com/%s/%s/%s/tunnel/manifest.txt",cfg.owner,cfg.repo,cfg.branch);
  vt_screen_message("Checking GitHub build manifest...");
  r=vt_http_download(url,VT_MANIFEST);
  if(r<0){err_state("Manifest HTTPS download failed",r);goto finish;}
  r=vt_read_manifest(VT_MANIFEST,&mf);
  if(r<0){err_state("Invalid manifest",r);goto finish;}
  if(strcmp(cfg.title_id,mf.title_id)){r=-40;err_state("Manifest target ID mismatch",r);goto finish;}
  {
    char expected_prefix[360];
    snprintf(expected_prefix,sizeof(expected_prefix),"https://github.com/%s/%s/releases/download/",cfg.owner,cfg.repo);
    if(strncmp(mf.vpk_url,expected_prefix,strlen(expected_prefix))){r=-43;err_state("Manifest VPK must belong to relay repository",r);goto finish;}
  }
  char app_path[80];SceIoStat app_stat;
  snprintf(app_path,sizeof(app_path),"ux0:app/%s/eboot.bin",cfg.title_id);
  if(version_is_same(&mf) && sceIoGetstat(app_path,&app_stat)>=0){
    vt_screen_message("Already up to date. Launching installed game...");
  }else{
    vt_screen_message("Downloading new VPK (TLS verified)...");
    r=vt_http_download(mf.vpk_url,VT_VPK);
    if(r<0){err_state("VPK download failed",r);goto finish;}
    vt_screen_message("Checking SHA-256 hash...");
    r=vt_sha256_file(VT_VPK,hash);
    if(r<0||strcasecmp(hash,mf.sha256)){r=-41;err_state("SHA-256 mismatch: install blocked",r);goto finish;}
    vt_screen_message("Checking embedded VPK TITLE_ID...");
    r=validate_package_title(VT_VPK,cfg.title_id);
    if(r<0){err_state("VPK title validation failed",r);goto finish;}
    // Upstream installer stages and promotes the unpacked VPK. Never update VitaTunnel itself.
    vt_screen_message("Installing verified VPK...");
    r=vpk_install(VT_VPK,report_progress);
    if(r<0){err_state("VPK installation failed",r);goto finish;}
    remove(VT_VPK);
    // Commit version only AFTER successful installation.
    if(vt_write_text(VT_STATE,mf.version)<0){r=-42;err_state("Failed to record installed version",r);goto finish;}
    vt_screen_message("New build installed successfully.");
  }
finish:
  vt_report_network_shutdown();
  if(r==0&&cfg.auto_launch){
    sceKernelDelayThread(1200000);
    vt_screen_message("Launching game. Reopen VitaTunnel after testing.");
    sceKernelDelayThread(500000);
    int lr=sceAppMgrLaunchAppByName(0x60000,cfg.title_id,NULL);
    if(lr<0){err_state("Unable to launch game",lr);return lr;}
    // Exit so the user's next manual launch performs a fresh diagnostic sync.
    sceKernelExitProcess(0);
  }
  return r;
}
int main(void){
  SceAppUtilInitParam ip;SceAppUtilBootParam bp;
  memset(&ip,0,sizeof(ip));memset(&bp,0,sizeof(bp));sceAppUtilInit(&ip,&bp);
  sceCtrlSetSamplingMode(SCE_CTRL_MODE_ANALOG);
  vita2d_init();font=vita2d_load_default_pgf();
  vt_screen_message("Starting sync...");
  int last=sync_once();
  char prior[320];snprintf(prior,sizeof(prior),"%s",state);
  unsigned old=0;int detail=0;
  while(1){
    SceCtrlData b={0};sceCtrlPeekBufferPositive(0,&b,1);
    unsigned pressed=b.buttons&~old;old=b.buttons;
    if(pressed&SCE_CTRL_CIRCLE)break;
    if(pressed&SCE_CTRL_SQUARE){vt_screen_message("Retrying sync...");last=sync_once();snprintf(prior,sizeof(prior),"%s",state);}
    if(pressed&SCE_CTRL_SELECT){detail=!detail;vt_screen_message(detail?"Reports stay local unless token is configured.":prior);}
    sceKernelPowerTick(0);
    sceKernelDelayThread(60000);
  }
  (void)last;
  vita2d_free_pgf(font);vita2d_fini();sceKernelExitProcess(0);return 0;
}
