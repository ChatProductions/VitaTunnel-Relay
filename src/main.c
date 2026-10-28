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
  vita2d_pgf_draw_text(font,38,49,0xFFFFFFFF,1.45f,"VitaTunnel   0.3.4");
  vita2d_pgf_draw_text(font,38,130,0xFFFFFFFF,1.05f,"NFSMW 2005 AOT Test / secure GitHub relay");
  vita2d_pgf_draw_text(font,38,195,0xFFE0F5FF,1.1f,state);
  if(strstr(state,"failed") || strstr(state,"unreadable")){
    const char *details=vt_report_last_error();
    if(details[0])vita2d_pgf_draw_text(font,38,229,0xFFBAD7E9,0.72f,details);
  }
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
/* Read the public, token-free defaults included at the root of the VPK. */
static int bundled_config(char *out,size_t max){
  static const char *paths[]={"app0:/config.ini","app0:config.ini",
                              "ux0:app/VITATUNN1/config.ini"};
  for(size_t i=0;i<sizeof(paths)/sizeof(paths[0]);i++){
    if(vt_read_text(paths[i],out,max)>0)return 0;
  }
  return -1;
}
static int first_config(void){
  char tmpl[2048];
  if(bundled_config(tmpl,sizeof(tmpl))<0)return -1;
  FILE *f=fopen(VT_CONFIG,"rb");
  if(!f)return vt_write_text(VT_CONFIG,tmpl);
  fclose(f);
  VTConfig prev;
  /* Only migrate the untouched v0.1 template. Any token or edits stay intact. */
  if(vt_read_config(VT_CONFIG,&prev)==0 &&
     !strcmp(prev.owner,"YOUR_GITHUB_NAME") &&
     !strcmp(prev.repo,"YOUR_RELAY_REPOSITORY") &&
     !strcmp(prev.branch,"main") &&
     !strcmp(prev.title_id,"OPENCE001") &&
     !strcmp(prev.log_dir,"ux0:data/open-ce/logs") &&
     !prev.log_file[0] && !prev.token[0] &&
     prev.upload_logs && !prev.upload_core && prev.auto_launch){
    return vt_write_text(VT_CONFIG,tmpl);
  }
  return 0;
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
  vt_mkdir();
  if(first_config()<0){vt_screen_message("Bundled config.ini missing or could not be saved.");return -1;}
  r=vt_read_config(VT_CONFIG,&cfg);
  if(r<0){vt_screen_message("Check ux0:data/vitatunnel/config.ini in VitaShell.");return r;}
  if(!strcmp(cfg.title_id,"OPENCE001")){
    vt_screen_message("Old OpenCE placeholder: set title_id=NFMRA0001 in config.ini.");
    return -44;
  }
  vt_screen_message("Checking previously generated diagnostics...");
  r=vt_report_network_init();if(r<0){err_state(r==-77?"CA bundle missing or unreadable":"Networking initialization failed",r);return r;}
  if(cfg.token[0]&&cfg.upload_logs){
    int sent=vt_report_collect(&cfg);
    if(sent<0)err_state("Diagnostic upload failed; continuing",sent);
  }
  snprintf(url,sizeof(url),"https://raw.githubusercontent.com/%s/%s/%s/tunnel/manifest.txt",cfg.owner,cfg.repo,cfg.branch);
  vt_screen_message("Checking GitHub build manifest...");
  r=vt_http_download(url,VT_MANIFEST);
  if(r<0){
    if(r==-22)vt_screen_message("No NFSMW AOT test manifest yet (GitHub HTTP error).");
    else err_state("Manifest HTTPS download failed",r);
    goto finish;
  }
  r=vt_read_manifest(VT_MANIFEST,&mf);
  if(r<0){err_state("Invalid manifest",r);goto finish;}
  if(strcmp(cfg.title_id,mf.title_id)){r=-40;err_state("Manifest target ID mismatch",r);goto finish;}
  {
    char release_prefix[360],raw_prefix[420];
    snprintf(release_prefix,sizeof(release_prefix),
             "https://github.com/%s/%s/releases/download/",cfg.owner,cfg.repo);
    snprintf(raw_prefix,sizeof(raw_prefix),
             "https://raw.githubusercontent.com/%s/%s/%s/tunnel/packages/",
             cfg.owner,cfg.repo,cfg.branch);
    // A raw package must come from this repo's pinned branch and package
    // subdirectory. No arbitrary URLs, hosts, paths or tokenized redirects.
    if(strncmp(mf.vpk_url,release_prefix,strlen(release_prefix)) &&
       strncmp(mf.vpk_url,raw_prefix,strlen(raw_prefix))){
      r=-43;err_state("Manifest VPK must belong to relay repository",r);goto finish;
    }
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
