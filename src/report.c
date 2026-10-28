#include "report.h"
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <psp2/net/net.h>
#include <psp2/net/netctl.h>
#include <psp2/sysmodule.h>
#include <psp2/io/dirent.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/power.h>

static void *netmem;
static int netready;
static unsigned char *ca_bundle;
static size_t ca_bundle_len;

/* The Vita's fopen() understands app0: paths, but OpenSSL's CA-file
 * loader may not. Read the bundled PEM using the Vita filesystem API,
 * then give curl its own in-memory copy for certificate verification. */
static int load_ca_bundle(void){
  static const char *paths[]={
    "app0:/cacert.pem", "app0:cacert.pem",
    "ux0:app/VITATUNN1/cacert.pem"
  };
  for(size_t i=0;i<sizeof(paths)/sizeof(paths[0]);i++){
    FILE *f=fopen(paths[i],"rb");
    if(!f)continue;
    if(fseek(f,0,SEEK_END)!=0){fclose(f);continue;}
    long size=ftell(f);
    if(size<64 || size>1024*1024 || fseek(f,0,SEEK_SET)!=0){fclose(f);continue;}
    unsigned char *data=malloc((size_t)size+1);
    if(!data){fclose(f);return -12;}
    size_t n=fread(data,1,(size_t)size,f);
    fclose(f);
    data[n]=0;
    if(n==(size_t)size && strstr((const char*)data,"-----BEGIN CERTIFICATE-----")){
      ca_bundle=data;ca_bundle_len=n;return 0;
    }
    free(data);
  }
  return -77; /* Missing or unreadable CA bundle; never disable verification. */
}
int vt_report_network_init(void){
  sceSysmoduleLoadModule(SCE_SYSMODULE_NET);
  sceSysmoduleLoadModule(SCE_SYSMODULE_HTTPS);
  netmem=malloc(1024*1024);if(!netmem)return -1;
  SceNetInitParam p={0};p.memory=netmem;p.size=1024*1024;
  int r=sceNetInit(&p);
  if(r<0){free(netmem);netmem=NULL;return r;}
  r=sceNetCtlInit();
  if(r<0){sceNetTerm();free(netmem);netmem=NULL;return r;}
  if(curl_global_init(CURL_GLOBAL_DEFAULT)!=CURLE_OK){
    sceNetCtlTerm();sceNetTerm();free(netmem);netmem=NULL;return -5;
  }
  r=load_ca_bundle();
  if(r<0){
    curl_global_cleanup();sceNetCtlTerm();sceNetTerm();
    free(netmem);netmem=NULL;return r;
  }
  netready=1;return 0;
}
void vt_report_network_shutdown(void){
  if(!netready)return;
  curl_global_cleanup();sceNetCtlTerm();sceNetTerm();
  free(ca_bundle);ca_bundle=NULL;ca_bundle_len=0;
  free(netmem);netmem=NULL;
  sceSysmoduleUnloadModule(SCE_SYSMODULE_NET);netready=0;
}
typedef struct { int last_percent; int initialized; } DlProgress;
static int download_progress(void *ctx,curl_off_t total,curl_off_t got,
                             curl_off_t utotal,curl_off_t unow){
  (void)utotal;(void)unow;
  DlProgress *progress=(DlProgress*)ctx;
  sceKernelPowerTick(0);
  if(total>0){
    int pct=(int)(got*100/total);
    if(!progress->initialized || pct-progress->last_percent>=5){
      progress->last_percent=pct;progress->initialized=1;
      char msg[140];snprintf(msg,sizeof(msg),"Downloading build... %d%%",pct);
      vt_screen_message(msg);
    }
  }
  return 0;
}
static CURLcode options(CURL *h,const char *url){
  curl_easy_setopt(h,CURLOPT_URL,url);
  curl_easy_setopt(h,CURLOPT_USERAGENT,"VitaTunnel/0.3");
  curl_easy_setopt(h,CURLOPT_SSL_VERIFYPEER,1L);
  curl_easy_setopt(h,CURLOPT_SSL_VERIFYHOST,2L);
  struct curl_blob trust={ca_bundle,ca_bundle_len,CURL_BLOB_COPY};
  CURLcode certificate_result=curl_easy_setopt(h,CURLOPT_CAINFO_BLOB,&trust);
  curl_easy_setopt(h,CURLOPT_PROTOCOLS,CURLPROTO_HTTPS);
  curl_easy_setopt(h,CURLOPT_REDIR_PROTOCOLS,CURLPROTO_HTTPS);
  curl_easy_setopt(h,CURLOPT_CONNECTTIMEOUT,20L);
  curl_easy_setopt(h,CURLOPT_TIMEOUT,1200L);
  curl_easy_setopt(h,CURLOPT_FAILONERROR,1L);
  curl_easy_setopt(h,CURLOPT_FOLLOWLOCATION,1L);
  curl_easy_setopt(h,CURLOPT_MAXREDIRS,5L);
  curl_easy_setopt(h,CURLOPT_LOW_SPEED_LIMIT,1L);
  curl_easy_setopt(h,CURLOPT_LOW_SPEED_TIME,45L);
  curl_easy_setopt(h,CURLOPT_MAXFILESIZE_LARGE,(curl_off_t)(512LL*1024*1024));
  return certificate_result;
}
static size_t to_file(char *ptr,size_t size,size_t nmemb,void *ctx){
  FILE *f=(FILE*)ctx;return fwrite(ptr,size,nmemb,f)*size;
}
int vt_http_download(const char *url,const char *path){
  FILE *f=fopen(path,"wb");if(!f)return -1;
  CURL *h=curl_easy_init();if(!h){fclose(f);return -2;}
  CURLcode setup=options(h,url);
  if(setup!=CURLE_OK){curl_easy_cleanup(h);fclose(f);remove(path);return -(int)setup;}
  DlProgress progress={0};
  curl_easy_setopt(h,CURLOPT_NOPROGRESS,0L);
  curl_easy_setopt(h,CURLOPT_XFERINFOFUNCTION,download_progress);
  curl_easy_setopt(h,CURLOPT_XFERINFODATA,&progress);
  curl_easy_setopt(h,CURLOPT_WRITEFUNCTION,to_file);
  curl_easy_setopt(h,CURLOPT_WRITEDATA,f);
  vt_screen_message("Downloading securely...");
  CURLcode r=curl_easy_perform(h);long code=0;curl_easy_getinfo(h,CURLINFO_RESPONSE_CODE,&code);
  curl_easy_cleanup(h);fclose(f);
  if(r!=CURLE_OK || code<200 || code>=300){remove(path);return r?-(int)r:-3;}
  return 0;
}
static size_t discard(char *p,size_t s,size_t n,void *data){(void)p;(void)data;return s*n;}
static int gh_write(const VTConfig *c,const char *filename,const char *raw,size_t bytes,int seq){
  if(!c->token[0])return -20;
  if(bytes>VT_MAXLOG)return -21;
  char url[640],path[180];
  snprintf(path,sizeof(path),"diagnostics/%s/%08d-%s",c->title_id,seq,filename);
  snprintf(url,sizeof(url),"https://api.github.com/repos/%s/%s/contents/%s",c->owner,c->repo,path);
  size_t encoded_len=4*((bytes+2)/3);char *encoded=malloc(encoded_len+1);
  if(!encoded)return -22;
  EVP_EncodeBlock((unsigned char*)encoded,(const unsigned char*)raw,(int)bytes);
  size_t bodycap=encoded_len+400;char *body=malloc(bodycap);
  if(!body){free(encoded);return -23;}
  snprintf(body,bodycap,"{\"message\":\"VitaTunnel diagnostic %08d\",\"branch\":\"%s\",\"content\":\"%s\"}",seq,c->branch,encoded);
  free(encoded);
  struct curl_slist *headers=NULL;char auth[250];
  snprintf(auth,sizeof(auth),"Authorization: Bearer %s",c->token);
  headers=curl_slist_append(headers,auth);
  headers=curl_slist_append(headers,"Accept: application/vnd.github+json");
  headers=curl_slist_append(headers,"Content-Type: application/json");
  headers=curl_slist_append(headers,"X-GitHub-Api-Version: 2022-11-28");
  CURL *h=curl_easy_init();if(!h){curl_slist_free_all(headers);free(body);return -24;}
  CURLcode setup=options(h,url);
  if(setup!=CURLE_OK){curl_easy_cleanup(h);curl_slist_free_all(headers);free(body);return -(int)setup;}
  curl_easy_setopt(h,CURLOPT_HTTPHEADER,headers);
  curl_easy_setopt(h,CURLOPT_CUSTOMREQUEST,"PUT");
  curl_easy_setopt(h,CURLOPT_POSTFIELDS,body);
  curl_easy_setopt(h,CURLOPT_POSTFIELDSIZE,(long)strlen(body));
  curl_easy_setopt(h,CURLOPT_WRITEFUNCTION,discard);
  vt_screen_message("Uploading selected diagnostics...");
  CURLcode r=curl_easy_perform(h);long code=0;curl_easy_getinfo(h,CURLINFO_RESPONSE_CODE,&code);
  curl_easy_cleanup(h);curl_slist_free_all(headers);free(body);
  return (r==CURLE_OK&&code==201)?0:(r?-(int)r:-(int)code);
}
static int next_seq(void){
  char data[32]={0};vt_read_text(VT_DIR "/sequence.txt",data,sizeof(data));
  int n=atoi(data);if(n<0 || n>=99999998)n=0;
  char out[32];snprintf(out,sizeof(out),"%d\n",n+1);
  if(vt_write_text(VT_DIR "/sequence.txt",out)<0)return -1;
  return n+1;
}
static void safe_filename(const char *src,char out[65]){
  size_t i=0;for(;*src&&i<58;src++){
    unsigned char ch=(unsigned char)*src;
    out[i++]=(isalnum(ch)||ch=='-'||ch=='_')?ch:'_';
  }out[i]=0;
  if(!out[0])strcpy(out,"log");
  strcat(out,".bin");
}
int vt_report_upload(const VTConfig *c,const char *path,const char *logical_name){
  if(!c->upload_logs || !c->token[0] || !vt_valid_logpath(path))return -1;
  FILE *f=fopen(path,"rb");if(!f)return -2;
  if(fseek(f,0,SEEK_END)!=0){fclose(f);return -3;}
  long size=ftell(f);if(size<=0){fclose(f);return -4;}
  // Deliberately cap each submitted report: no arbitrary whole-partition uploads.
  long count=size>VT_MAXLOG?VT_MAXLOG:size;
  if(fseek(f,size-count,SEEK_SET)!=0){fclose(f);return -5;}
  char *bytes=malloc(count);if(!bytes){fclose(f);return -6;}
  if(fread(bytes,1,count,f)!=(size_t)count){free(bytes);fclose(f);return -7;}
  fclose(f);
  // Deduplicate across launches by per-file tail and sanitized filename.
  char name[65];safe_filename(logical_name,name);
  char digest[65];char pathsha[65];
  // The state is per logical filename and content digest, not a listing of private files.
  unsigned char h[32];
  SHA256((const unsigned char*)bytes,count,h);
  for(int i=0;i<32;i++){sprintf(digest+i*2,"%02x",h[i]);}
  digest[64]=0;
  char key[200],prior[128]={0};snprintf(key,sizeof(key),VT_DIR "/last_%s.txt",name);
  vt_read_text(key,prior,sizeof(prior));
  if(!strncmp(prior,digest,64)){free(bytes);return 1;}
  (void)pathsha;
  int seq=next_seq();if(seq<0){free(bytes);return -8;}
  int r=gh_write(c,name,bytes,count,seq);free(bytes);
  if(r==0)vt_write_text(key,digest);
  return r;
}
static int recent_file(const char *folder,const char *suffix,char out[400]){
  SceUID fd=sceIoDopen(folder);if(fd<0)return -1;
  SceIoDirent e;int found=0;SceDateTime best={0};char chosen[256]={0};
  memset(&e,0,sizeof(e));
  while(sceIoDread(fd,&e)>0){
    const char *n=e.d_name;size_t z=strlen(n),k=strlen(suffix);
    if(SCE_S_ISDIR(e.d_stat.st_mode)||z<k||strcmp(n+z-k,suffix))continue;
    SceDateTime d=e.d_stat.st_mtime;
    int newer=!found||d.year>best.year||(d.year==best.year&&d.month>best.month)||
     (d.year==best.year&&d.month==best.month&&d.day>best.day)||
     (d.year==best.year&&d.month==best.month&&d.day==best.day&&d.hour>best.hour)||
     (d.year==best.year&&d.month==best.month&&d.day==best.day&&d.hour==best.hour&&d.minute>best.minute)||
     (d.year==best.year&&d.month==best.month&&d.day==best.day&&d.hour==best.hour&&d.minute==best.minute&&d.second>best.second);
    if(newer){best=d;snprintf(chosen,sizeof(chosen),"%s",n);found=1;}
    memset(&e,0,sizeof(e));
  }
  sceIoDclose(fd);
  if(!found)return -2;
  snprintf(out,400,"%s/%s",folder,chosen);return 0;
}
/* All AOT files are explicit, optional paths inside ux0:data/ps2vita.
 * A missing file is normal when the test fails before it can write logs. */
static int upload_if_present(const VTConfig *c,const char *path,const char *name){
  if(!path[0] || !vt_valid_logpath(path))return 1;
  SceIoStat stat;
  if(sceIoGetstat(path,&stat)<0 || SCE_S_ISDIR(stat.st_mode))return 1;
  return vt_report_upload(c,path,name);
}
int vt_report_collect(const VTConfig *c){
  if(!c->upload_logs || !c->token[0])return 0;
  int successes=0, first_error=0;char path[400];
  const char *files[]={c->log_file,c->log_fault,c->log_progress};
  const char *names[]={"startup","fault","progress"};
  for(size_t i=0;i<sizeof(files)/sizeof(files[0]);i++){
    int r=upload_if_present(c,files[i],names[i]);
    if(r==0)successes++;
    else if(r<0 && !first_error)first_error=r;
  }
  if(c->log_dir[0]&&vt_valid_logpath(c->log_dir)){
    if(recent_file(c->log_dir,".log",path)==0){
      int r=vt_report_upload(c,path,"newest_log");
      if(r==0)successes++;
      else if(r<0&&!first_error)first_error=r;
    }
  }
  if(c->upload_core && recent_file("ux0:data",".psp2dmp",path)==0){
    // Core dumps can belong to other apps; explicit opt-in only.
    int r=vt_report_upload(c,path,"recent_core_tail");
    if(r==0)successes++;
    else if(r<0&&!first_error)first_error=r;
  }
  return first_error?first_error:successes;
}
