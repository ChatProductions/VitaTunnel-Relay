#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/sha.h>
#ifndef VT_HOST
#include <psp2/io/stat.h>
#endif

int vt_mkdir(void){
#ifndef VT_HOST
  sceIoMkdir(VT_DIR,0777);
#else
  (void)0;
#endif
  return 0;
}
int vt_read_text(const char *path,char *out,size_t max){
  FILE *f=fopen(path,"rb"); size_t n;
  if(!f || !max){if(f)fclose(f);return -1;}
  n=fread(out,1,max-1,f);out[n]=0;
  if(!feof(f)){fclose(f);return -2;}
  fclose(f);return (int)n;
}
int vt_write_text(const char *path,const char *s){
  FILE *f=fopen(path,"wb");if(!f)return -1;
  size_t len=strlen(s);int rc=(fwrite(s,1,len,f)==len && fflush(f)==0)?0:-2;
  fclose(f);return rc;
}
int vt_valid_slug(const char *s){
  if(!s || !*s || strlen(s)>70)return 0;
  for(;*s;s++)if(!isalnum((unsigned char)*s)&&*s!='-'&&*s!='_'&&*s!='.')return 0;
  return 1;
}
int vt_valid_titleid(const char *s){
  if(!s||strlen(s)!=9||!strcmp(s,"VITATUNN1"))return 0;
  for(;*s;s++)if(!((*s>='A'&&*s<='Z')||(*s>='0'&&*s<='9')))return 0;
  return 1;
}
int vt_valid_sha256(const char *s){
  if(!s||strlen(s)!=64)return 0;
  for(;*s;s++)if(!isxdigit((unsigned char)*s))return 0;
  return 1;
}
int vt_valid_vpk_url(const char *url){
  if(!url || strlen(url)>550 || strncmp(url,"https://github.com/",19))return 0;
  if(!strstr(url,"/releases/download/")||!strstr(url,".vpk"))return 0;
  if(strchr(url,'\n')||strchr(url,'\r')||strchr(url,' ')||strchr(url,'@')||strchr(url,'#'))return 0;
  return 1;
}
int vt_valid_logpath(const char *path){
  if(!path||strncmp(path,"ux0:data/",9)||strlen(path)>245 || strstr(path,"..")||strchr(path,'\\'))return 0;
  if(!strncmp(path,VT_DIR,strlen(VT_DIR)))return 0;
  return 1;
}
static void put(char *dest,size_t cap,const char *val){
  if(strlen(val)<cap){memcpy(dest,val,strlen(val)+1);}
}
static int pair(char *line,char **key,char **val){
  char *eq=strchr(line,'=');if(!eq)return 0;
  *eq=0;*key=line;*val=eq+1;
  while(**val==' '||**val=='\t')(*val)++;
  while(**key==' '||**key=='\t')(*key)++;
  size_t n=strlen(*key);while(n&&isspace((unsigned char)(*key)[n-1]))(*key)[--n]=0;
  n=strlen(*val);while(n&&isspace((unsigned char)(*val)[n-1]))(*val)[--n]=0;
  return 1;
}
int vt_read_config(const char *path,VTConfig *c){
  FILE *f=fopen(path,"rb");char line[1024];if(!f)return -1;
  memset(c,0,sizeof(*c));c->auto_launch=1;c->upload_logs=1;
  while(fgets(line,sizeof(line),f)){
    char *k,*v;if(line[0]=='#'||line[0]==';'||!pair(line,&k,&v))continue;
    if(!strcmp(k,"owner"))put(c->owner,sizeof(c->owner),v);
    else if(!strcmp(k,"repo"))put(c->repo,sizeof(c->repo),v);
    else if(!strcmp(k,"branch"))put(c->branch,sizeof(c->branch),v);
    else if(!strcmp(k,"title_id"))put(c->title_id,sizeof(c->title_id),v);
    else if(!strcmp(k,"token"))put(c->token,sizeof(c->token),v);
    else if(!strcmp(k,"log_dir"))put(c->log_dir,sizeof(c->log_dir),v);
    else if(!strcmp(k,"log_file"))put(c->log_file,sizeof(c->log_file),v);
    else if(!strcmp(k,"upload_logs"))c->upload_logs=atoi(v)==1;
    else if(!strcmp(k,"upload_core"))c->upload_core=atoi(v)==1;
    else if(!strcmp(k,"auto_launch"))c->auto_launch=atoi(v)==1;
  }
  fclose(f);
  if(!vt_valid_slug(c->owner)||!vt_valid_slug(c->repo)||!vt_valid_slug(c->branch)||!vt_valid_titleid(c->title_id))return -2;
  if((c->log_dir[0]&&!vt_valid_logpath(c->log_dir))||(c->log_file[0]&&!vt_valid_logpath(c->log_file)))return -3;
  return 0;
}
int vt_read_manifest(const char *path,VTManifest *m){
  FILE *f=fopen(path,"rb");char line[1024];if(!f)return -1;
  memset(m,0,sizeof(*m));
  while(fgets(line,sizeof(line),f)){
    char *k,*v;if(line[0]=='#'||!pair(line,&k,&v))continue;
    if(!strcmp(k,"version"))put(m->version,sizeof(m->version),v);
    else if(!strcmp(k,"title_id"))put(m->title_id,sizeof(m->title_id),v);
    else if(!strcmp(k,"vpk_url"))put(m->vpk_url,sizeof(m->vpk_url),v);
    else if(!strcmp(k,"sha256"))put(m->sha256,sizeof(m->sha256),v);
  }
  fclose(f);
  if(!m->version[0]||strlen(m->version)>48||strpbrk(m->version,"/\\ \r\n")||!vt_valid_titleid(m->title_id)||!vt_valid_sha256(m->sha256)||!vt_valid_vpk_url(m->vpk_url))return -2;
  return 0;
}
int vt_sha256_file(const char *path,char out[65]){
  unsigned char buffer[32768],digest[32];FILE *f=fopen(path,"rb");SHA256_CTX ctx;
  if(!f)return -1;
  SHA256_Init(&ctx);size_t n;
  while((n=fread(buffer,1,sizeof(buffer),f))>0)SHA256_Update(&ctx,buffer,n);
  if(ferror(f)){fclose(f);return -2;}
  SHA256_Final(digest,&ctx);fclose(f);
  for(int i=0;i<32;i++){sprintf(out+2*i,"%02x",digest[i]);}
  out[64]=0;return 0;
}
