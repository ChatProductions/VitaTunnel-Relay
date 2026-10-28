#include "protocol.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv){
 assert(argc==3);
 VTConfig c;VTManifest m;
 assert(vt_valid_slug("ChatProductions"));
 assert(!vt_valid_slug("user/x"));
 assert(!vt_valid_slug("../oops"));
 assert(vt_valid_titleid("NFMRA0001"));
 assert(!vt_valid_titleid("VITATUNN1"));
 assert(!vt_valid_titleid("../../../../"));
 assert(vt_valid_sha256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
 assert(!vt_valid_sha256("BAD"));
 assert(vt_valid_vpk_url("https://github.com/test/repo/releases/download/v1/game.vpk"));
 assert(vt_valid_vpk_url("https://raw.githubusercontent.com/ChatProductions/VitaTunnel-Relay/main/tunnel/packages/test.vpk"));
 assert(!vt_valid_vpk_url("https://raw.githubusercontent.com/ChatProductions/VitaTunnel-Relay/main/tunnel/packages/test.vpk?token=x"));
 assert(!vt_valid_vpk_url("https://raw.githubusercontent.com/ChatProductions/VitaTunnel-Relay/main/other/test.vpk"));
 assert(!vt_valid_vpk_url("https://evil.example.com/test.vpk"));
 assert(!vt_valid_vpk_url("http://github.com/test/repo/releases/download/v1/game.vpk"));
 assert(!vt_valid_vpk_url("https://evil.example.com/release.vpk"));
 assert(vt_valid_logpath("ux0:data/ps2vita/startup.txt"));
 assert(!vt_valid_logpath("ur0:tai/config.txt"));
 assert(!vt_valid_logpath("ux0:data/../tai/config.txt"));
 assert(vt_read_config(argv[1],&c)==0);
 assert(!strcmp(c.title_id,"NFMRA0001"));
 assert(!strcmp(c.owner,"ChatProductions"));
 assert(!strcmp(c.repo,"VitaTunnel-Relay"));
 assert(!strcmp(c.log_dir,"ux0:data/ps2vita"));
 assert(!strcmp(c.log_file,"ux0:data/ps2vita/startup.txt"));
 assert(!strcmp(c.log_fault,"ux0:data/ps2vita/fault.txt"));
 assert(!strcmp(c.log_progress,"ux0:data/ps2vita/progress.txt"));
 assert(!c.upload_logs && !c.token[0] && !c.upload_core);
 assert(vt_read_manifest(argv[2],&m)==0);
 assert(!strcmp(m.title_id,"NFMRA0001"));
 puts("Protocol validation tests PASSED");
 return 0;
}
