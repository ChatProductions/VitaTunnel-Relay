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
 assert(vt_valid_titleid("OPENCE001"));
 assert(!vt_valid_titleid("VITATUNN1"));
 assert(!vt_valid_titleid("../../../../"));
 assert(vt_valid_sha256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
 assert(!vt_valid_sha256("BAD"));
 assert(vt_valid_vpk_url("https://github.com/test/repo/releases/download/v1/game.vpk"));
 assert(!vt_valid_vpk_url("http://github.com/test/repo/releases/download/v1/game.vpk"));
 assert(!vt_valid_vpk_url("https://evil.example.com/release.vpk"));
 assert(vt_valid_logpath("ux0:data/open-ce/logs/report.log"));
 assert(!vt_valid_logpath("ur0:tai/config.txt"));
 assert(!vt_valid_logpath("ux0:data/../tai/config.txt"));
 assert(vt_read_config(argv[1],&c)==0);
 assert(!strcmp(c.title_id,"OPENCE001"));
 assert(vt_read_manifest(argv[2],&m)==0);
 assert(!strcmp(m.title_id,"OPENCE001"));
 puts("Protocol validation tests PASSED");
 return 0;
}
