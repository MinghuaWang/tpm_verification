/* created by minghua
1) download libgpg-error and libgcrypt
2) compile libgpg-error at first (on a vm ):
	autoconf && ./configure && make -j6 && make install
3) compile libgcrypt
	./configure && find ./ -iname "mod-source-info.h"
4) copy the content and modify it.
*/

static char mod_source_info[] = 
	":generic/mpih-add1.S"
	":generic/mpih-sub1.S"
	":generic/mpih-mul1.S"
	":generic/mpih-mul2.S"
	":generic/mpih-mul3.S"
	":generic/mpih-lshift.S"
	":generic/mpih-rshift.S"
	;
			
			
			
			
			
			
