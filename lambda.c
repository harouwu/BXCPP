#include <stdio.h>
#define SKIP_SPACES(p, limit)  \
{ char *lim = (limit);         \
  while (p < lim) {            \
	if (*p++ != ' ') {         \
	  p--; break; }}}
	  

int main(){
	int * p = {1,2,3};
	if (*p != 0)
	  SKIP_SPACES (p, lim);
	else
		printf("it works!\n");
	return 0;
}