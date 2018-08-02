#include<stdio.h>
#include<stdlib.h>
#include<dirent.h>
#include<string.h>
#include<ctype.h>
#include<regex.h>

char path[128];


int proc_info(char *proc_path){
	FILE * fp;
	char proc_stat[248];
	char pid[12];
	char comm[24];

	regex_t preg;
	size_t nmatch=5;
	regmatch_t pmatch[nmatch];
	int i,j;

	pid[0]='\0';
	comm[0]='\0';
	
	fp= fopen(proc_path,"r");
	if(fp!=NULL){
		fgets(proc_stat,245,fp);
		//printf("%s\n",proc_stat);	
		
		//正規表現で()を引っこ抜こうとしている	
		if(regcomp(&preg,"([0-9]+)(.+[^A-Z])([A-Z])(.+)",REG_EXTENDED|REG_NEWLINE) != 0){
			fprintf(stderr,"regex complie failed");
			exit(1);
		}
		
		if(regexec(&preg,proc_stat,nmatch,pmatch,0) != 0){
			printf("no match\n");
		}else{
			j = pmatch[1].rm_eo - pmatch[1].rm_so;
			j = j+1;
			snprintf(pid,j,"%s",&proc_stat[pmatch[1].rm_so]);

			/*if(pmatch[2].rm_so >= 0 && pmatch[2].rm_eo >= 0){
				for(j=pmatch[2].rm_so ; j < pmatch[2].rm_eo ; j++){
					putchar(proc_stat[j]);
				}
			}			
			*/
			//proc_stat[pmatch[2].rm_eo]='\0';
			//printf("%s\n",&proc_stat[pmatch[2].rm_so]);
			
			//()を抜いて変数に入れる処理
			i = pmatch[2].rm_eo - pmatch[2].rm_so;
			snprintf(comm,i,"%s",&proc_stat[pmatch[2].rm_so]+1);
			
			printf("[pid=%s,comm=%s]",pid,comm);

		}	
		regfree(&preg);

		//printf("i=%d,eo=%d,so=%d\n",i,pmatch[2].rm_eo,pmatch[2].rm_so);
		//printf("%s\n",comm);
	}
}


int make_path(){
	DIR *dir;
	struct dirent *dp;
	char dname[48];

	if((dir=opendir("/proc"))==NULL){
		fprintf(stderr,"can not open /proc");
		exit(1);
	}else{
		for(dp=readdir(dir);dp!=NULL;dp=readdir(dir)){
			strncpy(dname,dp->d_name,20);
		
			snprintf(path,128,"%s%s%s","/proc/",dname,"/stat");
			proc_info(path);
		}
	closedir(dir);
	}
}

int main(){

	make_path();

	return 0;
}
