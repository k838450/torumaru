#include<stdio.h>
#include<stdlib.h>
#include<dirent.h>
#include<string.h>
#include<ctype.h>
#include<regex.h>
#include<time.h>
#include<unistd.h>

char stat_path[128];
char fd_path[128];
char proc_log[128];
char pid[64];

int proc_stat_info(char *c_pid){
	char proc_stat[248];
	char comm[24];
	char stat_path[48];
	
	FILE * proc_fp;

	regex_t preg;
	size_t nmatch=5;
	regmatch_t pmatch[nmatch];
	int i;

	//pid[0]='\0';
	comm[0]='\0';
	sprintf(stat_path,"/proc/%s/stat",c_pid);
	//proc/[PID]/statを開く
	if((proc_fp = fopen(stat_path,"r")) != NULL){
		fgets(proc_stat,245,proc_fp);
		
		//正規表現で()を引っこ抜こうとしている	
		if(regcomp(&preg,"([0-9]+)(.+[^A-Z])([A-Z])(.+)",REG_EXTENDED|REG_NEWLINE) != 0){
			fprintf(stderr,"regex compile failed");
			exit(1);
		}
		
		if(regexec(&preg,proc_stat,nmatch,pmatch,0) == 0){
			//()を抜いて変数に入れる処理
			i = pmatch[2].rm_eo - pmatch[2].rm_so;
			i = i-1;
			snprintf(comm,i,"%s",&proc_stat[pmatch[2].rm_so]+1);
			
			strcat(pid,comm);
		}else{
			printf("no match ()\n");
		}
		regfree(&preg);
		fclose(proc_fp);
	}
	return 0;
}


int proc_fd_info(char *fd_path,long time,char *dname,const char *tcp_inode){
	DIR *fd_dir;
	struct dirent *fd_dp;
	char fd_num[128];

	char fd_num_path[128];

	char linkname[248];
	ssize_t link_len;

	regex_t fd_preg;
	size_t fd_nmatch=5;
	regmatch_t fd_pmatch[fd_nmatch];

	char inode[24];
	char c_pid[24];
	int m,n;

	if((fd_dir=opendir(fd_path))==NULL){
		//printf("no pid\n");
		return 0;	
	}else{
		for(fd_dp=readdir(fd_dir);fd_dp!=NULL;fd_dp=readdir(fd_dir)){
			strncpy(fd_num,fd_dp->d_name,126);
			//fdの中の全てのファイルへのパスを作成
			snprintf(fd_num_path,126,"%s%s%s",fd_path,"/",fd_num);	
	
			//fd/数字のリンク先を取得	
			link_len = readlink(fd_num_path,linkname,sizeof(linkname));
			linkname[link_len]='\0';	

			inode[0]='\0';
			if(regcomp(&fd_preg,"(socket:)([[0-9]+])",REG_EXTENDED|REG_NEWLINE) != 0){
				fprintf(stderr,"fd regex compile failed");
				exit(1);
			}

			if(regexec(&fd_preg,linkname,fd_nmatch,fd_pmatch,0) == 0){
				m = fd_pmatch[2].rm_eo - fd_pmatch[2].rm_so;
				snprintf(inode,m-1,&linkname[fd_pmatch[2].rm_so+1]);

				if(strcmp(inode,tcp_inode)==0){
					sprintf(c_pid,"%s",dname);
					strcat(pid,dname);
					
					proc_stat_info(c_pid);			
					strcat(pid,",");
				}
			
			}else{
				//printf("no mutch\n");
			}
			regfree(&fd_preg);
		}
		closedir(fd_dir);	
	}
	return 0;
} 


int make_path(const char *tcp_inode){
	DIR *dir;
	struct dirent *dp;
	char dname[48];

	regex_t p_preg;
	size_t p_nmatch=5;
	regmatch_t p_pmatch[p_nmatch];
	
	//FILE * proc_print_fp;
	time_t t = time(NULL);
	//char file_name[64];
	
	char file_path[128];

	if((dir=opendir("/proc"))==NULL){
		fprintf(stderr,"can not open /proc");
		exit(1);
	}else{
		for(dp=readdir(dir);dp!=NULL;dp=readdir(dir)){
			strncpy(dname,dp->d_name,20);
			
			//dnameが数字かどうか正規表現で判断する
			if(regcomp(&p_preg,"([0-9]+)",REG_EXTENDED|REG_NEWLINE) != 0){
				fprintf(stderr,"path regex compile failed");
				exit(1);
			}

			if(regexec(&p_preg,dname,p_nmatch,p_pmatch,0) != 0){
				//printf("stat_path =  %s [no number]\n",dname);
			}else{
				//各PIDまでへのfdパスを作成してproc_fd_infoの実行
				//printf("start %s\n",dname);
				snprintf(fd_path,128,"%s%s%s","/proc/",dname,"/fd");
				proc_fd_info(fd_path,t,dname,tcp_inode);
				
			}
			regfree(&p_preg);
		}
		closedir(dir);
		//fclose(proc_print_fp);
	}
	return 0;
}

/*
int main(){
	
	make_path();
	return 0;
}*/
