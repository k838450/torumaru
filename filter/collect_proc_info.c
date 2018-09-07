//記録対象のパケットを検知した際に，その時端末内で動作していた全てのプロセスのpidと実行ファイル名を記録し，ファイルに出力する

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

int proc_stat_info(char *proc_path,long time,FILE * proc_print_fp){
	FILE * proc_fp;
	//FILE * proc_print_fp;
	
	char proc_stat[248];
	char pid[12];
	char comm[24];

	regex_t preg;
	size_t nmatch=5;
	regmatch_t pmatch[nmatch];
	int i,j;

	pid[0]='\0';
	comm[0]='\0';
	
	printf("start proc_info\n");

	//proc/[PID]/statを開く
	printf("stat_path = %s\n",proc_path);
	if((proc_fp = fopen(proc_path,"rb")) != NULL){
		fgets(proc_stat,245,proc_fp);
		//printf("%s\n",proc_stat);	
		
		//正規表現で()を引っこ抜こうとしている	
		if(regcomp(&preg,"([0-9]+)(.+[^A-Z])([A-Z])(.+)",REG_EXTENDED|REG_NEWLINE) != 0){
			fprintf(stderr,"regex compile failed");
			exit(1);
		}
		
		if(regexec(&preg,proc_stat,nmatch,pmatch,0) == 0){
			//PIDの取得
			j = pmatch[1].rm_eo - pmatch[1].rm_so;
			j = j+1;
			snprintf(pid,j,"%s",&proc_stat[pmatch[1].rm_so]);
			
			//()を抜いて変数に入れる処理
			i = pmatch[2].rm_eo - pmatch[2].rm_so;
			i = i-1;
			snprintf(comm,i,"%s",&proc_stat[pmatch[2].rm_so]+1);

			printf("pid = %s\n",pid);
			printf("cmm = %s\n",comm);
			printf("%s\n",proc_stat);	

/*	
			if((proc_print_fp = fopen(file_path,"a")) == NULL){
				printf("%d\n",&proc_print_fp);
				fprintf(stderr,"fail to open proc_.csv");
				exit(1);
			}
*/
			printf("[time=%ld,pid=%s,comm=%s]\n",time,pid,comm);	
			fprintf(proc_print_fp,"[time=%ld,pid=%s,comm=%s]\n",time,pid,comm);	
		}else{
			printf("no match ()\n");
		}
		regfree(&preg);
		//printf("i=%d,eo=%d,so=%d\n",i,pmatch[2].rm_eo,pmatch[2].rm_so);
		//printf("%s\n",comm);
	}
	printf("you\n");
	return 0;
}


int proc_fd_info(char *fd_path,long time,FILE * proc_print_fp,char *dname){
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
	int m;

	char pid_inode[456];

	char demo_tcp_inode[128];
	demo_tcp_inode[0]='\0';
	strcat(demo_tcp_inode,"30481");
	
	pid_inode[0]='\0';	

	if((fd_dir=opendir(fd_path))==NULL){
		fprintf(stderr,"fail to open /fd/num");
		exit(1);
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

				if(strcmp(inode,demo_tcp_inode)==0){
					//strcat(pid_inode,inode);
					//strcat(pid_inode,",");
					printf("path = %s -> %s\n",fd_num_path,linkname);
					printf("inode = %s\n",inode);
					printf("dname = %s\n",dname);
					//printf("inode_list = %s\n",pid_inode);	
				}
			
			}else{
				//printf("no mutch\n");
			}
		}
		closedir(fd_dir);	
	}
	return 0;
} 


int make_path(){
	DIR *dir;
	struct dirent *dp;
	char dname[48];

	regex_t p_preg;
	size_t p_nmatch=5;
	regmatch_t p_pmatch[p_nmatch];

	FILE * proc_print_fp;
	time_t t = time(NULL);
	//char file_name[64];
	char file_path[128];

	//ファイル名と出力先の設定
	//sprintf(file_name,"proc_%ld.csv",t);
	sprintf(file_path,"/opt/filter/proc_%ld.csv",t);

	if((proc_print_fp = fopen(file_path,"a")) == NULL){
		fprintf(stderr,"fail to open proc_.csv");
		exit(1);
	}
	
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
				//statのファイルパスを作成してproc_infoの実行
				//snprintf(stat_path,128,"%s%s%s","/proc/",dname,"/stat");
				//proc_stat_info(stat_path,t,proc_print_fp);

				//各PIDまでへのfdパスを作成してproc_fd_infoの実行
				snprintf(fd_path,128,"%s%s%s","/proc/",dname,"/fd");
				proc_fd_info(fd_path,t,proc_print_fp,dname);
				
			}
			regfree(&p_preg);
		}
		closedir(dir);
		fclose(proc_print_fp);
	}
	return 0;
}


int main(){

	make_path();

	return 0;
}
