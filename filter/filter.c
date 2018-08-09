#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<netinet/in.h>
#include<string.h>
#include<regex.h>
#include<dirent.h>
#include<ctype.h>
#include<time.h>
#include<linux/netfilter.h>
#include<libnetfilter_queue/libnetfilter_queue.h>

#define QUEUE_NUM 2 
 
int fd_w;
char port_num[48];
char all_log[248];
char inode[128];
char path[128];


int proc_info(char *proc_path,long time){
	FILE * proc_fp;
	FILE * proc_print_fp;

	char proc_stat[248];
	char pid[12];
	char comm[24];

	regex_t preg;
	size_t nmatch=5;
	regmatch_t pmatch[nmatch];
	int i,j;

	char file_name[48];
	char file_path[128];

	sprintf(file_name,"proc_collect_%ld.csv",time);
	sprintf(file_path,"/opt/filter/%s",file_name);

	pid[0]='\0';
	comm[0]='\0';

	printf("%s\n",file_path);

	if((proc_print_fp = fopen(file_path,"a")) == NULL){
		fprintf(stderr,"fail to open proc_collect.csv");
		exit(1);
	}
	

	if((proc_fp = fopen(proc_path,"r")) != NULL){
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
			
			fprintf(proc_print_fp,"[pid=%s,comm=%s]\n",pid,comm);

		}else{
			//printf("no match\n");
		}	
		regfree(&preg);
		//printf("i=%d,eo=%d,so=%d\n",i,pmatch[2].rm_eo,pmatch[2].rm_so);
		//printf("%s\n",comm);
	}
	fclose(proc_print_fp);
	return 0;
}


int make_path(){
	DIR *dir;
	struct dirent *dp;
	char dname[48];

	regex_t p_preg;
	size_t p_nmatch=5;
	regmatch_t p_pmatch[p_nmatch];

	time_t t = time(NULL);

	printf("start make path\n");
	
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
				//printf("no match\n");
			}else{
				snprintf(path,128,"%s%s%s","/proc/",dname,"/stat");
				proc_info(path,t);
			}
			regfree(&p_preg);
		}
	closedir(dir);
	}
	return 0;
}


int check_ip(const char *buf,int len){
	char dist_ip[20];
	char reject_ip[40];
	//FILE * ip_file;
	FILE * reject_file;

	dist_ip[0]='\0';
	//reject_ip[0]='\0';

	//fprint payload's dist_ip	
	sprintf(dist_ip,"%02x%02x%02x%02x\n",(unsigned char)buf[16],(unsigned char)buf[17],(unsigned char)buf[18],(unsigned char)buf[19]);

	//printf("dist_ip is : %s\n",dist_ip);

	//pythonで登録したファイルを読み込んでipアドレスの比較を行う
	reject_file=fopen("/opt/filter/rejectip.conf","r");
		while (fgets(reject_ip,40,reject_file) != NULL){
			if (strcmp(dist_ip,reject_ip)==0){
				return 1;
			}//else{
				//return 0; 
			//}	
			reject_ip[0]='\0';
		}
	fclose(reject_file);
	return 0;
}
 

int get_inode(const char *buf,int len){
	//パケットの送り元ポート番号
	port_num[0]='\0';	
	sprintf(port_num,"%02x%02x",(unsigned char)buf[20],(unsigned char)buf[21]);

	inode[0]='\0';
	
	char tcp_port[8];
	char tcp_inode[128];

	FILE * net_tcp;
	char tcp_data[248];

	regex_t t_preg;
	size_t t_nmatch=15;
	regmatch_t t_pmatch[t_nmatch];
	int i,j;

	//if(regcomp(&t_preg,"([0-9]:)(.+:([0-9]{4}))(.+:.{4})(.+:.+)([0-9]{2}:.{9})([0-9]+)(.+0.+0[^0-9])([0-9]+)(.+)([a-z]{4}.+)",REG_EXTENDED|REG_NEWLINE) != 0 ){

	if(regcomp(&t_preg,"([0-9]:)(.+:(.{4}))(.+:.{4})(.+:.+)([0-9]{2}:.{9})([0-9]+)(.+0.+0[^0-9])([0-9]+)(.+)([a-z]{4}.+)",REG_EXTENDED|REG_NEWLINE) != 0 ){

		fprintf(stderr,"net_tcp regex compile failed");
		exit(1);

	}
	
	net_tcp=fopen("/proc/net/tcp","r");
		while(fgets(tcp_data,247,net_tcp) != NULL){
			//printf("String is %s\n",tcp_data);
			if(regexec(&t_preg,tcp_data,t_nmatch,t_pmatch,0) == 0){
				
				i = t_pmatch[3].rm_eo - t_pmatch[3].rm_so;
				i = i+1;
				snprintf(tcp_port,i,"%s",&tcp_data[t_pmatch[3].rm_so]);

				if(strcasecmp(port_num,tcp_port)==0){

					j = t_pmatch[9].rm_eo - t_pmatch[9].rm_so;
					j = j+1;
					snprintf(tcp_inode,j,"%s",&tcp_data[t_pmatch[9].rm_so]);	

					//printf("[payload_port=%s,port=%s,inode=%s]\n",port_num,tcp_port,tcp_inode);
					//sprintf(inode,"%s",tcp_inode);
					strcat(inode,tcp_inode);
					strcat(inode,",");
					//printf("inode=[%s]\n",inode);	
				}
			}
			tcp_data[0]='\0';
		}
	//printf("get_inode=%s\n",inode);
	fclose(net_tcp);
}


//ペイロードからport番号を取り出してshellを起動
static void print_payload(const char *buf,int len){
	//port_num[0]='\0';
	//char cmd[128];
	char dist_port_hex[36];
	long use_port;
	long dist_port;	

	char pid[64];
	FILE * fp;

	FILE * all_file;

	printf("start print payload\n");

	//sprintf(port_num,"%02x%02x",(unsigned char)buf[20],(unsigned char)buf[21]);
	
	//sprintf(cmd,"/opt/filter/port_conversion.sh %s",port_num);
	use_port = strtol(port_num,NULL,16);
	
	sprintf(dist_port_hex,"%02x%02x",(unsigned char)buf[22],(unsigned char)buf[23]);
	dist_port = strtol(port_num,NULL,16);	

	//start shell
	//printf("cmd is %s\n",cmd);
	//shell実行＆pidをファイルから取得
	/*if (system(cmd)==0){
		fp=fopen("/opt/filter/pid.txt","r");
		if(fp==NULL){
			fprintf(stderr,"can not open pid.txt\n");
			exit(1);
		}	
			
		fgets(pid,64,fp);
		pid[strlen(pid)-1]='\0';
		fclose(fp);
	*/
			
		sprintf(all_log,"protcol_num=%02x,dist_ip=%d.%d.%d.%d,dist_port=%ld,use_port=%ld,inode=%s",(unsigned char)buf[9],(unsigned char)buf[16],(unsigned char)buf[17],(unsigned char)buf[18],(unsigned char)buf[19],dist_port,use_port,inode);
	//ログの吐き出し
		
		if((all_file = fopen("/opt/filter/net_filter_log.csv","a"))==NULL){
			fprintf(stderr,"can not open net_filter_log.csv");
		}	

		fprintf(all_file,"%s\n",all_log);
		fclose(all_file);
		
	/*}else{
		fprintf(stderr,"shell error\n");
		exit(1);
	}*/
		
}


int get_payload(struct nfq_q_handle *q_handle, struct nfgenmsg *nfmsg, struct nfq_data *nfdata,void *data){
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfdata);
	int id = ntohl(ph -> packet_id);
	int len;
	u_char *payload;

	len = nfq_get_payload(nfdata,(u_char **)&payload);

	char renice_cmd[48];
	char renice_cmd_return[48];
	
	pid_t c_pid;
	c_pid = getpid();

	sprintf(renice_cmd,"renice -20 -p %d > /dev/null 2>&1",c_pid);	
	sprintf(renice_cmd_return,"renice 0 -p %d > /dev/null 2>&1",c_pid);
	
	//排除対象のIPかどうかを確認し，その後の処理をするかどうか判断	
	if (check_ip(payload,len)==0){

		//優先順位をあげる	
		if (system(renice_cmd) != 0){
			fprintf(stderr,"failed_renice_change\n");
			exit(1);
		}
	
		make_path();
		get_inode(payload,len);	
		print_payload(payload,len);


		//優先順位を戻す
		if (system(renice_cmd_return) != 0){
			fprintf(stderr,"failed_renice_return\n");
			exit(1);
		}	
	}
	
	nfq_set_verdict(q_handle,id,NF_ACCEPT,0,NULL);

}


int main(void){

	struct nfq_handle *handle;
	struct nfq_q_handle *q_handle;
	int fd;
	int len;
	char buf[4096];

	handle = nfq_open();
	
	if(handle==NULL){
		fprintf(stderr,"nfq_open: error\n");
		exit(1);
	}

	if(nfq_unbind_pf(handle, AF_INET) < 0){
		fprintf(stderr,"nfq_unbind_pf: error\n");
		exit(1);
	}

	if(nfq_bind_pf(handle, AF_INET) < 0){
		fprintf(stderr,"nfq_bind_pf: error\n");
		exit(1);
	}

	q_handle = nfq_create_queue(handle, QUEUE_NUM,get_payload ,NULL);
	if(q_handle == NULL){
		fprintf(stderr,"nfq_create_queue: error\n");
		exit(1);
	}

	if(nfq_set_mode(q_handle, NFQNL_COPY_PACKET, 0xffff) < 0){
		fprintf(stderr,"nfq_set_mode: error\n");
		exit(1);
	}

	fd = nfq_fd(handle);

	while((len = read(fd,buf,sizeof(buf))) >= 0){
		nfq_handle_packet(handle,buf,len);
		//memset(buf, '\0',4096);
		buf[0]='\0';
	}

	nfq_destroy_queue(q_handle);
	nfq_unbind_pf(handle, AF_INET);
	nfq_close(handle);
	exit(0);
}
