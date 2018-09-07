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
//extern char *pid; 

int check_ip(const char *buf,int len){
	char dist_ip[20];
	char reject_ip[40];
	//FILE * ip_file;
	FILE * reject_file;

	dist_ip[0]='\0';
	//reject_ip[0]='\0';

	//fprint payload's dist_ip	
	sprintf(dist_ip,"%02x%02x%02x%02x\n",(unsigned char)buf[16],(unsigned char)buf[17],(unsigned char)buf[18],(unsigned char)buf[19]);

	printf("start check_ip\n");

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
	
	char tcp_port[8];
	char tcp_inode[32];

	FILE * net_tcp;
	char tcp_data[248];

	regex_t t_preg;
	size_t t_nmatch=15;
	regmatch_t t_pmatch[t_nmatch];
	int i,j;

	if(regcomp(&t_preg,"([0-9]:)(.+:(.{4}))(.+:.{4})(.+:.+)([0-9]{2}:.{9})([0-9]{8})(.{16})([0-9]+)(.+)([a-z]{4}.+)",REG_EXTENDED|REG_NEWLINE) != 0 ){

		fprintf(stderr,"net_tcp regex compile failed");
		exit(1);

	}

	//proc/net/tcpを開いてinodeを収集する	
	net_tcp=fopen("/proc/net/tcp","r");
		while(fgets(tcp_data,247,net_tcp) != NULL){
			//printf("String is %s\n",tcp_data);
			if(regexec(&t_preg,tcp_data,t_nmatch,t_pmatch,0) == 0){
				
				i = t_pmatch[3].rm_eo - t_pmatch[3].rm_so;
				i = i+1;
				snprintf(tcp_port,i,"%s",&tcp_data[t_pmatch[3].rm_so]);

				if(strcasecmp(port_num,tcp_port)==0){
					//proc/net/tcpにあるinode情報をtcp_inodeに格納している
					j = t_pmatch[9].rm_eo - t_pmatch[9].rm_so;
					j = j+1;
					snprintf(tcp_inode,j,"%s",&tcp_data[t_pmatch[9].rm_so]);	

					//proc/[pid]/fdのinodeと比較を行う
					printf("port_num = %s , packet_inode = %s\n",tcp_port,tcp_inode);
					make_path(tcp_inode);		
				}
			}else{
				//printf("/proc/net/tcp = %s",tcp_data);
				//printf("no match\n");
			}
			tcp_data[0]='\0';
		}
	fclose(net_tcp);
}


//ペイロードからport番号を取り出してshellを起動
static void print_payload(const char *buf,int len){
	//port_num[0]='\0';
	//char cmd[128];
	char dist_port_hex[36];
	long use_port;
	long dist_port;	
	char pid;

	FILE * fp;

	FILE * all_file;
	time_t a_t = time(NULL);
	
	//sprintf(port_num,"%02x%02x",(unsigned char)buf[20],(unsigned char)buf[21]);
	
	//sprintf(cmd,"/opt/filter/port_conversion.sh %s",port_num);
	use_port = strtol(port_num,NULL,16);
	
	sprintf(dist_port_hex,"%02x%02x",(unsigned char)buf[22],(unsigned char)buf[23]);
	dist_port = strtol(port_num,NULL,16);	

	sprintf(all_log,"time=%ld,protcol_num=%02x,dist_ip=%d.%d.%d.%d,dist_port=%ld,use_port=%ld,pid=%s",a_t,(unsigned char)buf[9],(unsigned char)buf[16],(unsigned char)buf[17],(unsigned char)buf[18],(unsigned char)buf[19],dist_port,use_port,pid);
	//ログの吐き出し
		
	if((all_file = fopen("/opt/filter/net_filter_log.csv","a"))==NULL){
		fprintf(stderr,"can not open net_filter_log.csv");
	}	

	fprintf(all_file,"%s\n",all_log);
	fclose(all_file);
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
	//if (check_ip(payload,len)==0){
		//優先順位をあげる	
	/*	if (system(renice_cmd) != 0){
			fprintf(stderr,"failed_renice_change\n");
			exit(1);
		}
	*/
		//make_path();
		get_inode(payload,len);	
		print_payload(payload,len);
	/*
		//優先順位を戻す
		if (system(renice_cmd_return) != 0){
			fprintf(stderr,"failed_renice_return\n");
			exit(1);
		}
	*/		
	//}
	
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
