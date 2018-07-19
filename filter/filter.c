#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<netinet/in.h>
#include<string.h>
#include<linux/netfilter.h>
#include<libnetfilter_queue/libnetfilter_queue.h>

#define QUEUE_NUM 2 
int fd_w;
char port_num[48];
char all_log[248];

int check_ip(const char *buf,int len){
	char dist_ip[40];
	char reject_ip[40];
	FILE * ip_file;
	FILE * reject_file;

	dist_ip[0]='\0';
	reject_ip[0]='\0';

	//fprint payload's dist_ip	
	ip_file=fopen("/opt/filter/cfilter/dist_ip.txt","w");
		fprintf(ip_file,"%02x",(unsigned char)buf[16]);
		fprintf(ip_file,"%02x",(unsigned char)buf[17]);
		fprintf(ip_file,"%02x",(unsigned char)buf[18]);
		fprintf(ip_file,"%02x",(unsigned char)buf[19]);
		fprintf(ip_file,"\n");
	fclose(ip_file);
	
	ip_file=fopen("/opt/filter/cfilter/dist_ip.txt","r");
		fgets(dist_ip,40,ip_file);
	fclose(ip_file);

	reject_file=fopen("/opt/filter/cfilter/rejectip.conf","r");
		while (fgets(reject_ip,40,reject_file) != NULL){
			printf("read to %s",reject_ip);
			if (strcmp(dist_ip,reject_ip)==0){
				printf("same ip\n");
				return 1;
			}else{
				return 0; 
			}	
		}
	fclose(reject_file);

}

/*使わないかも
int get_pid(){
	char pid[64];
	FILE * fp;

	fp=fopen("/opt/filter/pid.txt","r");
	if(fp==NULL){
		fprintf(stderr,"can not open pid.txt\n");
		exit(1);
	}
	
	fgets(pid,64,fp);
	sprintf(all_log,",pid=%s",pid);
	sprintf(all_log,"testtesttes");
	
	printf("full_all_log is:%s\n",all_log);
}
*/

int print_file(){
	FILE * file;

	file=fopen("/opt/filter/net_filter_log.csv","a");
	if(file==NULL){
		fprintf(stderr,"can not open net_filter_log.csv");
	}	

	fprintf(file,"%s\n",all_log);
	fclose(file);
	
}
 

//ペイロードからport番号を取り出してshellを起動
static void print_payload(const char *buf,int len){
	port_num[0]='\0';
	char cmd[128];
	
	char pid[64];
	FILE * fp;

	sprintf(port_num,"%02x%02x",(unsigned char)buf[20],(unsigned char)buf[21]);
	
	sprintf(cmd,"/opt/filter/port_conversion.sh %s",port_num);	
	
	//start shell
	//printf("cmd is %s\n",cmd);
	if (system(cmd)==0){
		//get_pid();
		fp=fopen("/opt/filter/pid.txt","r");
		if(fp==NULL){
			fprintf(stderr,"can not open pid.txt\n");
			exit(1);
		}	
			
		fgets(pid,64,fp);
		pid[strlen(pid)-1]='\0';
		fclose(fp);

		sprintf(all_log,"pid=%sprotcol_num=%02x,dist_ip=%d.%d.%d.%d,dist_port=%d%d,use_port=%d%d",pid,(unsigned char)buf[9],(unsigned char)buf[16],(unsigned char)buf[17],(unsigned char)buf[18],(unsigned char)buf[19],(unsigned char)buf[22],(unsigned char)buf[23],(unsigned char)buf[20],(unsigned char)buf[21]);
		print_file();
	}else{
		printf("no\n");
		fprintf(stderr,"shell error\n");
		exit(1);
	}
		
}


int get_payload(struct nfq_q_handle *q_handle, struct nfgenmsg *nfmsg, struct nfq_data *nfdata,void *data){
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfdata);
	int id = ntohl(ph -> packet_id);
	int len;
	u_char *payload;

	len = nfq_get_payload(nfdata,(u_char **)&payload);

	//排除対象のIPかどうかを確認し，その後の処理をするかどうか判断	
	//if (check_ip(payload,len)==0){
		print_payload(payload,len);
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
