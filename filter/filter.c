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

int pipeopen(int *fd_w,char *port_num){
	int pipefd[2];
	pid_t pid;
	char port[8]="22";
	if(pipe(pipefd) < 0){
		fprintf(stderr,"%s","fail to create pipe:pipe()\n");
		return 1;
	}

	if((pid = fork()) < 0){
		fprintf(stderr,"%s","fail to creat process:fork()\n");
		close(pipefd[0]);
		close(pipefd[1]);
		return 1;
	}
	
	if(pid == 0){
		close(pipefd[1]);
		dup2(pipefd[0],0);
		//if(execl("/opt/filter/cfilter/specify_file.sh","/opt/filter/cfilter/specify_file.sh",port,NULL) < 0){
		//if(execl("/opt/filter/cfilter/lsof.sh","/opt/filter/cfilter/lsof.sh","22",NULL) < 0){
		if(execl("/opt/filter/cfilter/echo.sh","/opt/filter/cfilter/echo.sh",NULL) < 0){
			fprintf(stderr,"%s","fail to execl()\n");
			close(pipefd[0]);
			return 1;
		}
	}

	close(pipefd[0]);
	*fd_w = pipefd[1];
	return 0;
}	


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


static void print_payload(const char *buf,int len){
	int i;
	char port[8];	
	FILE * file;
	
	port_num[0]='\0';
	port[0]='\0';

	file=fopen("/opt/filter/cfilter/log.txt","w");
		fprintf(file,"%d",(unsigned char)buf[20]);
		fprintf(file,"%d",(unsigned char)buf[21]);
		fprintf(file,"\n");
	fclose(file);	
	
	file=fopen("/opt/filter/cfilter/log.txt","r");
		fgets(port,8,file);
	fclose(file);
	
	strcpy(port_num,port);	

	//meke process & shell start	
	fd_w = fileno(stdout);
	if(pipeopen(&fd_w,port_num) == 1){
		exit(1);	
	}	
}


int get_payload(struct nfq_q_handle *q_handle, struct nfgenmsg *nfmsg, struct nfq_data *nfdata,void *data){
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfdata);
	int id = ntohl(ph -> packet_id);
	int len;
	u_char *payload;

	len = nfq_get_payload(nfdata,(u_char **)&payload);
	
	if (check_ip(payload,len)==0){
		print_payload(payload,len);
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
