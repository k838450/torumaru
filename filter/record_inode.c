#include<stdio.h>
#include<stdlib.h>
#include<regex.h>

int tcp_open(){
	char tcp_port[8];
	char inode[128];

	FILE * net_tcp;
	char tcp_data[248];

	regex_t t_preg;
	size_t t_nmatch=15;
	regmatch_t t_pmatch[t_nmatch];
	int i,j;

	//if(regcomp(&t_preg,"([0-9]:)(.+:([0-9]{4}))(.+:.{4})(.+:.+)([0-9]{2}:.{9})([0-9]+)(.+0.+0[^0-9])([0-9]+)(.+)([a-z]{4}.+)",REG_EXTENDED|REG_NEWLINE) != 0 ){


	if(regcomp(&t_preg,"([0-9]:)(.+:(.{4}))(.+:.{4})(.+:.+)([0-9]{2}:.{9})([0-9]{8})(.{16})([0-9]+)(.+)",REG_EXTENDED|REG_NEWLINE) != 0 ){
		fprintf(stderr,"net_tcp regex compile failed");
		exit(1);

	}


	net_tcp=fopen("/proc/net/tcp","r");
		while(fgets(tcp_data,247,net_tcp) != NULL){
			printf("String is %s\n",tcp_data);
			if(regexec(&t_preg,tcp_data,t_nmatch,t_pmatch,0) != 0){
				printf("no match\n");
			}else{
							
				i = t_pmatch[3].rm_eo - t_pmatch[3].rm_so;
				i = i+1;
				snprintf(tcp_port,i,"%s",&tcp_data[t_pmatch[3].rm_so]);

				j = t_pmatch[9].rm_eo - t_pmatch[9].rm_so;
				j = j+1;
				snprintf(inode,j,"%s",&tcp_data[t_pmatch[9].rm_so]);	

				printf("[port=%s,inode=%s]\n",tcp_port,inode);
				
			/*	
				for(i=0;i<t_nmatch;i++){
					printf("Match position = %d, %d, str=",(int)t_pmatch[i].rm_so,(int)t_pmatch[i].rm_eo);
					if(t_pmatch[i].rm_so >= 0 && t_pmatch[i].rm_eo >= 0){
						for(j=t_pmatch[i].rm_so;j<t_pmatch[i].rm_eo;j++){
							putchar(tcp_data[j]);
						}
					}
					printf("\n");
				}*/
			}

			tcp_data[0]='\0';
		}

	fclose(net_tcp);



}


int main(){
	tcp_open();

	return 0;
}
