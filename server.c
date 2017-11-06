/* 

Modified by: Oscar Avellan
StudentID :743342

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <stdint.h>
#include "uint256.h"
#include "sha256.h"


#define MAX_CLIENTS 100

/****************************************************************************************************************/

typedef struct {

	int fd;
	int socket_id;
	uint64_t start;
	BYTE seed[32];
	BYTE target[32];
	BYTE difficulty[9];
	BYTE seed_string[65];
	FILE *fp;
	struct sockaddr_in *serv_addr;
	unsigned short client_port;

} PTHREAD_ARGS;

/****************************************************************************************************************/

void sighandler(int signum);
void *get_in_addr(struct sockaddr *sa);

void getTarget(BYTE *target, char *token, uint32_t mask);
void getSolution(BYTE *soltn, char *token, uint32_t mask);

int doubleHash(BYTE *seed_uint256, BYTE *soltn, BYTE *target,FILE *fp, struct sockaddr_in *serv_addr, unsigned short client_port, int socket_id);

void workMessage(char *buffer, int fd, FILE *fp, struct sockaddr_in *serv_addr, unsigned short client_port, int socket_id);
int solnMessage(char buffer[], FILE *fp, struct sockaddr_in *serv_addr,unsigned short client_port, int socket_id);

void byte64_to_uint256(char *token, BYTE *seed_uint256);
void uint64_to_byte8(BYTE *nonce, uint64_t solution, uint32_t mask);
void uint32_to_byte4(BYTE *difficulty, uint32_t diff, uint32_t mask);
void byte32_to_byte64(BYTE *res, BYTE *hex_value);
char hex_to_ascii(int character);
void copy_struct(PTHREAD_ARGS *args, PTHREAD_ARGS *arguments);

void *findSolution(void *arguments);
void print_to_log(FILE *fp, struct sockaddr_in *addr, unsigned short client_port, char *msg, int socket_id);
int checkFileDescriptor(int fd, fd_set *readfds);

/****************************************************************************************************************/

pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
PTHREAD_ARGS arguments;

/****************************************************************************************************************/
/****************************************************************************************************************/

int main(int argc, char **argv)
{
	FILE *fp = fopen("log.txt","w");

	BYTE erro_okay_msg[41] = "ERRO: OKAY message only used by server\r\n";
	BYTE erro_pong_msg[41] = "ERRO: PONG message only used by server\r\n";
	BYTE pong[7] = "PONG\r\n";
	BYTE okay[7] = "OKAY\r\n";
	BYTE erro[7] = "ERRO\r\n";
	char *connect = "CONNECTED\n";
	char *disconnect = "DISCONNECTED\n";

	int sockfd, newsockfd, portno, clilen;
	char buffer[256];
	struct sockaddr_in serv_addr, cli_addr;
	int n, fdmax;

	fd_set readfds, master;

	FD_ZERO(&master);
	FD_ZERO(&readfds);

	if (argc < 2) 
	{
		fprintf(stderr,"ERROR, no port provided\n");
		exit(1);
	}

	 /* Create TCP socket */
	
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd < 0) 
	{
		perror("ERROR opening socket");
		exit(1);
	}

	
	bzero((char *) &serv_addr, sizeof(serv_addr));

	portno = atoi(argv[1]);
	
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);  
	
	if (bind(sockfd, (struct sockaddr *) &serv_addr,
			sizeof(serv_addr)) < 0) 
	{
		perror("ERROR on binding");
		exit(1);
	}
	
	
	listen(sockfd,MAX_CLIENTS);
	
	clilen = sizeof(cli_addr);

	FD_SET(sockfd,&master);
	fdmax = sockfd;

	int i;

	signal(SIGINT,sighandler);

	while(1){

		readfds = master;

		// Waiting for I/O operation in file descriptors
		if(select(fdmax+1, &readfds,NULL,NULL,NULL) == -1){
			perror("select");
			exit(1);
		}

		for( i = 0; i <= fdmax; i++){
			if(FD_ISSET(i,&readfds)){
				// Main port
				if(i == sockfd){
					
					// Accepting new connection 
					newsockfd = accept(	sockfd, (struct sockaddr *) &cli_addr, (socklen_t *)&clilen);

					if (newsockfd < 0) {
						perror("ERROR on accept");
						exit(1);
					}
					else{
					
                    	print_to_log(fp, &cli_addr, cli_addr.sin_port, connect,newsockfd);
						FD_SET(newsockfd,&master);

						if (newsockfd > fdmax) {    // keep track of the max
                            fdmax = newsockfd;
                        } 
					}
				}
				else{

					bzero(buffer,256);

					if( (n = read(i,buffer,255)) <= 0){
						

						if(n == 0){
							print_to_log(fp, &cli_addr, cli_addr.sin_port, disconnect,i);
						}
						else{
							perror("ERROR reading from socket");
							exit(1);
						}

						close(i);
						FD_CLR(i,&master);
					}
					else{

						print_to_log(fp, &cli_addr, cli_addr.sin_port, buffer,i);

						if( !strncmp(buffer,"PING\r\n",6) ){
							n = write(i,pong,6); 
							print_to_log(fp, &serv_addr, cli_addr.sin_port, (char*)pong,i);

						}		
						else if( !strncmp(buffer,"PONG\r\n",6) ){
							n = write(i,erro_pong_msg,40);
							print_to_log(fp, &serv_addr, cli_addr.sin_port, (char*)erro_pong_msg,i);
						}

						else if( !strncmp(buffer,"OKAY\r\n",6) ){
							n = write(i,erro_okay_msg,40);
							print_to_log(fp, &serv_addr, cli_addr.sin_port, (char*)erro_okay_msg,i);
			
						}

						else if( !strncmp(buffer,"SOLN ",5) ){
							int valid;
							valid = solnMessage(buffer,fp,&serv_addr,cli_addr.sin_port,i);
					
							if(valid)
								n = write(i,okay,6);
							else
								n = write(i,erro,6);
						}
						else if( !strncmp(buffer,"WORK ",5) ){
							workMessage(buffer,i,fp,&serv_addr,cli_addr.sin_port,i);
						
						}
						else
							n = write(i,erro,6); 

						if (n < 0) {
							perror("ERROR writing to socket");
							exit(1);
						}

					}

				}
			}
		}

	}
	
	fclose(fp);
	close(sockfd);
	
	return 0; 
}

/****************************************************************************************************************/
int checkFileDescriptor(int fd, fd_set *readfds){
	if (FD_ISSET(fd,readfds))
		return 1;

	return 0;
}	

/****************************************************************************************************************/

void print_to_log(FILE *fp, struct sockaddr_in *addr, unsigned short client_port, char *msg, int socket_id){
	
	char remoteIP[INET_ADDRSTRLEN], *time_to_string;

	time_t c_time = time(NULL);
    time_to_string = ctime(&c_time);

	fprintf(fp,"%s, SOCKET ID %d,PORT %d, %s: %s\n",inet_ntop(addr->sin_family,get_in_addr((struct sockaddr*)addr),
								remoteIP, INET_ADDRSTRLEN),socket_id,ntohs(client_port), time_to_string,strcat((char*)msg,"\0")); 
}

/****************************************************************************************************************/

void workMessage(char *buffer, int fd,FILE *fp, struct sockaddr_in *serv_addr, unsigned short client_port, int socket_id){

	pthread_t t1;

	char *token,buff[256];
	uint32_t mask = 0x000000ff;
	uint16_t workers_count;
	uint64_t start;
	BYTE target[32], seed_uint256[32], nonce[8];

	uint256_init(target);
	uint256_init(seed_uint256);

	bzero(buff,256);

	memcpy(buff,buffer,strlen(buffer)-2);

	token = strtok(buff," ");

	while( token != NULL ) {

      /* DIFFICULTY uint32 */
      if(strlen(token) == 8){

      	strcpy((char*)arguments.difficulty,token);
      	getTarget(target,token,mask);

      }
      /* SEED BYTE[64] */
      else if(strlen(token) == 64){

      	strcpy((char*)arguments.seed_string,token);
      	byte64_to_uint256(token, seed_uint256);

      }
      /* SOLUTION uint64 */
      else if(strlen(token) == 16){

      	start = (uint64_t) strtol(token,NULL,16);
      	uint64_to_byte8(nonce,start,mask);

      }

      /* Workers Count */
      else if(strlen(token) == 2){
      	workers_count = (uint16_t) strtol(token,NULL,16);
      	
      }
 
      token = strtok(NULL, " ");
    }

    /* Setting elements in the global structure */
    arguments.fp = fp;
    arguments.socket_id = socket_id;
    arguments.serv_addr = serv_addr;
    arguments.client_port = client_port;
    arguments.fd = fd;
    arguments.start = start;

    int i;
    for(i = 0; i < 32 ; i++){
    	arguments.seed[i] = seed_uint256[i];
    	arguments.target[i] = target[i];
    }

    int thread_created;
    thread_created = pthread_create(&t1,NULL,findSolution,(void*)&arguments);
}

/****************************************************************************************************************/
void *findSolution(void *arguments){
	

	PTHREAD_ARGS args;

	pthread_mutex_lock( &mutex1 );
	copy_struct(&args,(PTHREAD_ARGS*)arguments);
	pthread_mutex_unlock( &mutex1 );

	char remoteIP[INET_ADDRSTRLEN];
	
	BYTE nonce[8], nonce_string[17],temp1,temp2,reply[98];
	uint32_t mask = 0x000000ff;

	uint64_to_byte8(nonce,args.start,mask);

	/* Searching for NONCE value */
	while(doubleHash(args.seed,nonce,args.target,NULL,NULL,args.client_port,args.socket_id) != 1){
		args.start = args.start + 1;
		uint64_to_byte8(nonce,args.start,mask);
	}

	/* Converting HEX values to ASCII values */
	int i,j;
	for ( i = 0,j = 0; i < 8; i++, j = j+2)
	{
		temp1 = nonce[i] >> 4;
		nonce_string[j] = hex_to_ascii((int)temp1);
		temp2 = nonce[i] & 0x0f;
		nonce_string[j+1] = hex_to_ascii((int)temp2);  	
	}
	nonce_string[16] = '\0';

	/* Concatenating SOLN + DIFFICULTY + SEED + NONCE */
	strcpy((char*)reply,"SOLN ");
	strcat((char*)reply,(char *)args.difficulty);
	strcat((char*)reply," ");
	strncat((char*)reply,(char *)args.seed_string,65);
	strcat((char*)reply," ");
	strncat((char*)reply,(char*)nonce_string,17);
	strncat((char*)reply,"\r\n",2);
	reply[97] = '\0';

	time_t c_time = time(NULL);
    char *time_to_string;
    time_to_string = ctime(&c_time);

	fprintf(args.fp,"%s, SOCKET ID %d, PORT %d, %s: %s\n",inet_ntop(args.serv_addr->sin_family,get_in_addr((struct sockaddr*)args.serv_addr),
								remoteIP, INET_ADDRSTRLEN),args.socket_id,ntohs(args.client_port), time_to_string,reply);
	
	int n;
	n = write(args.fd,reply,97);

	if(n < 0)
		printf("ERROR WRITING TO SOCKET\n");

	return 0;

}

/****************************************************************************************************************/

void copy_struct(PTHREAD_ARGS *args, PTHREAD_ARGS *arguments){
	
	args->fd = arguments->fd;
	args->socket_id = arguments->socket_id;
	args->start = arguments->start;
	args->fp = arguments->fp;
	args->serv_addr = arguments->serv_addr;
	args->client_port = arguments->client_port;

	int i;
	for(i = 0 ; i < 32 ; i++){
		args->seed[i] = arguments->seed[i];
		args->target[i] = arguments->target[i];
	}

	i = 0;
	for (i = 0; i < 9; i++)
	{
		args->difficulty[i] = arguments->difficulty[i];
	}

	i = 0;
	for (i = 0; i < 65; i++)
	{
		args->seed_string[i] = arguments->seed_string[i];
	}
}

/****************************************************************************************************************/

void uint64_to_byte8(BYTE *nonce, uint64_t solution, uint32_t mask){
	 int i, bit;
    for(i = 7, bit = 0; i > -1; i--, bit = bit+8){
      	nonce[i] = (BYTE) ( (solution >> bit) & mask );
    }
}

/****************************************************************************************************************/

void uint32_to_byte4(BYTE *difficulty, uint32_t diff, uint32_t mask){
	int i, bit;
	for(i = 3, bit = 0; i > -1; i--, bit = bit+8){
      	difficulty[i] = (BYTE) ( (diff >> bit) & mask );
    }
}

/****************************************************************************************************************/

int solnMessage(char buffer[], FILE *fp, struct sockaddr_in *serv_addr, unsigned short client_port, int socket_id){
	
	char *token,buff[256];
	bzero(buff,256);

	uint32_t mask = 0x000000ff;
	BYTE target[32], seed_uint256[32], soltn[8];
	
	/* Initialising uint256 numbers */
	uint256_init(target);
	uint256_init(seed_uint256);
	
	/* Removing /r/n from message */
	memcpy(buff,buffer,strlen(buffer)-2);

	token = strtok(buff," ");

	while( token != NULL ) {

      /* DIFFICULTY uint32 */
      if(strlen(token) == 8){

      	getTarget(target,token,mask);

      }
      /* SEED BYTE[64] */
      else if(strlen(token) == 64){

      	byte64_to_uint256(token, seed_uint256);

      }
      /* SOLUTION uint64 */
      else if(strlen(token) == 16){

      	getSolution(soltn,token,mask);
      	return doubleHash(seed_uint256,soltn,target,fp,serv_addr,client_port,socket_id);

      }
 
      token = strtok(NULL, " ");
    }

    return 0;
   
}

/****************************************************************************************************************/

void getTarget(BYTE *target, char *token, uint32_t mask){
	
	uint32_t difficulty, alpha, beta, mask_a = 0xff000000, mask_b = 0x00ffffff;
	BYTE uint256_beta[32], uint256_base[32], uint256_res[32];

	/* Initialising uint256 numbers */
	uint256_init(uint256_res);
	uint256_init(uint256_beta);
	uint256_init(uint256_base);

	/* Setting a base equals to 2 */
	uint256_base[31] = 0x02;

	difficulty = (uint32_t) strtol(token,NULL,16);

    alpha = (difficulty & mask_a) >> 24;
    alpha = 8*(alpha - 3);

    beta = difficulty & mask_b;

    /* Setting BETA into a uint256 number */
    int i, bits;
    for(i = 31, bits = 0; i > 27; i--, bits += 8){
      	uint256_beta[i] = (beta >> bits) & mask;
    }

    /* 2^( 8*(alpha-3) ) */
    uint256_exp(uint256_res,uint256_base,alpha);
      	
    /* BETA * 2^( 8*(alpha-3) ) */
    uint256_mul(target,uint256_res,uint256_beta);

}

/****************************************************************************************************************/

void byte64_to_uint256(char *token, BYTE *seed_uint256){

	/* Temporary variables to merge SEED BYTE[64] into uint256 */
	char temp[2];
	uint8_t temp1;
	uint8_t temp2;

	int i,j;
    for(i = 0,j = 0; i < 64 ; i = i+2, j++){
      	/* Copy the first character to an empty String */
      	strncpy(temp,token + i,1);
      	temp[1] = '\0';
      	temp1 = (uint8_t) strtol(temp,NULL,16);

      	/* Copy the second character to an empty String */
      	strncpy(temp,token + (i+1), 1);
      	temp[1] = '\0';
      	temp2 = (uint8_t) strtol(temp,NULL,16);

      	/* Shift the first character 4 bits to the left */
      	temp1 = temp1 << 4;

      	/* OR temp1 and temp2 */
      	temp2 = temp1 | temp2;
      	seed_uint256[j] = (BYTE) temp2;
    }
}

/****************************************************************************************************************/

void getSolution(BYTE *soltn,char *token, uint32_t mask){
	
	uint64_t solution;

	solution = (uint64_t) strtol(token,NULL,16);
      	
    /* Setting SOLUTION into an 8 BYTE array */
    int i, bit;
    for(i = 7, bit = 0; i > -1; i--, bit = bit+8){
      	soltn[i] = (BYTE) ( (solution >> bit) & mask );
    }
}

/****************************************************************************************************************/

int doubleHash(BYTE *seed_uint256, BYTE *soltn, BYTE *target,FILE *fp, struct sockaddr_in *serv_addr, unsigned short client_port, int socket_id){
		
		SHA256_CTX ctx;
		BYTE buf1[SHA256_BLOCK_SIZE], buf2[SHA256_BLOCK_SIZE];
		BYTE hash[65],target_s[65];
		char *time_to_string;
		char remoteIP[INET_ADDRSTRLEN];

		/* Double Hash Implementation */	
      	size_t eight_bytes = 8, thirtytwo_bytes = 32;
      	
      	sha256_init(&ctx);

      	/* Double update concatenates SEED and SOLUTION */
      	sha256_update(&ctx, seed_uint256, thirtytwo_bytes);
		sha256_update(&ctx, soltn, eight_bytes);

		sha256_final(&ctx, buf1);
	
		sha256_init(&ctx);
		sha256_update(&ctx, buf1, thirtytwo_bytes);
		sha256_final(&ctx, buf2);

		time_t c_time = time(NULL);
        time_to_string = ctime(&c_time);

        byte32_to_byte64(hash,buf2);
        byte32_to_byte64(target_s,target);


		if(sha256_compare(buf2,target) < 0){
			if(fp && serv_addr){
        	fprintf(fp,"%s, SOCKET ID %d, PORT %d, %s: HASH VALUE 0x%s\n: TARGET     0x%s\n: OKAY\r\n\n",inet_ntop(serv_addr->sin_family,get_in_addr((struct sockaddr*)serv_addr),
								remoteIP, INET_ADDRSTRLEN),socket_id,ntohs(client_port), time_to_string,hash,target_s);
       		}
			return 1;
		}
		else {
			if(fp && serv_addr){
        	fprintf(fp,"%s, SOCKET ID %d, PORT %d, %s: HASH VALUE 0x%s\n: TARGET     0x%s\n: ERRO\r\n\n",inet_ntop(serv_addr->sin_family,get_in_addr((struct sockaddr*)serv_addr),
								remoteIP, INET_ADDRSTRLEN),socket_id,ntohs(client_port), time_to_string,hash,target_s);
       		}
			return 0;
		}
}

/****************************************************************************************************************/
void byte32_to_byte64(BYTE *res, BYTE *hex_value){
	BYTE temp1,temp2;
	int i,j;
	for(i = 0, j = 0; i < 32; i++,j = j+2){
		temp1 = hex_value[i] >> 4;
		res[j] = hex_to_ascii((int)temp1);
		temp2 = hex_value[i] & 0x0f;
		res[j+1] = hex_to_ascii((int)temp2);
	}
	res[64] = '\n';

}
/****************************************************************************************************************/

void sighandler(int signum)
{
	if(signum != SIGPIPE){
		printf("\tSIGNAL caught, Goodbye ... \n");
		exit(0);
	}	
   
}

/****************************************************************************************************************/

void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/****************************************************************************************************************/

char hex_to_ascii(int character){

	if(character == 0)
		return '0';
	if(character == 1)
		return '1';
	if(character == 2)
		return '2';
	if(character == 3)
		return '3';
	if(character == 4)
		return '4';
	if(character == 5)
		return '5';
	if(character == 6)
		return '6';
	if(character == 7)
		return '7';
	if(character == 8)
		return '8';
	if(character == 9)
		return '9';
	if(character == 10)
		return 'a';
	if(character == 11)
		return 'b';
	if(character == 12)
		return 'c';
	if(character == 13)
		return 'd';
	if(character == 14)
		return 'e';
	if(character == 15)
		return 'f';
	
	return '0';
}









