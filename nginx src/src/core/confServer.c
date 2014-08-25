/*
	It is added for communicating with Service4All and PHP. 
	It generate new configuration content and enable it immediately.
*/

#include <signal.h> 
#include <ctype.h>
#include <sys/file.h>
#include <unistd.h>
#include <stdio.h>	
#include <string.h>
#include <stdlib.h> 	 
#include <sys/socket.h>  
#include <sys/types.h>		// for socket 
#include <netinet/in.h>		// for sockaddr_in
#include <string.h> 	
#include <pthread.h>
#include <sys/errno.h>	
#include <libxml/parser.h>	//for xml parsing
#include <libxml/tree.h>
#include <iconv.h>
#include <sys/sem.h>
#include <sys/ipc.h>
#include "confServer.h"
#include <sys/msg.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>  


#define SERVER_PORT 4353
#define BACKLOG 20		// max length of listen queue
#define BUFFER_SIZE 2048

#define BUF (1024*8-10)

#define UPSTREAM 512
#define LOCATION 512

char* Merge(char*,char*,char*);
void ProcessContent(char* ,char* );

FILE *fp = NULL;			// for nginx.conf
FILE *fpsock0 = NULL;		// for closing serverPort(sockfd.ini), created in nginx.c
pthread_mutex_t mutex;		// for modifying nginx.conf

xmlDocPtr infoListDoc = NULL;
xmlNodePtr root = NULL; 

static int recvCount = 0;

static char* upstream = NULL;
static char* location = NULL;

static char user_name[20] ={"sdp\0"};
static char user_group[20]={"\0"};
static char worker_processes[10]={"2\0"};
static char error_log[40]={"logs/error.log\0"};
static char pid[40]="logs/nginx.pid\0";
static char worker_rlimit_nofile[10]="51200\0";
static char use_what[10]="epoll\0";
static char worker_connections[10]="1024\0";
static char before_upstream[500]="include mime.types;\n default_type  application/octet-stream; \n sendfile on; \n keepalive_timeout  65;\n log_format InvokeCounts '$upstream_addr|$request_uri';\n  \0";
static char location_added[1000]="\0";
static char listen_port[10] = "5200";
static char server_name[50] = "121.199.25.81"; // Deployed Node (Ali)
static char head[3000];

static char php_location[2000] ="location ~ \\.php$ { \nroot  html;\n fastcgi_pass  127.0.0.1:9800; \n fastcgi_index  index.php;\n fastcgi_param  SCRIPT_FILENAME /usr/local/nginx-1.4.2-file/html$fastcgi_script_name;\n fastcgi_param  QUERY_STRING  $query_string;\n fastcgi_param  REQUEST_METHOD $request_method;\n fastcgi_param  CONTENT_TYPE  $content_type;\n fastcgi_param  CONTENT_LENGTH  $content_length;\n fastcgi_param  SCRIPT_NAME  $fastcgi_script_name;\n fastcgi_param  REQUEST_URI  $request_uri;\n fastcgi_param  DOCUMENT_URI  $document_uri;\n fastcgi_param  DOCUMENT_ROOT  $document_root;\n fastcgi_param  SERVER_PROTOCOL $server_protocol;\n fastcgi_param  HTTPS  $https if_not_empty;\n fastcgi_param  GATEWAY_INTERFACE  CGI/1.1;\n fastcgi_param  SERVER_SOFTWARE  nginx/$nginx_version;\n fastcgi_param  REMOTE_ADDR  $remote_addr;\n fastcgi_param  REMOTE_PORT  $remote_port;\n fastcgi_param  SERVER_ADDR  $server_addr;\n fastcgi_param  SERVER_PORT  $server_port;\n fastcgi_param  SERVER_NAME  $server_name;\n # PHP only, required if PHP was built with --enable-force-cgi-redirect\n fastcgi_param  REDIRECT_STATUS    200;}\n\0";


static int beta = 1;
static int beta_count = 0;

struct message{          
    long msg_type;  
    char msg_text[BUF];  
};  

union semun{
	int val;
	struct semid_ds* buf; unsigned short* array;
};

/**
	For drp_show
	by xzl
*/
void ProcessContent(char* a ,char* b)
{
	printf("\n---------------------------\n process content \n");
	int p = 0; 
	int flag = 0;
	char str[500];
	int len = strlen(a);
	int i = 0;
	for(i = 0;i < len; i++)
		if( a[i] == '{') break;
	memset(str, 0, sizeof(str));

	while(1)
	{
		i++;
		while(isspace(a[i])) i++;
		
		while(!isspace(a[i]))
		{
			if( a[i] =='}') 
			{
				flag = 1;
				break;
			}
			i++;
		}

		if(flag) break;

		while(isspace(a[i])) i++;

		while(a[i]!=';') str[p++] = a[i++];

		str[p++] = '|'; 
		str[p++] = '/'; 
		str[p] = '\0';
		strcat(str, b);
		strcat(str, "/\n\0");
		p = strlen(str);
	}
	str[p] = '\0';
	printf("\n--------------------\nstr is %s\n",str);

	int fd = open("/usr/local/nginx-1.4.2-file/undeploy.txt", O_WRONLY | O_TRUNC);

	flock(fd, LOCK_EX);
	write(fd, str, sizeof(char)*strlen(str));
	flock(fd, LOCK_UN);		
	close(fd);

	FILE* out = fopen("/usr/local/nginx-1.4.2-file/logs/nginx.pid","r");
	char id[20];
	fscanf(out,"%s",id);
	char cmd[100];
	strcpy(cmd,"kill -39 ");
	strcat(cmd,id);
	printf("\n--------------%s\n",cmd);
	system(cmd);
	fclose(out);	
	
}

/**
	Generate the head of conf file
	by xzl
*/
void formHead()
{
	memset(head,0,sizeof(head));
	strcat(head, "user "); strcat(head, user_name); strcat(head, " "); strcat(head, user_group); strcat(head, ";\n");
	strcat(head, "worker_processes "); strcat(head, worker_processes); strcat(head, ";\n");
	strcat(head, "error_log "); strcat(head, error_log); strcat(head, ";\n");
	strcat(head, "pid "); strcat(head, pid); strcat(head, ";\n");
	strcat(head, "worker_rlimit_nofile "); strcat(head, worker_rlimit_nofile); strcat(head, ";\n");
	strcat(head, "events { use "); strcat(head, use_what); strcat(head, ";\n");
	strcat(head, "worker_connections "); strcat(head, worker_connections); strcat(head, ";\n}\n");
	strcat(head, "http { "); strcat(head, before_upstream); 
}

/**
	Handle signals
	by xzl
*/
void my_sig(int signo)
{
	/* The operation for this signal is to write infoListDoc to applicationList.xml */
	if( signo == 10 )
	{
		int fd = open("/usr/local/nginx-1.4.2-file/applicationList.xml", O_WRONLY);
		flock(fd, LOCK_EX);

		pthread_mutex_lock(&mutex);
		xmlSaveFile("/usr/local/nginx-1.4.2-file/applicationList.xml", infoListDoc);
		pthread_mutex_unlock(&mutex);	

		flock(fd, LOCK_UN);		
		close(fd);
	}
	else
		/*  recieve new conf and make it effective */
		if(signo == 12 )
		{
			pthread_mutex_lock(&mutex); 

			struct message msg;
			memset(msg.msg_text,0,sizeof(msg.msg_text));
			int msgid = msgget(456,IPC_CREAT|0666);			

			if( msgrcv(msgid,&msg,BUF,0,IPC_NOWAIT) == -1 )
				printf("rcv nodeNum failded\n");
			int nodeNum = atoi(msg.msg_text);

			memset(msg.msg_text,0,sizeof(msg.msg_text));
			if( msgrcv(msgid,&msg,BUF,0,IPC_NOWAIT) == -1 )
				printf("rcv user_name failded\n");
			strcpy(user_name,msg.msg_text);

			memset(msg.msg_text,0,sizeof(msg.msg_text));
			if( msgrcv(msgid,&msg,BUF,0,IPC_NOWAIT) == -1 )
				printf("rcv user_group failded\n");
			strcpy(user_group,msg.msg_text);

			memset(msg.msg_text,0,sizeof(msg.msg_text));
			if( msgrcv(msgid,&msg,BUF,0,IPC_NOWAIT) == -1 )
				printf("rcv worker_processes failded\n");
			strcpy(worker_processes,msg.msg_text);

			memset(msg.msg_text,0,sizeof(msg.msg_text));
			if( msgrcv(msgid,&msg,BUF,0,IPC_NOWAIT) == -1 )
				printf("rcv error_log failded\n");
			strcpy(error_log,msg.msg_text);			

			memset(msg.msg_text,0,sizeof(msg.msg_text));
			if( msgrcv(msgid,&msg,BUF,0,IPC_NOWAIT) == -1 )
				printf("rcv pid failded\n");
			strcpy(pid,msg.msg_text);

			memset(msg.msg_text,0,sizeof(msg.msg_text));
			if( msgrcv(msgid,&msg,BUF,0,IPC_NOWAIT) == -1 )
				printf("rcv worker_rlimit_nofile failded\n");
			strcpy(worker_rlimit_nofile,msg.msg_text);

			memset(msg.msg_text,0,sizeof(msg.msg_text));
			if( msgrcv(msgid,&msg,BUF,0,IPC_NOWAIT) == -1 )
				printf("rcv use_what failded\n");
			strcpy(use_what,msg.msg_text);

			memset(msg.msg_text,0,sizeof(msg.msg_text));
			if( msgrcv(msgid,&msg,BUF,0,IPC_NOWAIT) == -1 )
				printf("rcv worker_connections failded\n");
			strcpy(worker_connections,msg.msg_text);

			memset(msg.msg_text,0,sizeof(msg.msg_text));
			if( msgrcv(msgid,&msg,BUF,0,IPC_NOWAIT) == -1 )
				printf("rcv before_upstream failded\n");
			strcpy(before_upstream,msg.msg_text);

			xmlNodePtr temp_Node = NULL;
			temp_Node = root->xmlChildrenNode;

			while(temp_Node != NULL)
			{
				memset(msg.msg_text,0,sizeof(msg.msg_text));
				msgrcv(msgid,&msg,BUF,0,IPC_NOWAIT);

				xmlNodePtr temp_Node_Children = NULL;
				temp_Node_Children = temp_Node->xmlChildrenNode;
				while(temp_Node_Children!=NULL)
				{
					if(xmlStrcmp(temp_Node_Children->name,BAD_CAST"upstream")==0)
					{
						xmlNodeSetContent(temp_Node_Children,(xmlChar*)msg.msg_text);
					}
					temp_Node_Children = temp_Node_Children->next;			
				}
				temp_Node = temp_Node->next;
			}

			memset(msg.msg_text,0,sizeof(msg.msg_text));
			if( msgrcv(msgid,&msg,BUF,0,IPC_NOWAIT) == -1 )
				printf("rcv listen_port failded\n");
			strcpy(listen_port,msg.msg_text);

			memset(msg.msg_text,0,sizeof(msg.msg_text));
			if( msgrcv(msgid,&msg,BUF,0,IPC_NOWAIT) == -1 )
				printf("rcv server_name failded\n");
			strcpy(server_name,msg.msg_text);

			temp_Node = root->xmlChildrenNode;
			while(temp_Node != NULL)
			{
				memset(msg.msg_text,0,sizeof(msg.msg_text));
				msgrcv(msgid,&msg,BUF,0,IPC_NOWAIT);

				xmlNodePtr temp_Node_Children = NULL;
				temp_Node_Children = temp_Node->xmlChildrenNode;
				while(temp_Node_Children!=NULL)
				{
					if(xmlStrcmp(temp_Node_Children->name,BAD_CAST"location")==0)
					{
						xmlNodeSetContent(temp_Node_Children,(xmlChar*)msg.msg_text);
					}
					temp_Node_Children = temp_Node_Children->next;			
				}
				temp_Node = temp_Node->next;
			}

			memset(msg.msg_text,0,sizeof(msg.msg_text));
			if( msgrcv(msgid,&msg,BUF,0,IPC_NOWAIT) == -1 )
				printf("rcv php_location failded\n");
			strcpy(php_location,msg.msg_text);

			memset(msg.msg_text,0,sizeof(msg.msg_text));
			if( msgrcv(msgid,&msg,BUF,0,IPC_NOWAIT) == -1 )
				printf("rcv location_added failded\n");
			strcpy(location_added,msg.msg_text);
			
			bzero(upstream, (1024*UPSTREAM)*sizeof(char));
			bzero(location, (1024*LOCATION)*sizeof(char));
			formHead();
			strcpy(upstream, head);

			temp_Node = root->xmlChildrenNode;

			while(temp_Node != NULL) 
			{	
				if(!xmlStrcmp(temp_Node->name, BAD_CAST"application"))
				{	
					xmlNodePtr subNode = temp_Node->xmlChildrenNode;
					if(!xmlStrcmp(subNode->name, BAD_CAST"upstream"))
					{
						strcat(upstream, xmlNodeGetContent(subNode));
						strcat(upstream, "\n");
					}
					subNode = subNode->next;
					if(!xmlStrcmp(subNode->name, BAD_CAST"location"))
					{	
						strcat(location, xmlNodeGetContent(subNode));
						strcat(location, "\n");
					}
				}
				temp_Node = temp_Node->next;
			}
		
			strcat(location, php_location);
			strcat(location, location_added);			
			
			strcat(upstream, "\n server {\n");
			strcat(upstream, "listen  ");
			strcat(upstream, listen_port);
			strcat(upstream, ";\n");

			strcat(upstream, "server_name  ");
			strcat(upstream, server_name);
			strcat(upstream, ";\n");
			strcat(upstream, "access_log logs/invokeCounts.log InvokeCounts;\n");
			strcat(upstream, "access_log logs/access.log; \n");

			strcat(upstream, location);
			strcat(upstream, "  }\n }\n");

			printf("\n********Nginx.conf********\n%s\n**************************\n",upstream);

			if((fp = fopen("/usr/local/nginx-1.4.2-file/conf/nginx.conf","w")) == NULL)
			{
				printf("Cannot open nginx.conf !\n");
				exit(0);
			}

			fprintf(fp,"%s", upstream);
			fclose(fp);			

			system("/usr/local/nginx-1.4.2-file/sbin/nginx -t -c /usr/local/nginx-1.4.2-file/conf/nginx.conf");
			system("/usr/local/nginx-1.4.2-file/sbin/nginx -s reload");	
			pthread_mutex_unlock(&mutex);

		}
		else
			/* send conf to php */
			if(signo == 34 )
			{
				//semaphore
				int semID = semget(ftok("/usr/local/nginx-1.4.2-file/applicationList.xml",'a'),1,IPC_CREAT|0666);
				if( semID == -1 ) printf("Cannot create semaphore!\n");
				union semun arg;
				arg.val = 1;
				semctl(semID,0,SETVAL,arg);
				struct sembuf buf_1 ={ 0,-1,SEM_UNDO};
				semop(semID,&buf_1,1);

				int msgid = msgget(123,IPC_CREAT|0666);
				
				//send nodeNum
				int nodeNum = 0;
				xmlNodePtr temp = NULL;
				if(root != NULL)
				{					
					temp = root->xmlChildrenNode;
					while(temp!= NULL)
					{
						temp = temp->next;
						nodeNum++;
					}
				}
				struct message msg; memset(msg.msg_text,0,sizeof(msg.msg_text));
				msg.msg_type = 1;  sprintf(msg.msg_text,"%d",nodeNum); 
				msgsnd(msgid,(void*)&msg,strlen(msg.msg_text),IPC_NOWAIT);

				//send user_name
				memset(msg.msg_text,0,sizeof(msg.msg_text));
				msg.msg_type = 1;  strcpy(msg.msg_text,user_name);
				msgsnd(msgid,(void*)&msg,strlen(msg.msg_text),IPC_NOWAIT);

				//send user_group
				memset(msg.msg_text,0,sizeof(msg.msg_text));
				msg.msg_type = 1;  strcpy(msg.msg_text,user_group);
				msgsnd(msgid,(void*)&msg,strlen(msg.msg_text),IPC_NOWAIT);

				//send worker_processes
				memset(msg.msg_text,0,sizeof(msg.msg_text));
				msg.msg_type = 1;  strcpy(msg.msg_text,worker_processes);
				msgsnd(msgid,(void*)&msg,strlen(msg.msg_text),IPC_NOWAIT);

				//send error_log
				memset(msg.msg_text,0,sizeof(msg.msg_text));
				msg.msg_type = 1;  strcpy(msg.msg_text,error_log);
				msgsnd(msgid,(void*)&msg,strlen(msg.msg_text),IPC_NOWAIT);

				//send pid
				memset(msg.msg_text,0,sizeof(msg.msg_text));
				msg.msg_type = 1;  strcpy(msg.msg_text,pid);
				msgsnd(msgid,(void*)&msg,strlen(msg.msg_text),IPC_NOWAIT);

				//send worker_rlimit_nofile
				memset(msg.msg_text,0,sizeof(msg.msg_text));
				msg.msg_type = 1;  strcpy(msg.msg_text,worker_rlimit_nofile);
				msgsnd(msgid,(void*)&msg,strlen(msg.msg_text),IPC_NOWAIT);

				//send use_what
				memset(msg.msg_text,0,sizeof(msg.msg_text));
				msg.msg_type = 1;  strcpy(msg.msg_text,use_what);
				msgsnd(msgid,(void*)&msg,strlen(msg.msg_text),IPC_NOWAIT);

				//send worker_connections
				memset(msg.msg_text,0,sizeof(msg.msg_text));
				msg.msg_type = 1;  strcpy(msg.msg_text,worker_connections);
				msgsnd(msgid,(void*)&msg,strlen(msg.msg_text),IPC_NOWAIT);

				//send before_upstream
				memset(msg.msg_text,0,sizeof(msg.msg_text));
				msg.msg_type = 1;  strcpy(msg.msg_text,before_upstream);
				msgsnd(msgid,(void*)&msg,strlen(msg.msg_text),IPC_NOWAIT);

				//send upstreams
				if(root != NULL)
				{
					temp = root->xmlChildrenNode;
					while( temp != NULL )
					{
						xmlNodePtr temp_upstream = temp->xmlChildrenNode;
						struct message msg;
						msg.msg_type = 1;

						while( temp_upstream != NULL )
						{
							if( !xmlStrcmp(temp_upstream->name,BAD_CAST"upstream") )
							{
								strcpy( msg.msg_text, (char*)xmlNodeGetContent(temp_upstream));
							}
							temp_upstream = temp_upstream->next;
						}

						msgsnd(msgid,(void*)&msg,strlen(msg.msg_text),IPC_NOWAIT);
						temp = temp->next;
					}
				}

				//send listen_port
				memset(msg.msg_text,0,sizeof(msg.msg_text));
				msg.msg_type = 1;  strcpy(msg.msg_text,listen_port);
				msgsnd(msgid,(void*)&msg,strlen(msg.msg_text),IPC_NOWAIT);
				
				//send server_name
				memset(msg.msg_text,0,sizeof(msg.msg_text));
				msg.msg_type = 1;  strcpy(msg.msg_text,server_name);
				msgsnd(msgid,(void*)&msg,strlen(msg.msg_text),IPC_NOWAIT);

				//send locations
				if(root!=NULL)
				{
					temp = root->xmlChildrenNode;
					while( temp!=NULL )
					{
						xmlNodePtr temp_location= temp->xmlChildrenNode;
						struct message msg;
						msg.msg_type = 1;

						while( temp_location != NULL )
						{
							if( !xmlStrcmp(temp_location->name,BAD_CAST"location") )
							{
								strcpy( msg.msg_text, (char*)xmlNodeGetContent(temp_location));
							}
							temp_location = temp_location->next;
						}

						msgsnd(msgid,(void*)&msg,strlen(msg.msg_text),IPC_NOWAIT);
						temp = temp->next;
					}
				}

				//send php_location
				memset(msg.msg_text,0,sizeof(msg.msg_text));
				msg.msg_type = 1;  
				strcpy(msg.msg_text,php_location);
				msgsnd(msgid,(void*)&msg,strlen(msg.msg_text),IPC_NOWAIT);				


				//send location_added
				memset(msg.msg_text,0,sizeof(msg.msg_text));
				msg.msg_type = 1;  
				strcpy(msg.msg_text,location_added);
				msgsnd(msgid,(void*)&msg,strlen(msg.msg_text),IPC_NOWAIT);

				struct sembuf buf_2 ={0,1,SEM_UNDO};
				semop(semID,&buf_2,1);
			}
}


int myServer()
{
	freopen("/usr/local/nginx-1.4.2-file/out.txt","a",stdout);
	//signal registration
	signal(SIGUSR1,my_sig);
	signal(SIGUSR2,my_sig);
	signal(SIGRTMIN,my_sig);

	xmlInitParser();
	xmlKeepBlanksDefault(0); 

	if(infoListDoc == NULL)
	{	
		infoListDoc = xmlParseFile("/usr/local/nginx-1.4.2-file/applicationList.xml");
		root = xmlDocGetRootElement(infoListDoc);
	}	

	int sockfd;
	struct sockaddr_in serverAddr; 	
	bzero(&serverAddr, sizeof (serverAddr));
	serverAddr.sin_family      = AF_INET;		// (TCP/IP)addr family
	serverAddr.sin_port        = htons(SERVER_PORT);
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);	// fill in with local IP addr

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{ 
		perror("Create socket failed !\n"); 
		exit(1); 
	}
		
	if (bind(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) 
	{ 
		printf("Bind port %d failed !\n", SERVER_PORT);
		exit(1); 
	}   
	if(listen(sockfd, BACKLOG) == -1)// server socket begin to listen
	{
		printf("Server listen failed !\n");
	  	exit(1);	
	}
	printf("version: file     listening...\n");

	int lock_mutex = pthread_mutex_init(&mutex, NULL);
	if(lock_mutex != 0)
	{
		printf("Mutex init failed!\n");
	}

	upstream = (char*)malloc((1024*UPSTREAM)*sizeof(char));
	if (upstream == NULL) {
     		printf("**********  upstream malloc failed");
  	   	exit(1);
  	}
	char* upstream2 = upstream; 
	bzero(upstream, (1024*UPSTREAM)*sizeof(char));

	location = (char*)malloc((1024*LOCATION)*sizeof(char)); 
	if (location == NULL) {
     		printf("**********  location malloc failed");
  	   	exit(1);
  	}
	char* location2 = location; 
	bzero(location, (1024*LOCATION)*sizeof(char));

	pthread_t pidShut;	// for shutting down SERVERPORT
	int pthread_shut = pthread_create(&pidShut, NULL, (void*)closeServerPort, (void *)sockfd);
	if (pthread_shut != 0)
	{
		printf("Create closeServerPort thread failed !\n");
		exit(0);
	}
	
	while(1)
	{       
		struct sockaddr_in clientAddr; 
		socklen_t length = sizeof(clientAddr);
		int new_sockfd = accept(sockfd, (struct sockaddr*)&clientAddr, &length);
		if (new_sockfd == -1)
		{
			printf("Server accept failed !\n");
			break;
		}

		// create new thread and communicate
		pthread_t pid;
		int pthread_err = pthread_create(&pid, NULL, (void*)recv_send_data, (void *)new_sockfd);
		
		if (pthread_err != 0)
		{
			printf("Create recv_send_data thread failed !\n");
			exit(0);
		}
		pthread_join(pid, NULL);
	}

	if(upstream2 != NULL)
	{
		free(upstream2);
		upstream2 = NULL;
	}
	if(location2 != NULL)
	{
		free(location2);
		location2 = NULL;
	}

	shutdown(sockfd,2);
	xmlCleanupParser();
	pthread_mutex_destroy(&mutex);
	return 0;	

	
}

void closeServerPort(int sockfd)
{	
	int closeFlag = 0;	// 0:donnot close; 1:to close; 2:already closed
inquery:
	if((fpsock0 = fopen("/usr/local/nginx-1.4.2-file/sockfd.ini","r")) == NULL)
	{
		printf("sockfd.ini not exists !\n");
		exit(0);
	}
	fscanf(fpsock0, "%d", &closeFlag);
    fclose(fpsock0);
	if(closeFlag == 1)
	{
		shutdown(sockfd,2);
		closeFlag = 2;
		exit(0);
	}
	else
	{
		usleep(100000);// 0.1s
		goto inquery;
	}	
}

void recv_send_data(int new_sockfd)
{	
	char buffer[BUFFER_SIZE];
	bzero(buffer, BUFFER_SIZE);
	int fileLength = 0;
	if(recv(new_sockfd, buffer, BUFFER_SIZE, 0) > 0)
	{
		fileLength = atoi(buffer);	
		bzero(buffer, BUFFER_SIZE);
	}
	else 
	{	
		printf("Error in Receiving!\n");
	}

	char* text = (char*)malloc((fileLength+10)*sizeof(char)); 
	if (text == NULL) {
     	printf("**********  text malloc failed");
  	   	exit(1);
  	}
	char* text2 = text;
	bzero(text, (fileLength+10)*sizeof(char));
	
	int recvNo = 0;
	int cnt = 0;
	while ((recvNo = recv(new_sockfd, buffer, BUFFER_SIZE, 0)))
	{
		
		if( recvNo < 0 )
		{
			printf("recv failed! ErrorCode is %d\n",recvNo);
			int sendNo = send(new_sockfd,"@@@@",4,0);
			if(sendNo == -1)
			{		
				printf("Error in sending @@@@ !\n");
			}
			break;
		}		
		
		cnt += recvNo;
		strcat(text,buffer);
		bzero(buffer,BUFFER_SIZE);
		
		if(cnt == fileLength)
		{
			int sendNo = send(new_sockfd,"@@@@",4,0);
			if(sendNo == -1)
			{		
				printf("Error in sending @@@@ !\n");
			}
			break;
		}
	}				

	printf("\n--------------\nfileLength is %d \ntext = \n%s\n-----------\n",fileLength,text);

	pthread_mutex_lock(&mutex);
	int parseNo = 0;
	parseNo = parseAndOperate(text, fileLength);// parse
	pthread_mutex_unlock(&mutex);

	if(parseNo == 2)
	{
		recvCount++;
		printf("recvCount = %d\n", recvCount);
	}  
	if(text2 != NULL)
	{
		free(text2);	
		text2 = NULL;
	}	
	shutdown(new_sockfd,2);
	pthread_exit(NULL);
		  	
}

char* Merge(char* a,char* b,char* res)
{
	int begin=0,i;
	for(i=0;i<strlen(a);i++)
	{
		res[i]=a[i];
		if( a[i]=='{')
			break;
	}

	int j = i+1;
	for(++i;a[i]!='}';i++)
	{
		res[j]=a[i];
		j++;
	}
	res[j]='\n'; j++;

	for(i=0;i<strlen(b);i++)
	{
		if(b[i]=='{') break;
	}
	for(++i;b[i]!='}';i++)
	{
		res[j]=b[i];
		j++;
	}
	res[j]='}'; res[++j]='\0';
	return res;
}

int parseAndOperate(char* text, int infoLength)
{	
	xmlDocPtr doc = NULL;           // define parsing file pointer
	xmlNodePtr curNode = NULL;      // define Node pointer
	xmlNodePtr subroot = NULL; 
	xmlNodePtr subCurNode = NULL;
	xmlKeepBlanksDefault(0); 

	if(infoListDoc == NULL)
	{	
		infoListDoc = xmlParseFile("/usr/local/nginx-1.4.2-file/applicationList.xml");
		root = xmlDocGetRootElement(infoListDoc);
	}

	doc = xmlParseMemory(text,(infoLength+10)*sizeof(char));
	if (doc == NULL ) 
	{		
		printf("Document is null. \n");
		printf("Memory not parsed successfully. \n");
		return -1;
	}	
	subroot = xmlDocGetRootElement(doc); // get root "confInfoSegment"
	if (subroot == NULL)	
	{ 
		printf("Empty information!\n"); 
		if(doc != NULL)
		{
			xmlFreeDoc(doc);
			doc = NULL;
		} 
		return -1; 
	}	

	if (xmlStrcmp(subroot->name, (const xmlChar *) "confInfoSegment")) 
	{	
		printf("Text of the wrong type, subroot node != confInfoSegment");
		if(doc != NULL)
		{
			xmlFreeDoc(doc);
			doc = NULL;
		}
		return -1;
	}
	xmlChar * operationProp;
	operationProp = xmlGetProp(subroot, (xmlChar *)"operation");

	// operation = deploy
	if(strcmp((char *)operationProp, "de") == 0)
	{
		subCurNode = subroot->xmlChildrenNode;
		while(subCurNode != NULL)
		{
			// support for adding a back-end node (scale out), by xzl
			xmlChar* id = xmlGetProp(subCurNode,(xmlChar*)"id");
			int bool_int;
			bool_int = 0;
			xmlNodePtr xzl;
			xzl = root->xmlChildrenNode;
			while(xzl != NULL)
			{
				xmlChar* xzl_id = xmlGetProp(xzl,(xmlChar*)"id");
				if( xmlStrcmp(id,xzl_id) == 0 )
				{
					char str_res[3000];
					bool_int=1;

					xmlNodePtr xzl_upstream = xzl->xmlChildrenNode;
					char* xzl_upstream_content = (char*)xmlNodeGetContent(xzl_upstream);

					xmlNodePtr subCurNode_upstream = subCurNode->xmlChildrenNode;
					char* subCurNode_upstream_content = (char*)xmlNodeGetContent(subCurNode_upstream);

					Merge(xzl_upstream_content,subCurNode_upstream_content,str_res);

					printf("xzl_upstream_content is %s\n",xzl_upstream_content);
					printf("subCurNode_upstream_content is %s\n",subCurNode_upstream_content);
					printf("Merge result is %s\n",str_res);

					xmlNodeSetContent(xzl_upstream,(xmlChar*)str_res);
					break;
				}
				xzl = xzl->next;
			}

			if(!bool_int && !xmlStrcmp(subCurNode->name, BAD_CAST"application"))
			{
				xmlAddChild(root, subCurNode);
			}
			subCurNode = subCurNode->next;
		}
		curNode = root->xmlChildrenNode;
	}
	else if(strcmp((char *)operationProp, "un") == 0)		// operation = undeploy
	{
		xmlChar * idProp;
		xmlChar * appIdProp;
		xmlNodePtr listChildNode = NULL;
		int idExist = 0;

		subCurNode = subroot->xmlChildrenNode;
		while(subCurNode != NULL)
		{
			if(!xmlStrcmp(subCurNode->name, BAD_CAST"remove"))
			{				
				idProp =  xmlGetProp(subCurNode, (xmlChar *)"id");
				idExist = 0;
				listChildNode = root->xmlChildrenNode;	
				while(listChildNode != NULL)
				{
					if(!xmlStrcmp(listChildNode->name, BAD_CAST"application"))
					{
						appIdProp = xmlGetProp(listChildNode, (xmlChar *)"id");
						if(strcmp((char *)idProp, (char *)appIdProp) == 0)
						{
							idExist = 1;
							char name[50];
							strcpy(name,(char*)xmlGetProp(listChildNode,(xmlChar*)"name"));

							xmlNodePtr upstream_node = listChildNode->xmlChildrenNode;
							char* content = (char*)xmlNodeGetContent(upstream_node);

							ProcessContent(content,name);  //enable     2014-7-21-problem: after undeployment, repeated counting

							xmlNodePtr tempNode = NULL;
							tempNode = listChildNode->next;
							xmlUnlinkNode(listChildNode);
							xmlFreeNode(listChildNode);
							listChildNode = tempNode;
							break;
						}
					}
					listChildNode = listChildNode->next;
				}
				if (idExist == 0)
				printf("\n%%%%%%%%%%%\n The node to be undeployed does not exist! \n%%%%%%%%%%%%%%\n");
			}
			subCurNode = subCurNode->next;
		}
		curNode = root->xmlChildrenNode;
		xmlFree(idProp);
		xmlFree(appIdProp);	
	}
	xmlFree(operationProp);
	
	beta_count++;	

	if((beta == 1)||(beta_count % beta == 1))	//create new conf
	{				
		bzero(upstream, (1024*UPSTREAM)*sizeof(char));
		bzero(location, (1024*LOCATION)*sizeof(char));
		formHead();
		strcpy(upstream, head);	
	}

	if(beta_count % beta == 0)//commit new conf
	{	
		while(curNode != NULL) 
		{	
			if(!xmlStrcmp(curNode->name, BAD_CAST"application"))
			{
				xmlNodePtr subNode = curNode->xmlChildrenNode;
				if(!xmlStrcmp(subNode->name, BAD_CAST"upstream"))
				{
					strcat(upstream, xmlNodeGetContent(subNode));
					strcat(upstream, "\n");
				}
				subNode = subNode->next;
				if(!xmlStrcmp(subNode->name, BAD_CAST"location"))
				{	
					strcat(location, xmlNodeGetContent(subNode));
					strcat(location, "\n");
				}
			}
			curNode = curNode->next;
		}
	
		strcat(location,php_location);
		strcat(location,location_added);
	
		strcat(upstream, "\n server {\n");
		strcat(upstream, "listen  ");
		strcat(upstream, listen_port);
		strcat(upstream, ";\n");
		strcat(upstream, "server_name  ");
		strcat(upstream, server_name);
		strcat(upstream, ";\n");
		strcat(upstream, "access_log logs/invokeCounts.log InvokeCounts;\n");
		strcat(upstream, "access_log logs/access.log; \n");
	
		strcat(upstream, location);
		strcat(upstream, "  }\n }\n");

		printf("\n********nginx.conf********\n%s\n**************************\n",upstream);

		if((fp = fopen("/usr/local/nginx-1.4.2-file/conf/nginx.conf","w")) == NULL)
		{
			printf("Cannot open nginx.conf !\n");
			exit(0);
		}

		fprintf(fp,"%s", upstream);
		fclose(fp);

		system("/usr/local/nginx-1.4.2-file/sbin/nginx -t -c /usr/local/nginx-1.4.2-file/conf/nginx.conf");
		system("/usr/local/nginx-1.4.2-file/sbin/nginx -s reload");
	}
	return 2;

}
 

