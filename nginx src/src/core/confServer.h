/*
	Newly added file
*/

#include <stdio.h>
void formHead();
void my_sig(int signo);
void closeServerPort(int sockfd);
void recv_send_data(int new_sockfd);
int parseAndOperate(char* text, int infoLength);
int myServer();
