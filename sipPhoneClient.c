#include <eXosip2/eXosip.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h> 
#include <sys/types.h> 
#include "jauth.h"



//心跳线程
void* keepAliveThread(void * arg)
{
	int 				ret = 0;
	struct sip_data_t * sipData;
	char * 				tmp = (char*)malloc(4096);
	
	sipData =(struct sip_data_t *) arg;
	
	while(!sipData->stop_keepalive)
	{
		if(sipData->registerFlag == 1)//如果没注册成功0，或注销2，都不发送keepalive
		{
			//传送xml消息
			(sipData->sendAliveNum)++;


			ret = getMessageFromFile("./sendMeg/keepalive.txt",tmp); 
			convertMessageToSipMeg(sipData,tmp);


	        eXosip_lock(sipData->context_eXosip);
			sendMessage(sipData,tmp,"Application/MANSCDP+xml");
	        eXosip_unlock(sipData->context_eXosip);
		}

		sleep(60);
	}

	free(tmp);

}




int helpInfo()
{
	printf("1   register to server\n");
    printf("2   cancel register\n");
    printf("3   invite request\n");
    printf("4   hold off the call\n");    
    printf("5   send INFO msg\n");
	printf("6   send xml control msg\n");
	printf("7   send xml control msg as weight random\n");
	printf("8   quit \n");
	printf("0   help\n");
	return 0;
}




int sipPhoneInit(int num)
{
	int ret 				= 0;
	int regFlag				= 0;
	int i					= 0;
	char fileName[100] 		= "";
	int regNum 				= 3;
	pthread_t tid;	//线程号
	struct sip_data_t sipData = {0};

	int tmnum = num;

	
	snprintf(fileName,100,"./config/sipPhone%d.ini",tmnum);

	ret = initSipDataFromFile(fileName,&sipData);
	if(0 != ret)
	{
		printf("init sip fail!\n");
		return -1;
	}

	//注册消息
	regFlag = sipData.registerFlag;
	sipData.registerFlag = 1;
	ret = sipRegister(&sipData);

	while(regNum != 0 && ret != 0)
	{
		ret = sipRegister(&sipData);
		sleep(1);
		regNum--;
	}
	
	if(ret != 0)
	{
		sipData.registerFlag = regFlag;
		printf("register fail -> regNum = %d,ret  =%d\n",regNum,ret);
		sipFree(&sipData);
		return -1;
	}


	sleep(2);
	
	//心跳线程
	ret = pthread_create(&sipData.tid_keepalive,NULL,keepAliveThread,&sipData); 
	if(ret!=0)
	{
		printf("keepalive thread fail\n");
	}

	//响应消息线程
	ret = pthread_create(&sipData.tid_resp,NULL,sipResponseThread,&sipData); 
	if(ret!=0)
	{
		printf("sipResponseThread fail\n");
	}

    return 0;
}



int main(int argc,char *argv[])
{
    int call_id		= 0;
	int dialog_id	= 0;
	int ret 		= 0;
	int flag 		= 0;
	int regFlag		= 0;
	int i			= 0;
	char command;
	char * tmp 		= (char*)malloc(4096);
	char *fileName 	= (char*)malloc(100);
	char *callNumber= (char*)malloc(100);

	pthread_t tid;	//线程号
	struct sip_data_t sipData ;


	


	if(argc > 1)
		snprintf(fileName,100,"./config/%s",argv[1]);
	else
		snprintf(fileName,100,"./config/sipPhone1.ini");

	ret = initSipDataFromFile(fileName,&sipData);
	if(0 != ret)
	{
		printf("init sip fail!\n");
		free(tmp);
		free(fileName);
		return -1;
	}


	//注册消息
	regFlag = sipData.registerFlag;
	sipData.registerFlag = 1;
	ret = sipRegister(&sipData);
	if(ret != 0)
	{
		sipData.registerFlag = regFlag;
		printf("register fail!\n");
		sipFree(&sipData);
		return -1;
	}

	//sleep(2);
	
	//心跳线程
	ret = pthread_create(&tid,NULL,keepAliveThread,&sipData); 
	if(ret!=0)
	{
		printf("keepalive thread fail\n");
	}


	//响应消息线程
	ret = pthread_create(&tid,NULL,sipResponseThread,&sipData); 
	if(ret!=0)
	{
		printf("sipResponseThread fail\n");
	}

	helpInfo();

	
    flag=1;
    while(flag)
    {
        //输入命令
        printf("Please input the command:\n");
        scanf("%c",&command);
        getchar();

        switch(command)
        {
        case '1':
			regFlag = sipData.registerFlag;
			sipData.registerFlag = 1;
			ret = sipRegister(&sipData);	
			if(ret != 0)
				sipData.registerFlag = regFlag;
			break;
		case '2':
			regFlag = sipData.registerFlag;
			sipData.registerFlag = 0;
			ret = sipRegister(&sipData);	
			if(ret != 0)
				sipData.registerFlag = regFlag;		
			break;
        case '3'://INVITE，发起呼叫请求
        	printf("Please input call phone number:\n");
        	scanf("%s",callNumber);
			sipInvite(&sipData, callNumber);
            break;
		case '4':   //挂断
            printf("Holded!\n");
			//printf("cid = %d,did = %d,ret = %d\n",ccid,ddid,ret);
            eXosip_lock(sipData.context_eXosip);

            ret = eXosip_call_terminate(sipData.context_eXosip, sipData.call_id, sipData.dialog_id);
		
			printf("ccid = %d,did = %d,ret = %d\n",  sipData.call_id,  sipData.dialog_id,ret);

			//flag = 0;
			eXosip_unlock(sipData.context_eXosip);
            break;


		case '5': 
			//传输INFO方法
        	printf("Input the INFO message name:\n");
			scanf("%s",tmp);
			snprintf(fileName,100,"./sendMeg/%s.txt",tmp);
			printf("It will send INFO %s\n",fileName);
			
            ret = getMessageFromFile(fileName,tmp); 
			convertMessageToSipMeg(&sipData,tmp);
			sendInfo(&sipData,dialog_id,tmp,"text/plain");
            break;		

		case '6':
            //传送xml消息
			printf("Input the message name:\n");
			scanf("%s",tmp);
			snprintf(fileName,100,"./sendMeg/%s.txt",tmp);
			printf("It will send %s\n",fileName);
			
            ret = getMessageFromFile(fileName,tmp); 
			convertMessageToSipMeg(&sipData,tmp);
			sendMessage(&sipData,tmp,"Application/MANSCDP+xml");
            break;




        case '8':
            eXosip_quit(sipData.context_eXosip);
            printf("Exit the sip Client!\n");
            flag=0;

			sipData.stop_keepalive = 1;
	        sipData.stop_resp = 1;
	        //pthread_join (sipData.tid_keepalive, NULL);
	        //pthread_join (sipData.tid_resp, NULL);
			sipFree(&sipData);
            break;
		case '0':
			helpInfo();
			break;

		default:
			break;
        }
    }

	free(tmp);
	free(fileName);

    return 0;
}




