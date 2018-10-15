#include "sipInterface.h"
#include "osip_md5.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
//#include <netinet/in.h>
#include <winsock2.h>
#include <string.h>
#include <pthread.h>
#include <time.h>


pthread_mutex_t 			mutex;
struct sip_init_data_t   	g_sip_data;
struct statis_data_t    	g_stat_data;


/*���ַ���source�е�s1�Ӵ��滻Ϊs2�ִ�*/
int replace_string(char *result, char *source, char* s1, char *s2)
{
    char *q=NULL;
    char *p=NULL;

	
	if(NULL == result || NULL == source || NULL == s1 || NULL == s2)
		return -1;
	
   
    p=source;
    while((q=strstr(p, s1))!=NULL)
    {
        strncpy(result, p, q-p);
        result[q-p]= '\0';//very important, must attention!
        strcat(result, s2);
        strcat(result, q+strlen(s1));
        strcpy(p,result);
    }
    strcpy(result, p);   

	return 0;
}


/*��XML��Ϣmessage�в��ҹؼ���key��ֵ*/
int findStrFromMessage(char* message, char* key, char* value)
{
	char* ptr;
	int i = 0;
	int len = 0;
	
	if(NULL == message || NULL == key || NULL == value)
		return -1;

	ptr = strstr(message,key);

	if(NULL == ptr)
		return -1;


	len = strlen(key);


	ptr+=(len+1);

	while(*ptr!='\0' && *ptr!='<')
	{
		value[i++]=*ptr;
		ptr++;
	}


	value[i] = '\0';
	return 0;
}



/*���ļ�file��������Ϊmessage data*/
int getMessageFromFile(char *filePath, char *data)  
{  
    FILE *fp;  
    
    int filesize; 
	char* ret ;
	int bufsize= 4096;  
	char *buffer = (char*)malloc(bufsize);

	
    if ((fp=fopen(filePath,"r"))==NULL){  
        printf("open file %s error  \r\n",filePath);  
        return -2;  
    }  

	if(NULL == data)
		return -1;
  
    fseek(fp,0,SEEK_END);  
    filesize = ftell(fp);  


	memset(data,0,filesize+1);  
    rewind(fp);  
    

	//fgets�����ɹ�������buf��ʧ�ܻ�����ļ���β����NULL��
    //������ǲ���ֱ��ͨ��fgets�ķ���ֵ���жϺ����Ƿ��ǳ�������ֹ�ģ�
    //Ӧ�ý���feof��������ferror�������жϡ�  
    while(!feof(fp)){  
        ret = fgets(buffer,bufsize,fp); 
		if(!ret) break;

        strcat(data,buffer);  
    }  
    fclose(fp);  

	free(buffer);
    return 0;  
}  


/*
weight:���鰴Ȩ�ر���ִ�е��¼���š�
size:Ϊ��Ȩ�ص��ܺ�ֵ��Ŀǰ��Ϊ200��Ȩ��֮�Ͳ��ܳ�����ֵ
count:��󷵻�weight������Ч��ŵ�������
*/
int getWeightFromFile(char *filePath, int *weight,int size)  
{  
    FILE *fp;  
	int num 			= 0; //Ϊִ�е��¼���Ϣ���
	int weg 			= 0; //ִ�е�Ȩ�ر���
	int count  			= 0;
	char speator[10] 	= "";
	int i 				= 0;
	int ret 			= 0;

	if(NULL == weight)
		return -1;

	memset(weight,0,size); 

	if ((fp=fopen(filePath,"r"))==NULL){  
        printf("open file %s error! \r\n",filePath);  
        return -1;  
    }  

	
  
    fseek(fp,0,SEEK_END);  
    rewind(fp);  
     
    /*
      numΪ���͵���Ϣ���
	  wegΪ��Ϣ��Ӧ��Ȩ��
    */
    while((ret = fscanf(fp,"%d %s %d",&num,speator,&weg)) == 3){  
		for(i = 0;i<weg;i++)
		{
			weight[count++] = num;
			if(count>=size) 
				return -1;
		}
		
    }  
    fclose(fp);  


    return count;  
}  



/*
��data�������еĸ�ʽ��===SNID===��
ʹ��config�е���Ӧ�����滻,
�˺����費������
*/
int convertMessageToSipMeg( struct sip_data_t * sipData, char *data)  
{  
	char newSNId[20]	= "";
	char SNFlag[20] 	= "===SNID===";
	char devIdFlag[20] 	= "===DEVID===";
	char timeFlag[20] 	= "===SYSTIME===";
	char tmp1[4096]		= {0}; 
	char now[100] 		= {0};
	int  ret 			= 0;
	time_t nowtim;
	struct tm *tm_now ;
	
	time(&nowtim) ;
	tm_now = localtime(&nowtim) ;
	
	
	sprintf(now, "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d",
		tm_now->tm_year+1900, tm_now->tm_mon+1,tm_now->tm_mday, tm_now->tm_hour, 
		tm_now->tm_min, tm_now->tm_sec);
	
	//�滻�ı�message�е�SNid,deviceId
	snprintf(newSNId,20,"%d",sipData->SNId);
	
	strcpy(tmp1,data);
	ret = replace_string(data,tmp1,SNFlag,newSNId);
	
	strcpy(tmp1,data);
	ret = replace_string(data,tmp1,devIdFlag,sipData->clientId);
	
	strcpy(tmp1,data);
	ret = replace_string(data,tmp1,timeFlag,now);
	

    return 0;  
}  


//��ȡ��Ӧ��response���������б�
int getResponseList(char *filePath, char **responseList, int size)  
{  
    FILE *fp;  
	int count  		= 0;
	int i 			= 0;
	int ret 		= 0;
	char tmp[20]	= "";

	if(NULL == responseList)
		return -1;

	if ((fp=fopen(filePath,"r"))==NULL){  
        fprintf(stderr,"open file %s error! \r\n",filePath);  
        return -1;  
    }  

	
  
    fseek(fp,0,SEEK_END);  
    rewind(fp);  

    while((ret = fscanf(fp,"%s",tmp)) == 1)
	{  
		strcpy(responseList[count++],tmp);	
    }  

	fclose(fp);  

    return count;  
}  



/*free���ṹ����������ڴ�*/
int sipFree(struct sip_data_t * sipData)  
{
	int i 				= 0;
	int size			= 100;

	if(NULL == sipData)
	{
		printf("sipFree sipData is NULL\n");
		return -1;
	}
	
	//��ʼ����Ӧ��response���������б�
	for(i = 0;i<size;i++)
	{
		if(NULL != sipData->responseList[i])
		free(sipData->responseList[i]);
	}

	if(NULL != sipData->clientId)
	free(sipData->clientId);
	if(NULL != sipData->clientAdress)
	free(sipData->clientAdress);
	if(NULL != sipData->password)
	free(sipData->password );
	if(NULL != sipData->serverId)
	free(sipData->serverId	);
	if(NULL != sipData->serverAdress)
	free(sipData->serverAdress);
	if(NULL != sipData->userAgent)
	free(sipData->userAgent);
	if(NULL != sipData->logFilePath)
	free(sipData->logFilePath);

	if(NULL != sipData->logFilePath)
	free(sipData->clientPhoneNumber);

	eXosip_quit(sipData->context_eXosip);
        osip_free (sipData->context_eXosip);


	return 0;
}


/*free���ṹ����������ڴ�*/
int initDataFree(struct sip_init_data_t * sipData)  
{

	if(NULL != sipData->clientId)
	free(sipData->clientId);
	if(NULL != sipData->clientAdress)
	free(sipData->clientAdress);
	if(NULL != sipData->password)
	free(sipData->password );
	if(NULL != sipData->serverId)
	free(sipData->serverId	);
	if(NULL != sipData->serverAdress)
	free(sipData->serverAdress);
	if(NULL != sipData->userAgent)
	free(sipData->userAgent);

	if(NULL != sipData->clientPhoneNumber)
	free(sipData->clientPhoneNumber);


	return 0;
}



/*��ʼ��������
�����ļ��еĲ�������ʼ��sipData�ṹ���е��������
�˺���Ҳ�費�ϵظ���*/
int initGlobalSipDataFromFile(char *filePath )  
{  
    FILE *fp;  
	char para[30] 		= ""; 	//������
	char value[30] 		= "";	    //����ֵ
	char speator[30] 	= "";
	int count  			= 0;
	int i 				= 0;
	int ret 			= 0;
	int tmp 			= 0;

	

	g_sip_data.clientId			= (char*)malloc(30);
	g_sip_data.clientAdress		= (char*)malloc(30);
	g_sip_data.password 		= (char*)malloc(30);
	g_sip_data.serverId			= (char*)malloc(30);
	g_sip_data.serverAdress 	= (char*)malloc(30);
	g_sip_data.userAgent 		= (char*)malloc(40);
	g_sip_data.clientPhoneNumber= (char*)malloc(100);
	
	/*�˴����file��û����Ӧֵ��Ĭ��ֵ*/
	g_sip_data.clientPort		= 5060;
	g_sip_data.serverPort		= 5060;
	g_sip_data.SNId				= 1;
	g_sip_data.expire			= 3600;//ע��ʧЧʱ��
	g_sip_data.sendDelay		= 200;//΢��
	g_sip_data.sendRunNumber	= 0;//��Ȩ�ط�������
	sprintf(g_sip_data.clientPhoneNumber,"");


	printf("======Using file : %s init======\r\n",filePath);

	if ((fp=fopen(filePath,"r"))==NULL){  
        printf("open file %s error! \r\n",filePath);  
		initDataFree(&g_sip_data);
        return -1;  
    }  

    fseek(fp,0,SEEK_END);  
    rewind(fp);  
     
    //�ַ����������ݻ�ȡ
    while((ret = fscanf(fp,"%s %s %s",para,speator,value)) == 3)
	{  	
		
        if(0 == strcmp(para,"clientId"))
        {
        	strcpy(g_sip_data.clientId,value);
        }
		else if(0 == strcmp(para,"clientAdress"))
        {
        	strcpy(g_sip_data.clientAdress,value);
        }
		else if(0 == strcmp(para,"password"))
        {
        	strcpy(g_sip_data.password,value);
        }
		else if(0 == strcmp(para,"serverId"))
        {
        	strcpy(g_sip_data.serverId,value);
        }
		else if(0 == strcmp(para,"serverAdress"))
        {
        	strcpy(g_sip_data.serverAdress,value);
        }
		else if(0 == strcmp(para,"userAgent"))
        {
        	strcpy(g_sip_data.userAgent,value);
        }
		else if(0 == strcmp(para,"clientPhoneNumber"))
        {
        	strcpy(g_sip_data.clientPhoneNumber,value);
        }


		//�������Ͳ�����ȡ
		if(0 == strcmp(para,"clientPort"))
		{
			sscanf( value, "%d", &tmp );   
			g_sip_data.clientPort = tmp;
		}
		else if(0 == strcmp(para,"serverPort"))
		{
			sscanf( value, "%d", &tmp );
			g_sip_data.serverPort = tmp;
		}
		else if(0 == strcmp(para,"SNId"))
		{
			sscanf( value, "%d", &tmp );
			g_sip_data.SNId= tmp;
		}
		else if(0 == strcmp(para,"expire"))
		{
			sscanf( value, "%d", &tmp );
			g_sip_data.expire = tmp;
		}
		else if(0 == strcmp(para,"sendDelay"))
		{
			sscanf( value, "%d", &tmp );
			g_sip_data.sendDelay = tmp;
		}
		else if(0 == strcmp(para,"sendRunNumber"))
		{
			sscanf( value, "%d", &tmp );
			g_sip_data.sendRunNumber = tmp;
		}
	
	}


    fclose(fp);  
    return 0;  
}  


/*��ʼ��������
�����ļ��еĲ�������ʼ��sipData�ṹ���е��������
�˺���Ҳ�費�ϵظ���*/
int initSipData(int number, struct sip_data_t * sipData)  
{  
    FILE *fp;  
	char para[30] 		= ""; 	//������
	char value[30] 		= "";	    //����ֵ
	char speator[30] 	= "";
	int count  			= 0;
	int i 				= 0;
	int ret 			= 0;
	int tmp 			= 0;
	int kkk  			= 0;
	int size			= 100;
	int resListNum;

	char lastId[30]		= "";
	int	 lastNum		= 0;

	
	
	if(NULL == sipData)
		return -1;


	sipData->context_eXosip = eXosip_malloc ();
	sipData->clientId		= (char*)malloc(30);
	sipData->clientAdress	= (char*)malloc(30);
	sipData->password 		= (char*)malloc(30);
	sipData->serverId		= (char*)malloc(30);
	sipData->serverAdress 	= (char*)malloc(30);
	sipData->userAgent 		= (char*)malloc(40);
	sipData->logFilePath	= (char*)malloc(100);
	sipData->clientPhoneNumber= (char*)malloc(100);
	
	/*�˴����file��û����Ӧֵ��Ĭ��ֵ*/
	sipData->registerFlag 	= 0; //Ĭ�ϻ�û��ע��
	sipData->sendTotalNum	= 0;
	sipData->sendAliveNum	= 0;
	sipData->recv200OkNum	= 0;
	sipData->recvFailNum	= 0;
	sipData->stop_keepalive = 0;
    sipData->stop_resp = 0;

    strcpy(sipData->clientId,g_sip_data.clientId);
    strcpy(sipData->clientAdress,g_sip_data.clientAdress);
    strcpy(sipData->password,g_sip_data.password);
    strcpy(sipData->serverId,g_sip_data.serverId);
    strcpy(sipData->serverAdress,g_sip_data.serverAdress);
    strcpy(sipData->userAgent,g_sip_data.userAgent);
    strcpy(sipData->clientPhoneNumber,g_sip_data.clientPhoneNumber);
    
	sipData->serverPort = g_sip_data.serverPort;
	sipData->SNId= g_sip_data.SNId;
	sipData->expire = g_sip_data.expire;
	sipData->sendDelay = g_sip_data.sendDelay;
	sipData->sendRunNumber = g_sip_data.sendRunNumber;
	sipData->clientPort = g_sip_data.clientPort+number;



	for(i = 0;i<4;i++)
	{
		lastId[i]=sipData->clientId[16+i];
	}
	lastId[4]='\0';
	lastNum = atoi(lastId); 
	lastNum+=number;

	
	sipData->clientId[16]='\0';
	sprintf(sipData->clientId, "%s%d",sipData->clientId,lastNum);

	//��ʼ����Ӧ��response���������б�
	for(i = 0;i<size;i++)
		sipData->responseList[i] = (char*)malloc(50);
	

	resListNum = getResponseList("./ResponseMeg/responseList.ini", sipData->responseList,size) ;
	sipData->resListNum = resListNum;




    //��ʼ��
    i=eXosip_init(sipData->context_eXosip);

    if(i!=0)
    {
        printf("Couldn't initialize eXosip!\r\n");
		sipFree(sipData);
        return -1;
    }
    

	//���Լ��Ķ˿�ClientPort�������ж˿ڼ���
    ret = eXosip_listen_addr(sipData->context_eXosip, IPPROTO_UDP,NULL,sipData->clientPort,AF_INET,0);
    if(ret != 0)
    {
        eXosip_quit(sipData->context_eXosip);
        printf("Couldn't initialize transport layer!\r\n");
		sipFree(sipData);
        return -1;
    }

	eXosip_set_user_agent(sipData->context_eXosip,sipData->userAgent);


    return 0;  
}  



/*������к���*/
//sip:038804000001@172.16.20.1 //�����ſڻ�
//sip:048804050501@192.168.0.247:5060//���ڻ�
//sip:019999999901@192.168.0.247:5060//����
//sip:019999998801@192.168.0.247:5060//������

int sipInvite(struct sip_data_t * sipData, char* callNumber)  
{   
    char fromuser[256]		={0};  
    char proxy[256]			={0};  
	osip_message_t *invite	=NULL;
    osip_message_t *ack		=NULL;
	int ret 				= 0;
	int flag1 				= 0;
	eXosip_event_t *je;
	char tmp[4096]			={0};



	if(NULL == sipData->context_eXosip || NULL == sipData->clientId || NULL == sipData->clientAdress
		|| NULL == sipData->serverAdress || NULL == sipData->serverId
		|| NULL == sipData->clientPhoneNumber || NULL == callNumber)
		return -1;


    sprintf(proxy,"sip:%s@%s:%d",callNumber,sipData->serverAdress,sipData->serverPort);  
 	sprintf(fromuser,"sip:%s@%s",sipData->clientPhoneNumber,sipData->clientAdress);
	/*sprintf(fromuser, "\"%s\"<sip:%s@%s:%d>",
		sipData->clientPhoneNumber,
		sipData->clientId,
		sipData->clientAdress,
		sipData->clientPort);*/

	//printf("fromuser --> %s\r\n",fromuser);
	//printf("proxy --> %s\r\n",proxy);

	
	snprintf(tmp,4096,
				"v=0\r\n"
				//"o=%s 0 0 IN IP4 %s\r\n"
				"o=000211932910 0 0 IN IP4 %s\r\n"
				"s=Talk session\r\n"
				"c=IN IP4 %s\r\n"
				"t=0 0\r\n"
				"m=audio 9654 RTP/AVP 8 0 2 101\r\n"
				"a=rtpmap:8 PCMA/8000\r\n"
				"a=rtpmap:0 PCMU/8000\r\n"
				"a=rtpmap:2 G726-32/8000\r\n"
				"a=rtpmap:101 telephone-event/8000\r\n"
				"a=fmtp:101 0-16\r\n"
				"a=sendrecv\r\n"
				"m=video 9856 RTP/AVP 96\r\n"
				"a=rtpmap:96 H264/90000\r\n"
				"a=fmtp:96 packetization-mode=1;profile-level-id=4D001E\r\n"
				"a=sendrecv\r\n",
				//sipData->clientId,
				sipData->clientAdress,
				sipData->clientAdress/*,sipData->clientPhoneNumber*/
				);


	ret = eXosip_call_build_initial_invite(sipData->context_eXosip, &invite,proxy,fromuser,NULL,"This is a call invite");
	if(ret!=0)
	{
		printf("Initial INVITE failed!\r\n");
		return -1;
	}

    osip_message_set_body(invite,tmp,strlen(tmp));
    osip_message_set_content_type(invite,"Application/sdp");

    eXosip_lock(sipData->context_eXosip);
    ret = eXosip_call_send_initial_invite(sipData->context_eXosip, invite); //invite SIP INVITE message to send
    eXosip_unlock(sipData->context_eXosip);

    
	return 0;	
} 



/*������invite���ӳɹ��ˣ����ܷ���info��Ϣ*/
int sendInfo(struct sip_data_t * sipData, int dialog_id,char * mes,char * mesType)
{
	osip_message_t *info=NULL;
	int ret = 0;

	if(NULL == sipData->context_eXosip || NULL == mes|| NULL == mesType)
		return -1;

	

	//��ʽ���������趨��mesType = text/plain�����ı���Ϣ;
	ret = eXosip_call_build_info(sipData->context_eXosip, dialog_id, &info);

	if(ret != 0)
	{
		printf("please invite firstly\r\n");
		return -1;
	}
	else
	{
		printf("****send the INFO ****\r\n%s\r\n\r\n",mes);
	}
	
	osip_message_set_body(info, mes, strlen(mes));
	ret = osip_message_set_content_type(info, mesType);
	ret = eXosip_call_send_request(sipData->context_eXosip, dialog_id, info);
	

	return 0;
}


/*
	����MESSAGE������Ҳ���Ǽ�ʱ��Ϣ��
 	MESSAGE���ý������ӣ�ֱ�Ӵ�����Ϣ
 	ÿ����һ��message ��SNID ��Ҫ����
*/
int sendMessage(struct sip_data_t * sipData,char * mes,char * mesType)
{
    osip_message_t *message	=	NULL;
	char fromuser[256]		=	{0};  
    char proxy[256]			=	{0}; 
	int ret 				= 	0;


	if(NULL == sipData->context_eXosip || NULL == sipData->clientId || NULL == sipData->clientAdress
		|| NULL == sipData->serverAdress || NULL == sipData->serverId
		|| NULL == sipData->clientPhoneNumber)
		return -1;

    sprintf(fromuser,"sip:%s@%s",sipData->clientId,sipData->clientAdress); 
    /*sprintf(fromuser, "\"%s\"<sip:%s@%s:%d>",
	sipData->clientPhoneNumber,
	sipData->clientId,
	sipData->clientAdress,
	sipData->clientPort); */

	if(sipData->serverPort > 0)
    	sprintf(proxy,"sip:%s@%s:%d",sipData->serverId,sipData->serverAdress,sipData->serverPort);  
	else
		sprintf(proxy,"sip:%s@%s",sipData->serverId,sipData->serverAdress);
	
	eXosip_message_build_request(sipData->context_eXosip, &message,"MESSAGE",proxy,fromuser,NULL);
	osip_message_set_body(message, mes, strlen(mes));
	osip_message_set_content_type(message, mesType);
	eXosip_message_send_request(sipData->context_eXosip, message);

	//ÿ����һ��message ��SNID ��Ҫ����
	(sipData->SNId)++;
	(sipData->sendTotalNum)++;

	return 0;
}







/*����ע����ϢregisterFlag = 1: ע�� 0 : ע��*/
int sipRegister(struct sip_data_t * sipData)  
  
{   
    char fromuser[256]	={0};  
    char proxy[256]		={0};  
    char route[256]		={0}; 
	char phoneNum[256]	={0}; 
	osip_message_t *reg = NULL;
	eXosip_event_t *je;
	int ret 		= 0;
	int flag1 		= 0;
	int regid		= 0;//ע��id 
	int expire		= 0;
	int regNum		= 3;



	if(NULL == sipData->context_eXosip || NULL == sipData->clientId || NULL == sipData->clientAdress
		|| NULL == sipData->serverAdress || NULL == sipData->serverId
		|| NULL == sipData->clientPhoneNumber)
		return -1;


	
	if(1 == sipData->registerFlag)
	{
		expire = sipData->expire;
	}


	//sprintf(fromuser,"sip:%s@%s",sipData->clientId,sipData->clientAdress);   	

    sprintf(fromuser, "\"%s\"<sip:%s@%s:%d>",
		sipData->clientPhoneNumber,
		sipData->clientId,
		sipData->clientAdress,
		sipData->clientPort); 

	//printf("fromuser = %s\n",fromuser);

	//sprintf(fromuser,"sip:%s@%s",sipData->clientId,sipData->clientAdress); 
	
/*
	if(sipData->serverPort > 0)
    	sprintf(proxy,"sip:%s@%s:%d",sipData->serverId,sipData->serverAdress,sipData->serverPort);  
	else
		sprintf(proxy,"sip:%s@%s",sipData->serverId,sipData->serverAdress);
*/
	sprintf(proxy,"sip:%s:%d",sipData->serverAdress,sipData->serverPort); 


	eXosip_clear_authentication_info(sipData->context_eXosip);  
      
    regid = eXosip_register_build_initial_register(sipData->context_eXosip, 
							fromuser, proxy, NULL, expire, &reg);  




	ret = eXosip_register_send_register(sipData->context_eXosip, regid, reg);
	if(ret !=0)  //����ʧ�ܣ�û��ע��ɹ�
	{
		fprintf(stderr,"[%s,%d]======Register err ret=%d======\r\n",__FUNCTION__,__LINE__,ret);  
    	return -1; 
	}


	//������ע����Ϣ���ȴ�Ӧ��
    flag1=1;
    while(flag1)
    {
    	//Wait for an eXosip event
        je=eXosip_event_wait(sipData->context_eXosip, 2, 200); 
		//je=eXosip_event_wait(sipData->context_eXosip, 0, 50);
        //(��ʱʱ���룬��ʱʱ�����)
		
		
        if(je==NULL)
        {
        	/*if(regNum--)
        	{
        		printf("d %d dd%s\n",regNum,sipData->clientId);
				continue;
        	}*/
        	printf("[%s,%d]======Register timeout(%s)!======\r\n",
				__FUNCTION__,__LINE__,sipData->clientId);
			break;
        }

		
		
		if(EXOSIP_REGISTRATION_SUCCESS == je->type)
		{
			//printf("[%s,%d]======register sccess(%s:%d)!=====\r\n",__FUNCTION__,__LINE__,sipData->clientAdress,sipData->clientPort);
			flag1=0; //�˳�Whileѭ��
			eXosip_event_free(je);
			break;
		}
        else if(EXOSIP_REGISTRATION_FAILURE == je->type)   //���ܻᵽ�����¼�����
        {
			if(je->response && je->response->status_code==401)  
			{  
				char realm[256]; 
				osip_message_t *reg = NULL; 
				osip_www_authenticate_t *dest = NULL;  
				HASHHEX pwd_md5;
				

				//���ݷ��������ص�Я����Ȩ��Ϣ�����·�ע������
				eXosip_lock(sipData->context_eXosip);	
				
				osip_message_get_www_authenticate(je->response,0,&dest);  
				if(dest == NULL) 
					{
					eXosip_event_free(je);
				  	continue; 
					}
				 
				eXosip_clear_authentication_info(sipData->context_eXosip);  
				strcpy(realm,osip_www_authenticate_get_realm(dest));  
					
				
				DigestCalcMD5(sipData->password, pwd_md5);
				eXosip_add_authentication_info(sipData->context_eXosip,
						sipData->clientId,sipData->clientId,pwd_md5, "MD5",realm);  


				eXosip_register_build_register(sipData->context_eXosip, je->rid, expire, &reg);  
				if(reg==NULL)  
				{  
					fprintf(stderr,"[%s,%d]======eXosip_register_build_register fail=====\r\n",__FUNCTION__,__LINE__); 
					eXosip_event_free(je);

					continue;  
				}  

				eXosip_register_send_register(sipData->context_eXosip, je->rid,reg);	
				eXosip_unlock(sipData->context_eXosip);   
			  
			}  
			else
			{
				fprintf(stderr,"[%s,%d]======register other response(%s:%d)!======\r\n\r\n",__FUNCTION__,__LINE__,sipData->clientAdress,sipData->clientPort); 
				eXosip_event_free(je);
				break;
			}
        }
		
        eXosip_event_free(je);
    }

	fflush(stdout);
	fflush(stderr);

	if(flag1)
		return -2;//����ȷ�ķ��أ�û��ע��ɹ�
	else
		return 0; //ע��ɹ�
} 



/*��Ϊ�������˵ĵ��ã����յ�ע����Ϣ��
	1.�ظ�401����Ȩ��Ϣ��
	2.�ظ�200 OK ��Ϣ��ϵͳʱ��*/
void SendRegisterAnswer(struct eXosip_t *context_eXosip, eXosip_event_t *je, int status)
{
	osip_message_t *answer = NULL;
	int ret = 0;
	const char *const realm = "14000";

	
	eXosip_lock(context_eXosip);
	ret = eXosip_message_build_answer(context_eXosip,je->tid, status, &answer);

	if (status == 401)
	{
		char hvalue[128] 	= {0};
		char now[128] 		= {0};
		HASHHEX nonce;
		HASHHEX opaque;
		time_t nowtim ;
        struct tm *tm_now ;

        time(&nowtim) ;
        tm_now = localtime(&nowtim) ;
		
		sprintf(now, "%ld", time(NULL));
		DigestCalcMD5(now, nonce);
		
		sprintf(now, "%ld", time(NULL));
		DigestCalcMD5(now, opaque);
		sprintf(hvalue, "Digest realm=\"%s\",qop=\"%s\",nonce=\"%s\",opaque=\"%s\"", realm, "auth,auth-int", nonce, opaque);
		osip_message_set_www_authenticate(answer, hvalue);

		
		sprintf(now, "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d\r\n",
		    tm_now->tm_year+1900, tm_now->tm_mon+1,tm_now->tm_mday, tm_now->tm_hour, 
		    tm_now->tm_min, tm_now->tm_sec);

		osip_message_set_header(answer, "time", now);
		
		//osip_message_set_body(answer, now, strlen(now));
		//osip_message_set_content_type(answer, "Application/TIME");
		//printf("1.server send 401 packet\r\n");
	}
	else if (status == 200)
	{

		time_t nowtim ;
        struct tm *tm_now ;
		char now[128] = {0};

        time(&nowtim) ;
        tm_now = localtime(&nowtim) ;
		
		
		sprintf(now, "%.4d-%.2d-%.2d %.2d:%.2d:%.2d\r\n",
					tm_now->tm_year+1900, tm_now->tm_mon+1,tm_now->tm_mday, tm_now->tm_hour, 
					tm_now->tm_min, tm_now->tm_sec);
				

		osip_message_set_header(answer, "time", now);
		//osip_message_set_body(answer, now, strlen(now));
		//osip_message_set_content_type(answer, "Application/TIME");
		//printf("2.server send 200 packet\r\n");
	}

	if (ret != 0)
	{
		eXosip_message_send_answer(context_eXosip, je->tid, 400, NULL);
	}
	else
	{
		eXosip_message_send_answer(context_eXosip, je->tid, status, answer);
	}
	eXosip_unlock(context_eXosip);
}



//ʹ�÷���������Ϣ���SNID
int convertMessageForResponse( struct sip_data_t * sipData, char *data, char *snid)  
{  
	char newSNId[20]	=	"";
	char SNFlag[20] 	= 	"===SNID===";
	char devIdFlag[20] 	= 	"===DEVID===";
	char tmp1[4096]		=	{0}; 
	char tmp2[4096]		=	{0}; 
	int ret = 0;


	strcpy(tmp1,data);

	//�滻�ı�message�е�SNid
	ret = replace_string(tmp2,tmp1,SNFlag,snid);

	//�滻�ı�message�е�clientId
	ret = replace_string(tmp1,tmp2,devIdFlag,sipData->clientId);

	strcpy(data,tmp1);
    return 0;  
}  



/*
���յ�Message��������
�������󲻶�����
�˺���Ҳ�費�ϸ���
*/
int sipMessageResponse(struct sip_data_t * sipData,eXosip_event_t *je)
{
	
	int ret 				= 0;
	int i   				= 0;
	int flag 				= 0;
	char tmp[4096]			= {0};	
	char CmdType[100]		= "CmdType";
	char Cmd[100] 			= "";
	char SN[10]				= "SN";
	char SNId[100]			= "";
	char Response[10]		= "Response";
	char ResponseValue[100]	= "";
	char Notify[10]			= "Notify";
	char NotifyValue[100]	= "";
	char *fileName 			= (char*)malloc(100);

	osip_body_t *body;
	osip_message_t *answer	= NULL;


	//fprintf(stderr,"######receive a message #####\r\n");
	
	if (MSG_IS_MESSAGE (je->request))
	{
		/*�ͻ���: ������ܵ�����Ϣ������MESSAGE*/
		osip_message_get_body (je->request, 0, &body);
		//fprintf(stderr,"The coming msg body is: \r\n%s\r\n", body->body);

		/*1.���չ�����Ҫ�ظ�OK��Ϣ*/
		eXosip_message_build_answer (sipData->context_eXosip,je->tid, 200,&answer);
		eXosip_message_send_answer (sipData->context_eXosip,je->tid, 200,answer);


		/*2.�����response ��Ϣ������Ҫ��һ�������ظ�*/
		ret = findStrFromMessage(body->body,Response,ResponseValue);
		if(0 == ret)
		{
			//fprintf(stderr,"This is a Response message\r\n");
			free(fileName);
			return 0;
		}

		/*2.�����notify ��Ϣ������Ҫ��һ�������ظ�*/
		ret = findStrFromMessage(body->body,Notify,NotifyValue);
		if(0 == ret)
		{
			fprintf(stderr,"This is a Notify(like keepalive) message\r\n");
			free(fileName);
			return 0;
		}



		findStrFromMessage(body->body,CmdType,Cmd);
		findStrFromMessage(body->body,SN,SNId);

		/*3.���ݽ��յ�����Ϣ�壬��ȡ���е�SNId,Ȼ���һ���ظ���Ӧ��Ϣrespnse*/


		for(i = 0;i < sipData->resListNum;i++)
		{
			if(0==strcmp(Cmd,sipData->responseList[i]))
			{
				snprintf(fileName,100,"./ResponseMeg/%s.txt",Cmd);
				getMessageFromFile(fileName,tmp);
				convertMessageForResponse(sipData,tmp,SNId);
				flag = 1;
				break;
			}

		}


		if(flag)
		{
			sendMessage(sipData,tmp,"Application/MANSCDP+xml");
		}


	}


	
	else if (MSG_IS_REGISTER(je->request))
	{
		/*��������: �˴�����Ϊ�������˽��յ�ע�������Ĵ���*/
	
		osip_authorization_t *auth = NULL;
		osip_message_get_authorization(je->request, 0, &auth);

		/*1.���û�м�Ȩ��Ϣ�ظ�401���ģ��ظ��ı�����Я���������ļ�Ȩ��Ϣ*/
		if (auth == NULL) 
		{
			SendRegisterAnswer(sipData->context_eXosip,je, 401);
		}
		else
		{
			char *username = NULL;
			char *realm = NULL;
			char *nonce = NULL;
			char *nonce_count = NULL;
			char *cnonce = NULL;
			char *qop = NULL;
			char *uri = NULL;
			char *response = NULL;

			char *pszAlg = "MD5";
			char *pszUserName = NULL;
			char *pszRealm = NULL;
			HASHHEX pszPassword;
			
			char *pszNonce = NULL;
			char *pszNonceCount = NULL;
			char *pszCNonce = NULL;
			char *pszQop = NULL;
			char *pszDigestUri = NULL;
			char *pszResponse = NULL;
			HASHHEX HA1;
			HASHHEX Response;


			/*2.����м�Ȩ��Ϣ��Ա���Я���ļ�Ȩ��Ϣ�����ж�*/

			DigestCalcMD5(sipData->password, pszPassword);

			username = osip_authorization_get_username(auth);
			if (username)
			{
				pszUserName = osip_strdup_without_quote(username);
			}
			realm = osip_authorization_get_realm(auth);
			if (realm)
			{
				pszRealm = osip_strdup_without_quote(realm);
			}
			nonce = osip_authorization_get_nonce(auth);
			if (nonce)
			{
				pszNonce = osip_strdup_without_quote(nonce);
			}
			nonce_count = osip_authorization_get_nonce_count(auth);
			if (nonce_count)
			{
				pszNonceCount = osip_strdup_without_quote(nonce_count);
			}
			cnonce = osip_authorization_get_cnonce(auth);
			if (cnonce)
			{
				pszCNonce = osip_strdup_without_quote(cnonce);
			}
			qop = osip_authorization_get_message_qop(auth);
			if (qop)
			{
				pszQop = osip_strdup_without_quote(qop);
			}
			uri = osip_authorization_get_uri(auth);
			if (uri)
			{
				pszDigestUri = osip_strdup_without_quote(uri);
			}

			
			DigestCalcHA1(pszAlg, pszUserName, pszRealm, pszPassword, pszNonce, pszCNonce, HA1);
			DigestCalcResponse(HA1, pszNonce, pszNonceCount, pszCNonce, pszQop, 0, je->request->sip_method, pszDigestUri, NULL, Response);
			response = osip_authorization_get_response(auth);
			if (response)
			{
				pszResponse = osip_strdup_without_quote(response);
			}

			//printf("pszRes = %s\r\n Resp = %s\r\n", pszResponse, Response);

			
			if (strcmp(pszResponse, Response) == 0)
			{
				osip_via_t *via = NULL;

				osip_message_get_via(je->request, 0, &via);
				if (via)
				{
					
					osip_generic_param_t *received = NULL;
					osip_generic_param_t *rport = NULL;

					fprintf(stderr,"user:%s, host:%s, port:%s\r\n", pszUserName, via->host, via->port);


					osip_via_param_get_byname(via, "received", &received);
					osip_via_param_get_byname(via, "rport", &rport);
					if (received && rport)
					{
						//fprintf(stderr,"ip:%d, port:%d\r\n", received->gvalue, rport->gvalue);
					}
				}

				/*3.��Ȩ�ɹ����ظ�200 OK*/
				fprintf(stderr,"I will send 200 OK\r\n");
				SendRegisterAnswer(sipData->context_eXosip,je, 200);
			}
			else
			{
				/*3.��Ȩʧ�ܣ��ظ�403 ����*/
				fprintf(stderr,"user name pass error\r\n");
				fprintf(stderr,"I will send 403 error\r\n");
				SendRegisterAnswer(sipData->context_eXosip,je, 403);
			}
		}
	}

	fflush(stdout);
	fflush(stderr);
	free(fileName);

	
	return 0;
}


//���յ���Ϣ���������߳�
void* sipResponseThread(void * arg)
{
	int ret 					= 0;
	int call_id 				= 0;
	int dialog_id 				= 0;
	char tmp[4096]				= {0};
    int pos 					= 0;
	eXosip_event_t *je;
	osip_message_t *ack			= NULL;
	osip_message_t *answer 		= NULL;
	sdp_message_t *remote_sdp 	= NULL;
    osip_body_t *body;
	char remoteIp[50]			= {0};
	char remoteVideoPort[50]	= {0};
	char remoteAudioPort[50]	= {0};
	char *cmd 					= (char*)malloc(200);
	struct sip_data_t * sipData;
	
	sipData =(struct sip_data_t *) arg;


	while(!sipData->stop_resp)
    {
        //�����Ƿ�����Ϣ����
		je = eXosip_event_wait (sipData->context_eXosip, 0, 50);
		//û�н��յ���Ϣ
		if (je == NULL)
            continue;
		
        eXosip_lock (sipData->context_eXosip);
        eXosip_default_action (sipData->context_eXosip,je);	
        //eXosip_automatic_action(sipData->context_eXosip);
	
        //printf("jeeeee type =%d\r\n",je->type);
        switch (je->type)
        {
		/*1.invite:��Ϊ�������ˣ��յ�һ��INVITE����*/
		case EXOSIP_CALL_INVITE:	
			call_id = je->cid;
			dialog_id = je->did;
			
			//�õ����յ���Ϣ�ľ�����Ϣ
			fprintf(stderr,"1Received a INVITE msg ,send to %s:%s, UserName is %s, password is %s\r\n",
					je->request->req_uri->host,
					je->request->req_uri->port, 
					je->request->req_uri->username, 
					je->request->req_uri->password);


			{
				sdp_connection_t * sdp_Cont;
				sdp_media_t * sdp_med;
				sdp_media_t * sdp_aud;


				//�õ���Ϣ��,��Ϊ����Ϣ����SDP��ʽ.
				remote_sdp = eXosip_get_remote_sdp (sipData->context_eXosip,je->did);
				
				sdp_Cont = eXosip_get_video_connection(remote_sdp);


				printf("[remote_sdp]v_version =%s,o_username =%s,o_sess_version =%s,\no_addr =%s,o_addrtype =%s,s_name =%s,\n\n",
					remote_sdp->v_version,remote_sdp->o_username,remote_sdp->o_sess_version,
					remote_sdp->o_addr,remote_sdp->o_addrtype,remote_sdp->s_name);


				printf("[connection]c_nettype =%s,c_addrtype =%s,c_addr =%s,\n\n",
					sdp_Cont->c_nettype,sdp_Cont->c_addrtype,sdp_Cont->c_addr);


				sdp_med = eXosip_get_video_media(remote_sdp);
				sdp_aud = eXosip_get_audio_media(remote_sdp);
				printf("[video]m_media =%s,m_port =%s,\m_proto = %s,\n\n",
									sdp_med->m_media,sdp_med->m_port,sdp_med->m_proto);
				pos=0;
				//��ʾ����sdp��Ϣ���е�attribute ������
				printf ("[video]the sdp a_attributes is :\r\n\n");
				while (!osip_list_eol ( &(sdp_med->a_attributes), pos))
				{
					//���������Ϊʲô��SDP��Ϣ��������a�����ű���������
					sdp_attribute_t *at;
					at = (sdp_attribute_t *) osip_list_get ( &sdp_med->a_attributes, pos);
					printf ("%s : %s\r\n", at->a_att_field, at->a_att_value);
					pos ++;
				}

				printf("[audio]m_media =%s,m_port =%s,\m_proto = %s\n\n",
									sdp_aud->m_media,sdp_aud->m_port,sdp_aud->m_proto);

				
				pos=0;
				//��ʾ����sdp��Ϣ���е�attribute ������
				printf ("[audio]the sdp a_attributes is :\r\n");
				while (!osip_list_eol ( &(sdp_aud->a_attributes), pos))
				{
					sdp_attribute_t *at;
	
					at = (sdp_attribute_t *) osip_list_get ( &sdp_aud->a_attributes, pos);
					printf ("%s : %s\r\n", at->a_att_field, at->a_att_value);//���������Ϊʲô��SDP��Ϣ��������a�����ű���������
	
					pos ++;
				}

				printf("1remoteIp = %s,remoteVideoPort = %s,remoteAudioPort = %s\n",
					sdp_Cont->c_addr,sdp_med->m_port,sdp_aud->m_port);

				sprintf(remoteIp,"%s",sdp_Cont->c_addr);
				sprintf(remoteVideoPort,"%s",sdp_med->m_port);
				sprintf(remoteAudioPort,"%s",sdp_aud->m_port);

				printf("2remoteIp = %s,remoteVideoPort = %s,remoteAudioPort = %s\n",
					remoteIp,remoteVideoPort,remoteAudioPort);


			}


			//eXosip_lock (sipData->context_eXosip);
			eXosip_call_send_answer (sipData->context_eXosip,je->tid, 180, NULL);
			ret = eXosip_call_build_answer (sipData->context_eXosip,je->tid, 200, &answer);
			if (ret != 0)
			{
				fprintf(stderr,"This request msg is invalid!Cann't response!\r\n");
				eXosip_call_send_answer (sipData->context_eXosip,je->tid, 400, NULL);
			}
			else
			{
				snprintf (tmp, 4096,
						  "v=0\r\n"
						  "o=anonymous 0 0 IN IP4 0.0.0.0\r\n"
						  "t=1 10\r\n"
						  "a=username:rainfish\r\n"
						  "a=password:123\r\n");

				//���ûظ���SDP��Ϣ��,��һ���ƻ�������Ϣ��
				//û�з�����Ϣ�壬ֱ�ӻظ�ԭ������Ϣ����һ�����Ĳ��á�
				osip_message_set_body (answer, tmp, strlen(tmp));
				osip_message_set_content_type (answer, "application/sdp");

				eXosip_call_send_answer (sipData->context_eXosip, je->tid, 200, answer);
				printf ("   <==send 200 over!==>\r\n");
			}
			//eXosip_unlock (sipData->context_eXosip);

			break;

		/*2.invite �ͻ��ˣ�����5��call��Ϣ���յ�����������������Ӧ��Ϣ*/
       case EXOSIP_CALL_PROCEEDING: //�յ�100 trying��Ϣ����ʾ�������ڴ�����
            printf("   <==Receive call proceeding(100 trying)!==>\r\n");
			sipData->recv100Flag = 1;
			break;
        case EXOSIP_CALL_RINGING:   //�յ�180 RingingӦ�𣬱�ʾ���յ�INVITE�����UAS�����򱻽��û�����
			sipData->recv180Flag = 1;
			printf("   <==Receive call ringing(180 ringing)!==>\r\n");
            //printf("call_id is %d,dialog_id is %d \r\n",je->cid,je->did);
			sipData->call_id = je->cid;
            sipData->dialog_id = je->did;


			{
				sdp_connection_t * sdp_Cont;
				sdp_media_t * sdp_med;
				sdp_media_t * sdp_aud;


				//�õ���Ϣ��,��Ϊ����Ϣ����SDP��ʽ.
				remote_sdp = eXosip_get_remote_sdp (sipData->context_eXosip,je->did);
				
				sdp_Cont = eXosip_get_video_connection(remote_sdp);

				/*
				printf("[remote_sdp]v_version =%s,o_username =%s,o_sess_version =%s,\no_addr =%s,o_addrtype =%s,s_name =%s,\n\n",
					remote_sdp->v_version,remote_sdp->o_username,remote_sdp->o_sess_version,
					remote_sdp->o_addr,remote_sdp->o_addrtype,remote_sdp->s_name);


				printf("[connection]c_nettype =%s,c_addrtype =%s,c_addr =%s,\n\n",
					sdp_Cont->c_nettype,sdp_Cont->c_addrtype,sdp_Cont->c_addr);

				*/
				sdp_med = eXosip_get_video_media(remote_sdp);
				sdp_aud = eXosip_get_audio_media(remote_sdp);

				//printf("[video]m_media =%s,m_port =%s,\m_proto = %s,\n\n",
				//					sdp_med->m_media,sdp_med->m_port,sdp_med->m_proto);
				pos=0;
				//��ʾ����sdp��Ϣ���е�attribute ������
				//printf ("[video]the sdp a_attributes is :\r\n\n");
				while (!osip_list_eol ( &(sdp_med->a_attributes), pos))
				{
					//���������Ϊʲô��SDP��Ϣ��������a�����ű���������
					sdp_attribute_t *at;
					at = (sdp_attribute_t *) osip_list_get ( &sdp_med->a_attributes, pos);
					//printf ("%s : %s\r\n", at->a_att_field, at->a_att_value);
					pos ++;
				}

				/*printf("[audio]m_media =%s,m_port =%s,\m_proto = %s\n\n",
									sdp_aud->m_media,sdp_aud->m_port,sdp_aud->m_proto);
				*/
				
				pos=0;
				//��ʾ����sdp��Ϣ���е�attribute ������
				//printf ("[audio]the sdp a_attributes is :\r\n");
				while (!osip_list_eol ( &(sdp_aud->a_attributes), pos))
				{
					sdp_attribute_t *at;
					at = (sdp_attribute_t *) osip_list_get ( &sdp_aud->a_attributes, pos);
					//printf ("%s : %s\r\n", at->a_att_field, at->a_att_value);
					pos ++;
				}


				/*
				printf("3remoteIp = %s,remoteVideoPort = %s,remoteAudioPort = %s\n",
									sdp_Cont->c_addr,sdp_med->m_port,sdp_aud->m_port);
				*/
				sprintf(remoteIp,"%s",sdp_Cont->c_addr);
				sprintf(remoteVideoPort,"%s",sdp_med->m_port);
				sprintf(remoteAudioPort,"%s",sdp_aud->m_port);

				/*
				printf("4remoteIp = %s,remoteVideoPort = %s,remoteAudioPort = %s\n",
					remoteIp,remoteVideoPort,remoteAudioPort);
				*/

			}

			snprintf(cmd, 200, "start /min cmd /k  \"ffmpeg -re -i hldwm.264 -vcodec copy -f rtp rtp://%s:%s>video.sdp \"", remoteIp,remoteVideoPort);
			//printf(cmd);
			system(cmd);
			sipData->mediaSendFlag = 1;
			
            break;
		case EXOSIP_CALL_ANSWERED: //�յ�200 OK����ʾ�����Ѿ����ɹ����ܣ��û�Ӧ��
            printf("   <==call connected(200 OK)!==>\r\n");
			sipData->recv200Flag = 1;
			sipData->call_id = je->cid;
            sipData->dialog_id = je->did;
            //printf("!!call_id is %d,dialog_id is %d \r\n",je->cid,je->did);

            //����ackӦ����Ϣ
            eXosip_call_build_ack(sipData->context_eXosip, je->did, &ack);
            eXosip_call_send_ack(sipData->context_eXosip, je->did, ack);
            //flag1=0; //�Ƴ�Whileѭ��
            break;

		case EXOSIP_CALL_CLOSED:
            printf ("   <==The remote hold the session!==>\r\n");
            
			ret = eXosip_call_build_answer (sipData->context_eXosip, je->tid, 200, &answer);
            if (ret != 0)
            {
                //printf ("This request msg is invalid!Cann't response!\r\n");
                eXosip_call_send_answer (sipData->context_eXosip, je->tid, 400, NULL);
            }
            else
            {
                eXosip_call_send_answer (sipData->context_eXosip, je->tid, 200, answer);
                printf ("   <==Bye send 200 over!==>\r\n");
				if(sipData->mediaSendFlag)
				{
					system("taskkill /f /im ffmpeg.exe");
					system("taskkill /f /im cmd.exe");
					sipData->mediaSendFlag = 0;
				}
            }
            break;
        case EXOSIP_CALL_ACK: //ACK received for 200ok to INVITE
            printf("   <==ACK received!==>\r\n");
            break;
		
		case EXOSIP_CALL_RELEASED:
			printf("   <==Call context is cleared!==>\r\n");
			break;
		case EXOSIP_CALL_REQUESTFAILURE:
			printf("   <==Call request is failure!==>\r\n");
			break;
		//����û�Ӿ�ֱ�ӹһ�
		case EXOSIP_CALL_GLOBALFAILURE:
			printf("   <==Remote reject the call==>\r\n");

			if(sipData->mediaSendFlag)
			{
				system("taskkill /f /im ffmpeg.exe");
				system("taskkill /f /im cmd.exe");
				sipData->mediaSendFlag = 0;
			}
			break;

			
		/*3.register:��Ϊ�ͻ��ˣ��յ�һ���������ķ�����Ϣ����*/
        case EXOSIP_REGISTRATION_SUCCESS:// ע��ɹ�
            //fprintf(stderr,"[%s,%d]======register sccess!=====\n",__FUNCTION__,__LINE__);	 
            //fprintf(stderr,"je->rid=%d\n", je->rid);
            break;

        case EXOSIP_REGISTRATION_FAILURE:// ע��ʧ��
			//fprintf(stderr,"[%s,%d]======register fail ======\n",__FUNCTION__,__LINE__);	
            //fprintf(stderr,"je->rid=%d\n", je->rid);
            break;

			
        case EXOSIP_MESSAGE_NEW://�µ���Ϣ����
            //fprintf(stderr," EXOSIP_MESSAGE_NEW!\r\n");
            //***������ܵ�����Ϣ������MESSAGE***
            sipMessageResponse(sipData,je);
            break;

			
        case EXOSIP_CALL_MESSAGE_NEW:
            /*
            //���ڸ����ͺ�EXOSIP_MESSAGE_NEW������Դ������ô���͵�
            // request related events within calls (except INVITE)
             EXOSIP_CALL_MESSAGE_NEW,          < announce new incoming request.
            // response received for request outside calls
             EXOSIP_MESSAGE_NEW,          < announce new incoming request.
             ��Ҳ���Ǻ����ף������ǣ�
             EXOSIP_CALL_MESSAGE_NEW��һ�������е��µ���Ϣ����������ring trying���㣬�����ڽ��ܵ�������ж�
             ����Ϣ���ͣ�EXOSIP_MESSAGE_NEW���Ǳ�ʾ���Ǻ����ڵ���Ϣ������
            */
            fprintf(stderr,"   <==EXOSIP_CALL_MESSAGE_NEW==>\r\n");
            if (MSG_IS_INFO(je->request) ) //����������INFO����
            {
                //eXosip_lock (sipData->context_eXosip);
                ret = eXosip_call_build_answer (sipData->context_eXosip, je->tid, 200, &answer);
                if (ret == 0)
                {
                    eXosip_call_send_answer (sipData->context_eXosip, je->tid, 200, answer);
                }
                //eXosip_unlock (sipData->context_eXosip);

                osip_message_get_body (je->request, 0, &body);
                printf ("the body is %s\r\n", body->body);
            }
            break;
		case EXOSIP_MESSAGE_ANSWERED:
		case EXOSIP_CALL_MESSAGE_ANSWERED:
			//fprintf(stderr,"Get message 200 OK Response!\n");
			(sipData->recv200OkNum)++;
			break;
		case EXOSIP_MESSAGE_REQUESTFAILURE:
			//fprintf(stderr,"Message request failure!\n");
			(sipData->recvFailNum)++;
			break;
		
        default:
			fprintf(stderr,"   <==Could not parse the msg! je type =%d==>\r\n", je->type);
            break;
        }

		fflush(stdout);
		fflush(stderr);

		if(NULL!= je)
		eXosip_event_free(je);

		//if(NULL!=remote_sdp)
			//free(remote_sdp);
		//if(NULL!=body)
			//free(body);

		eXosip_unlock (sipData->context_eXosip);
	
    }

	//sipFree(sipData);
}



//�����ļ�weightFile�е�Ȩ�رȣ�����mes*.txt��Ϣ
int sendMessageAsWeight(struct sip_data_t * sipData, char* weightFile,int loop)
{
	int i 					= 0;
	int ret 				= 0;
	int weight[200]			= {0};
	int wegSize 			= 0;
	int wegTotal 			= 0;
	long long startSec 		= 0;
	long long endSec 		= 0;
	int consumTime   		= 0;
	int RunNum 				= 0;
	char fileName[100] 		={0};
	char nowStart[100] 		= {0};
	char nowEnd[100] 		= {0};

	time_t nowtim;
	struct tm *tm_now ;
	startSec = time(&nowtim) ;
	tm_now = localtime(&nowtim) ;

	char * mes = (char*)malloc(4096);

	
	sprintf(nowStart, "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d",
		tm_now->tm_year+1900, tm_now->tm_mon+1,tm_now->tm_mday, tm_now->tm_hour, 
		tm_now->tm_min, tm_now->tm_sec);



	wegSize = sizeof(weight)/sizeof(weight[0]);
	wegTotal = getWeightFromFile(weightFile,weight,wegSize);


	if(0 >= wegTotal) 
		return -1;

	srand((unsigned)time(NULL));
	

	while(1)
	{
		if(i++ >= loop)break;
		
		RunNum  = rand()%wegTotal;
		
		snprintf(fileName,100,"./sendMeg/mes%d.txt",weight[RunNum]);

		ret = getMessageFromFile(fileName,mes); 
		convertMessageToSipMeg(sipData,mes);	

	        eXosip_lock(sipData->context_eXosip);
		sendMessage(sipData,mes,"Application/MANSCDP+xml");
	        eXosip_unlock(sipData->context_eXosip);
	

		//usleep((sipData->sendDelay)*1000);
		//usleep((sendDelayTime)*1000);
		Sleep(g_stat_data.sendDelayTime);


		//loopΪ-1��������ѭ��
		if(-1 == loop)continue;
		
	}


	endSec = time(&nowtim) ;
	tm_now = localtime(&nowtim) ;
	sprintf(nowEnd, "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d",
		tm_now->tm_year+1900, tm_now->tm_mon+1,tm_now->tm_mday, tm_now->tm_hour, 
		tm_now->tm_min, tm_now->tm_sec);
		
	consumTime = (int)(endSec - startSec);

	free(mes);

	return consumTime;
}




//�����߳�
void* keepAliveThread(void * arg)
{
	int ret = 0;
	int heartIntervel = 30;
	int firstHeart = 1;
	struct sip_data_t * sipData;
	char * tmp = (char*)malloc(4096);
	
	sipData =(struct sip_data_t *) arg;
	
	while(!sipData->stop_keepalive)
	{
	    if(firstHeart)
    	{
    		firstHeart = 0;
    	}
		else
		{
			--heartIntervel;
			Sleep(2000);//2*30 �뷢��һ������
			if (heartIntervel != 0)
			{
				continue;
			}
		}
		
		heartIntervel = 30;
		if(sipData->registerFlag == 1)
		{
			//����xml��Ϣ
			(sipData->sendAliveNum)++;

			ret = getMessageFromFile("./sendMeg/keepalive.txt",tmp); 
			convertMessageToSipMeg(sipData,tmp);


	        eXosip_lock(sipData->context_eXosip);
			sendMessage(sipData,tmp,"Application/MANSCDP+xml");
	        eXosip_unlock(sipData->context_eXosip);
		}


		//sleep(60);
		//Sleep(60*1000);
	}

	free(tmp);
}




int printNowTime()
{
	time_t nowtim;
	struct tm *tm_now ;
	char nowStart[100] 	= {0};

	time(&nowtim) ;
	tm_now = localtime(&nowtim) ;
	sprintf(nowStart, "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d",
		tm_now->tm_year+1900, tm_now->tm_mon+1,tm_now->tm_mday, tm_now->tm_hour, 
		tm_now->tm_min, tm_now->tm_sec);

	printf(" %s\r\n",nowStart);

	return 0;
}



int statistic(int TotalClientNum)
{
	char tmp2[4096]				= "";
	double sendQps				= 0;
	double realQps					= 0;
	double successRate			= 0;
	

	if(g_stat_data.sendTotalNum)
		successRate = ((double)g_stat_data.recv200OkNum)*100/g_stat_data.sendTotalNum;

	if(g_stat_data.totalConsumTime)
		sendQps = ((double)g_stat_data.sendTotalNum)/ g_stat_data.totalConsumTime;

	if (g_stat_data.totalConsumTime)
		realQps = ((double)g_stat_data.recv200OkNum) / g_stat_data.totalConsumTime;
	

	snprintf(tmp2,4096,
		"sendTotalPacket    : %d\r\n"
		"recv200OkPacket    : %d\r\n"
		"RequestFailure     : %d\r\n"
		"successRate        : %f%%\r\n"
		"sendQps            : %f\r\n"
		"realQps            : %f\r\n",
		  g_stat_data.sendTotalNum, g_stat_data.recv200OkNum,
		  g_stat_data.recvFailNum,successRate,sendQps,realQps);

	printf("\r\n-----------------------------------\r\n"); 

	printNowTime();
	
	printf("TotalClientNum : %d\r\n", TotalClientNum);
	printf("RegisterOKNum  : %d\r\n", g_stat_data.totalRegisterOK);
	printf("SendDelayTime  : %d(msec)\r\n", g_stat_data.sendDelayTime);
	printf("consumTime     : %d(sec)\r\n", g_stat_data.totalConsumTime);
	printf("\r\n%s",tmp2);

	printf("\r\n-----------------------------------\r\n\r\n");	

	return 0;
}



int startSend(void * arg)
{
	int ret 				= 0;
	int regFlag				= 0;
	int i					= 0;
	int consumTime  		= 0;
	char fileName[100] 		= "";
	int regNum 				= 3;
	struct sip_data_t sipData = {0};

	int* num = (int*)arg;
	int tmnum = num;

	initSipData(tmnum,&sipData);
	sipData.registerFlag = 1;
	ret = sipRegister(&sipData);
	
	if(ret != 0)
	{
		sipData.registerFlag = 0;
		printf("[%s]register fail\r\n",sipData.clientId);
	    sipFree(&sipData);
		return -1;
	}


	//�����߳�
	ret = pthread_create(&sipData.tid_keepalive,NULL,keepAliveThread,&sipData); 
	if(ret!=0)
	{
		printf("keepalive thread fail\r\n");
	}


	//��Ӧ��Ϣ�߳�
	ret = pthread_create(&sipData.tid_resp,NULL,sipResponseThread,&sipData); 
	if(ret!=0)
	{
		printf("sipResponseThread fail\r\n");
	}

	
	//��ʱ���������豸������ע�ᣬ����ĳЩ�豸�ѿ�ʼ���з��ͻᵼ��ע�᲻�ɹ�
	//sleep(10);
	Sleep(10*1000);


	consumTime = sendMessageAsWeight(&sipData,"./sendMeg/weight.ini", g_stat_data.sendRunNumber);

	//��ʱ�������������ڷ����еı���
	//sleep(30);
	Sleep(130*1000);
    sipData.stop_keepalive = 1;
    sipData.stop_resp = 1;
    pthread_join (sipData.tid_keepalive, NULL);
    pthread_join (sipData.tid_resp, NULL);	
	sipFree(&sipData);


	pthread_mutex_lock (&mutex);

	if(consumTime > g_stat_data.totalConsumTime)
		g_stat_data.totalConsumTime = consumTime;
	g_stat_data.sendTotalNum += sipData.sendTotalNum;
	g_stat_data.sendAliveNum += sipData.sendAliveNum;
	g_stat_data.recv200OkNum += sipData.recv200OkNum;
	g_stat_data.recvFailNum  += sipData.recvFailNum;
	g_stat_data.totalRegisterOK++;

	pthread_mutex_unlock(&mutex);

    return 0;

}



