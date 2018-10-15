#include <eXosip2/eXosip.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <sys/types.h> 
//#include <netinet/in.h>
#include <winsock2.h>
#pragma  comment(lib,"ws2_32.lib")
#include "unistd.h"
#include "sipInterface.h"

extern pthread_mutex_t 		mutex;
extern struct statis_data_t    g_stat_data;

PhoneStatusT phoneList[2000];

int sipPhoneHelpInfo()
{
	printf("---------------------------------\r\n");
	//printf("1   register to server\r\n");
    //printf("2   cancel register\r\n");
    printf("3   Invite a call\r\n");
    printf("4   Hold off the call\r\n");    
    //printf("5   send INFO msg\r\n");
	//printf("6   send xml control msg\r\n");
	printf("8   Quit sip Phone \r\n");
	printf("0   Help\r\n");
	printf("---------------------------------\r\n");
	return 0;
}


int systemHelpInfo()
{
	printf("==================================================\r\n");
	printf("1   Performance Tool\r\n");
    printf("2   SIP Phone Tool\r\n");
	printf("3   Singal loop phone call Tool\r\n");
	//printf("4   many to one phone call Tool\r\n");
	//printf("5   many to many phone call Tool\r\n");
	printf("9   Quit\r\n");
	printf("0   Help\r\n");
	printf("==================================================\r\n");
	return 0;
}

//性能测试工具，可创建多个模拟设备
//参数: 设备个数(最大1K)，时延，发送报文个数
int performanceFuntion()
{
	int status, i;
	int sleepTime = 0;
	int ret = 0;
	pthread_t pid;
	pthread_t pidList[1000];

	memset(pidList, 0, 100);
	pthread_mutex_init(&mutex, NULL);

	g_stat_data.recv200OkNum = 0;
	g_stat_data.recvFailNum = 0;
	g_stat_data.sendAliveNum = 0;
	g_stat_data.sendTotalNum = 0;
	g_stat_data.sendDelayTime = 100;
	g_stat_data.sendRunNumber = 100;
	g_stat_data.totalConsumTime = 0;
	g_stat_data.totalRegisterOK = 0;
	g_stat_data.deviceNum = 1;


	printf("==================================================\r\n");
	printf("Please input number of device : ");
	scanf("%d", &g_stat_data.deviceNum);
	printf("Please input sendIntervalTime(ms) : ");
	scanf("%d", &g_stat_data.sendDelayTime);
	printf("Please input sending number of packets by every device : ");
	scanf("%d", &g_stat_data.sendRunNumber);

	printf("==================================================\r\n");
	printf("\r\n Start to create thread ...\r\n");


	for (i = 0; i < g_stat_data.deviceNum; i++)
	{
		ret = pthread_create(&pid, NULL, startSend, i);

		if (ret != 0)
		{
			printf("startSend thread fail\r\n");
		}
		else
		{
			pidList[i] = pid;
		}

	}

	printf(" Sending packets, please wait ...\r\n");
	printNowTime();

	for (i = 0; i < g_stat_data.deviceNum; i++)
		pthread_join(pidList[i], NULL);


	statistic(g_stat_data.deviceNum);

	return 0;
}


//SIP电话模拟器初始化，num为初始化文件中的DEVID+num，在创建多个时可用
int sipPhoneInit(struct sip_data_t * sipData,int num)
{
	int ret = 0;
	int i = 0;
	char fileName[100] = "";
	int regNum = 3;
	int tmnum = num;


	initSipData(tmnum,sipData);
	sipData->registerFlag = 1;
	ret = sipRegister(sipData);

	if (ret != 0)
	{
		sipData->registerFlag = 0;
		printf("register fail -> regNum = %d,ret  =%d\r\n", regNum, ret);
		sipFree(sipData);
		return -1;
	}


	ret = pthread_create(&(sipData->tid_keepalive), NULL, keepAliveThread, sipData);
	if (ret != 0)
	{
		printf("keepalive thread fail\r\n");
	}

	ret = pthread_create(&sipData->tid_resp, NULL, sipResponseThread, sipData);
	if (ret != 0)
	{
		printf("sipResponseThread fail\r\n");
	}


	return 0;
}


//sip电话功能函数
int sipPhoneFuntion(int initFileNum)
{
	int call_id 	= 0;
	int dialog_id	= 0;
	int ret 		= 0;
	int flag		= 0;
	int regFlag 	= 0;
	int i			= 0;
	int command;
	char * tmp		= (char*)malloc(4096);
	char *fileName	= (char*)malloc(100);
	char *callNumber = (char*)malloc(100);
	char *callIP = (char*)malloc(100);
	char *cmd = (char*)malloc(200);
	int callingFlag = 0;

	struct sip_data_t sipData ;

	ret = sipPhoneInit(&sipData,initFileNum);

	if(ret != 0)
	{
		printf("Sip Phone init fail!\n");
		return -1;
	}

	sipPhoneHelpInfo();
	
	flag=1;
	while(flag)
	{
		//输入命令
		printf("Please input the command : \n");
		scanf("%d",&command);
		getchar();

		switch(command)
		{
		case 1:
			regFlag = sipData.registerFlag;
			sipData.registerFlag = 1;
			ret = sipRegister(&sipData);	
			if(ret != 0)
				sipData.registerFlag = regFlag;
			break;
		case 2:
			regFlag = sipData.registerFlag;
			sipData.registerFlag = 0;
			ret = sipRegister(&sipData);	
			if(ret != 0)
				sipData.registerFlag = regFlag; 	
			break;
		case 3://INVITE，发起呼叫请求
			if(sipData.registerFlag)
			{
				printf("Please input call phone number:\r\n");
				scanf("%s",callNumber);
				sipInvite(&sipData, callNumber);
				callingFlag = 1;
				//system("start cmd /k \"ffmpeg -re -i hldwm.264 -vcodec copy -f rtp rtp://172.24.9.145:9856>video.sdp \"");
				//WinExec("cmd /C ffmpeg -re -i hldwm.264 -vcodec copy -f rtp rtp://172.24.9.145:9856>video.sdp ",SW_HIDE);
			}
			break;
		case 4:   //挂断
			if(sipData.registerFlag && callingFlag)
			{
				printf("   <==Holded off the phone!==>\r\n");
				if(sipData.mediaSendFlag)
				{
					system("taskkill /f /im ffmpeg.exe");
					system("taskkill /f /im cmd.exe");
					sipData.mediaSendFlag = 0;
				}

				eXosip_lock(sipData.context_eXosip);
				ret = eXosip_call_terminate(sipData.context_eXosip, sipData.call_id, sipData.dialog_id);
				eXosip_unlock(sipData.context_eXosip);
				callingFlag = 0; 
			}
			break;


		case 5: 
			//传输INFO方法
			printf("Input the INFO message name:\r\n");
			scanf("%s",tmp);
			snprintf(fileName,100,"./sendMeg/%s.txt",tmp);
			printf("It will send INFO %s\r\n",fileName);
			
			ret = getMessageFromFile(fileName,tmp); 
			convertMessageToSipMeg(&sipData,tmp);
			sendInfo(&sipData,dialog_id,tmp,"text/plain");
			break;		

		case 6:
			//传送xml消息
			printf("Input the message name:\r\n");
			scanf("%s",tmp);
			snprintf(fileName,100,"./sendMeg/%s.txt",tmp);
			printf("It will send %s\r\n",fileName);
			
			ret = getMessageFromFile(fileName,tmp); 
			convertMessageToSipMeg(&sipData,tmp);
			sendMessage(&sipData,tmp,"Application/MANSCDP+xml");
			break;

		case 8:
			if(sipData.registerFlag)
			{
				if(callingFlag)
				{
					if(sipData.mediaSendFlag)
					{
						system("taskkill /f /im ffmpeg.exe");
						system("taskkill /f /im cmd.exe");
						sipData.mediaSendFlag = 0;
					}
					eXosip_lock(sipData.context_eXosip);
					ret = eXosip_call_terminate(sipData.context_eXosip, sipData.call_id, sipData.dialog_id);
					eXosip_unlock(sipData.context_eXosip);
					callingFlag = 0;
				}
			
				sipData.stop_keepalive = 1;
				sipData.stop_resp = 1;
				pthread_join (sipData.tid_resp, NULL);
				pthread_join (sipData.tid_keepalive, NULL);
				eXosip_quit(sipData.context_eXosip);
				//sipFree(&sipData);
			}
			printf("   <==Exit the sip Client!==>\r\n");
			flag = 0;
			break;
		case 0:
			sipPhoneHelpInfo();
			break;

		default:
			break;
		}
	}

	free(tmp);
	free(fileName);

	return 0;
}



//从Excel文件中获取电话号码等信息
int getPhoneListFromExcel(char *filePath)
{
	int ret = 0;
	int totalPhoneNum = 0;
	char temp[30]="";
    FILE *fp = NULL ;
	//char filePath[100] = "./initData/phoneList.xls";

	if(filePath ==NULL)
	{
		printf("FilePath is NULL\n");  
		return -1;	
	}
	if ((fp=fopen(filePath,"r"))==NULL)
	{  
		printf("open file %s error! \r\n",filePath);  
		return -1;	
	} 

	  
	//printf("start\n");
	//读取第一行
	fscanf(fp, "%s\t%s\t%s\t%s\t%s\t%s", temp, temp,temp, temp,temp, temp);
	
	while((ret = fscanf(fp,"%s\t%d\t%d\t%d\t%d\t%d",
				temp,
				&phoneList[totalPhoneNum].needCallFlag,
				&phoneList[totalPhoneNum].recv100Flag,
				&phoneList[totalPhoneNum].recv180Flag,
				&phoneList[totalPhoneNum].recv200Flag,
				&phoneList[totalPhoneNum].callResult)) == 6)
	{
		
		phoneList[totalPhoneNum].phoneNumber = (char*)malloc(30);
		if(temp[0]!='0')
			sprintf(phoneList[totalPhoneNum].phoneNumber, "0%s",temp);

		else
			strcpy(phoneList[totalPhoneNum].phoneNumber,temp);

/*
		printf("%s\t%d\t%d\t%d\t%d\t%d\n",
				phoneList[totalPhoneNum].phoneNumber,
				phoneList[totalPhoneNum].needCallFlag,
				phoneList[totalPhoneNum].recv100Flag,
				phoneList[totalPhoneNum].recv180Flag,
				phoneList[totalPhoneNum].recv200Flag,
				phoneList[totalPhoneNum].callResult);
*/
		totalPhoneNum++;
	}
	fclose(fp);
	return totalPhoneNum;
	
}


//将呼叫信息写入Excel文件中
int writePhoneListTitle(char *filePath)
{
	int i = 0;
	int ret = 0;
	int totalPhoneNum = 0;
	char temp[30]="";
    FILE *fp = NULL ;

	if(filePath ==NULL)
	{
		printf("FilePath is NULL\n");  
		return -1;	
	}

	if ((fp=fopen(filePath,"w"))==NULL)
	{  
		printf("open file %s error! \r\n",filePath);  
		return -1;	
	} 

	fprintf(fp,"PhoneNumber\tNeedCall\t100Trying\t180Ringing\t200OK\tResult\tTime\n") ;
	
	
	fclose(fp);
	return 0;
	
}


//将呼叫记录写入Excel文件中
int writePhoneListToExcel(PhoneStatusT pht,char *filePath)
{
	int i = 0;
	int ret = 0;
	int totalPhoneNum = 0;
	char temp[30]="";
    FILE *fp = NULL ;

	char nowTime[100] 		= {0};
	long long startSec 		= 0;
	time_t nowtim;
	struct tm *tm_now ;
	startSec = time(&nowtim) ;
	tm_now = localtime(&nowtim) ;

	sprintf(nowTime, "%.4d-%.2d-%.2d %.2d:%.2d:%.2d",
		tm_now->tm_year+1900, tm_now->tm_mon+1,tm_now->tm_mday, tm_now->tm_hour, 
		tm_now->tm_min, tm_now->tm_sec);

	

	if(filePath ==NULL)
	{
		printf("FilePath is NULL\n");  
		return -1;	
	}

	if ((fp=fopen(filePath,"a"))==NULL)
	{  
		printf("open file %s error! \r\n",filePath);  
		return -1;	
	} 

	if(pht.phoneNumber == NULL)
	{
		printf("phoneNumber is NULL \n");
		fclose(fp);
		return -1;
	}
	
	fprintf(fp,"%s\t%d\t%d\t%d\t%d\t%d\t%s\n",
				pht.phoneNumber,
				pht.needCallFlag,
				pht.recv100Flag,
				pht.recv180Flag,
				pht.recv200Flag,
				pht.callResult,
				nowTime
				) ;
	fclose(fp);
	return 0;
	
}



int singalLoopPhoneCall2()
{
	int totalPhoneNum = 0;
	int i = 0;
	int ret 		= 0;
	int flag 		= 1;
	int regFlag		= 0;
	PhoneStatusT pht;
	char filePhoneList[100] = "./initData/phoneList.xls";
	char *filePhoneResult = (char*)malloc(100);


	char *callNumber 	= (char*)malloc(100);
	char *callIP 		= (char*)malloc(100);
	char *cmd 			= (char*)malloc(200);
	struct sip_data_t sipData ;


	char nowTime[100] 		= {0};
	long long startSec 		= 0;
	time_t nowtim;
	struct tm *tm_now ;
	startSec = time(&nowtim) ;
	tm_now = localtime(&nowtim) ;

	sprintf(nowTime, "%.4d-%.2d-%.2d-%.2d_%.2d_%.2d",
		tm_now->tm_year+1900, tm_now->tm_mon+1,tm_now->tm_mday, tm_now->tm_hour, 
		tm_now->tm_min, tm_now->tm_sec);

	sprintf(filePhoneResult,"./callResultLog/[%s]CallResult.xls",nowTime);





	totalPhoneNum = getPhoneListFromExcel(filePhoneList);
	writePhoneListTitle(filePhoneResult);



	ret = sipPhoneInit(&sipData,0);

	if(ret != 0 || sipData.registerFlag == 0 )
	{
		printf("Sip Phone init fail!\n");
		
		return -1;
	}


    for(i = 0;i < totalPhoneNum;i++)
	{
		if(phoneList[i].needCallFlag != 1)
			continue;
		
        printf("Try to call Number : %s...\n",phoneList[i].phoneNumber);

		sipData.recv100Flag = 0;
		sipData.recv180Flag = 0;
		sipData.recv200Flag = 0;
    	//INVITE，发起呼叫请求
		sipInvite(&sipData, phoneList[i].phoneNumber);
	

		Sleep(20 *1000);

		//挂断
		if(sipData.recv180Flag)
		{	
	        printf("   <==Holded off the phone!==>\r\n");
			if(sipData.mediaSendFlag)
			{
				system("taskkill /f /im ffmpeg.exe");
				system("taskkill /f /im cmd.exe");
				sipData.mediaSendFlag = 0;
			}

	        eXosip_lock(sipData.context_eXosip);
	        ret = eXosip_call_terminate(sipData.context_eXosip, sipData.call_id, sipData.dialog_id);
			eXosip_unlock(sipData.context_eXosip);

			phoneList[i].callResult = 1;
			phoneList[i].needCallFlag = 0;
		}
		else
		{
			phoneList[i].callResult = 0;
			phoneList[i].needCallFlag = 1;
		}


		phoneList[i].recv100Flag =sipData.recv100Flag ;
		phoneList[i].recv180Flag =sipData.recv180Flag ;
		phoneList[i].recv200Flag =sipData.recv200Flag ;


		writePhoneListToExcel(phoneList[i],filePhoneResult);
           
    }


	sipData.stop_keepalive = 1;
	sipData.stop_resp = 1;
	pthread_join (sipData.tid_resp, NULL);
	pthread_join (sipData.tid_keepalive, NULL);
	eXosip_quit(sipData.context_eXosip);


	return 0;

}



//单呼轮询
int singalLoopPhoneCall(char *filePath )
{
	int ret 		= 0;
	int flag 		= 1;
	int regFlag		= 0;
	int i			= 0;


	char *fileName 	= (char*)malloc(100);
	char *callNumber = (char*)malloc(100);
	char *callIP = (char*)malloc(100);
	char *cmd = (char*)malloc(200);

	struct sip_data_t sipData ;
	FILE *fp; 



	ret = sipPhoneInit(&sipData,0);

	if(ret != 0 || sipData.registerFlag == 0 )
	{
		printf("Sip Phone init fail!\n");
		
		return -1;
	}



	
	if ((fp=fopen(filePath,"r"))==NULL){  
        printf("open file %s error! \r\n",filePath);  
        return -1;  
    }
	else
	{
		printf("open file %s ! \r\n",filePath);  
	}

    fseek(fp,0,SEEK_END);  
    rewind(fp);  
     
    //字符串类型数据获取
    while((ret = fscanf(fp,"%s",callNumber)) == 1)
	{  	
        printf("Try to call Number : %s...\n",callNumber);
		
    	//INVITE，发起呼叫请求
		sipInvite(&sipData, callNumber);
	

		Sleep(30 *1000);

		//挂断
		
        printf("   <==Holded off the phone!==>\r\n");
		//system("taskkill /f /im ffmpeg.exe");
		//system("taskkill /f /im cmd.exe");
        eXosip_lock(sipData.context_eXosip);
        ret = eXosip_call_terminate(sipData.context_eXosip, sipData.call_id, sipData.dialog_id);
		//printf("ccid = %d,did = %d,ret = %d\r\n",  sipData.call_id,  sipData.dialog_id,ret);
		eXosip_unlock(sipData.context_eXosip);

		
           
    }


	sipData.stop_keepalive = 1;
	sipData.stop_resp = 1;
	pthread_join (sipData.tid_resp, NULL);
	pthread_join (sipData.tid_keepalive, NULL);
	eXosip_quit(sipData.context_eXosip);


	fclose(fp); 
	free(fileName);

    return 0;
}










//多个同时呼同一个号码
int multiToOnePhoneCall()
{
	return 0;
}

//多个模拟器并行呼叫不同号码
int multiToMultiPhoneCall()
{
	return 0;
}




int main(int argc,char *argv[])
{
	int funChoice = 0;
	int correctInput = 1;
	char fileName[100] 		= "";
	snprintf(fileName,100,"./initData/initData.ini");

	initGlobalSipDataFromFile(fileName);
	
	while(1)
	{
		if (correctInput)
			systemHelpInfo();
		else
			correctInput = 1;

		printf("Please input your choice : \n");
		scanf("%d", &funChoice);

		switch(funChoice)
        {
        case 1:
			performanceFuntion();
			continue;
		case 2:
			sipPhoneFuntion(0);
			continue;
		case 3:
			singalLoopPhoneCall2();
			continue;
		case 4:
			//multiToOnePhoneCall();
			continue;
		case 5:
			//multiToMultiPhoneCall();
			continue;
		case 9:
			printf("Leaving system\r\n");
			return 0;
		case 0:
			continue;
		default:
			correctInput = 0;
			continue;
			
		}
		
	}


	return 0;
}


