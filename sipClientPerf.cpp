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

int sendDelayTime = 0;
int sendRunNumber = 100;
int totalConsumTime = 0;
int totalRegisterOK = 0;
pthread_mutex_t 		mutex;
struct statis_data_t    g_stat_data;


/*
weight:数组按权重保存执行的事件序号。
size:为总权重的总和值，目前定为200，权重之和不能超过此值
count:最后返回weight保存有效序号的总数。
*/
int getWeightFromFile(char *filePath, int *weight, int size)
{
	FILE *fp;
	int num = 0; //为执行的事件消息序号
	int weg = 0; //执行的权重比例
	int count = 0;
	char speator[10] = "";
	int i = 0;
	int ret = 0;

	if (NULL == weight)
		return -1;

	memset(weight, 0, size);

	if ((fp = fopen(filePath, "r")) == NULL) {
		printf("open file %s error! \n", filePath);
		return -1;
	}



	fseek(fp, 0, SEEK_END);
	rewind(fp);

	/*
	num为发送的消息编号
	weg为消息对应的权重
	*/
	while ((ret = fscanf(fp, "%d %s %d", &num, speator, &weg)) == 3) {
		for (i = 0; i<weg; i++)
		{
			weight[count++] = num;
			if (count >= size)
				return -1;
		}

	}
	fclose(fp);


	return count;
}




int printNowTime()
{
	time_t nowtim;
	struct tm *tm_now;
	char nowStart[100] = { 0 };

	time(&nowtim);
	tm_now = localtime(&nowtim);
	sprintf(nowStart, "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d",
		tm_now->tm_year + 1900, tm_now->tm_mon + 1, tm_now->tm_mday, tm_now->tm_hour,
		tm_now->tm_min, tm_now->tm_sec);

	printf(" %s\n", nowStart);

	return 0;
}



//按照文件weightFile中的权重比，发送mes*.txt消息
int sendMessageAsWeight(struct sip_data_t * sipData, char* weightFile, int loop)
{
	int i = 0;
	int ret = 0;
	int weight[200] = { 0 };
	int wegSize = 0;
	int wegTotal = 0;
	long long startSec = 0;
	long long endSec = 0;
	int consumTime = 0;
	int RunNum = 0;
	char fileName[100] = { 0 };
	char nowStart[100] = { 0 };
	char nowEnd[100] = { 0 };

	time_t nowtim;
	struct tm *tm_now;
	startSec = time(&nowtim);
	tm_now = localtime(&nowtim);

	char * mes = (char*)malloc(4096);


	sprintf(nowStart, "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d",
		tm_now->tm_year + 1900, tm_now->tm_mon + 1, tm_now->tm_mday, tm_now->tm_hour,
		tm_now->tm_min, tm_now->tm_sec);



	wegSize = sizeof(weight) / sizeof(weight[0]);
	wegTotal = getWeightFromFile(weightFile, weight, wegSize);


	if (0 >= wegTotal)
		return -1;

	srand((unsigned)time(NULL));


	while (1)
	{
		if (i++ >= loop)break;

		RunNum = rand() % wegTotal;

		snprintf(fileName, 100, "./sendMeg/mes%d.txt", weight[RunNum]);

		ret = getMessageFromFile(fileName, mes);
		convertMessageToSipMeg(sipData, mes);

		eXosip_lock(sipData->context_eXosip);
		sendMessage(sipData, mes, "Application/MANSCDP+xml");
		eXosip_unlock(sipData->context_eXosip);


		//usleep((sipData->sendDelay)*1000);
		usleep((sendDelayTime) * 1000);


		//loop为-1，则无限循环
		if (-1 == loop)continue;

	}



	endSec = time(&nowtim);


	tm_now = localtime(&nowtim);
	sprintf(nowEnd, "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d",
		tm_now->tm_year + 1900, tm_now->tm_mon + 1, tm_now->tm_mday, tm_now->tm_hour,
		tm_now->tm_min, tm_now->tm_sec);



	consumTime = (int)(endSec - startSec);

	free(mes);

	return consumTime;
}




//心跳线程
void* keepAliveThread(void * arg)
{
	int ret = 0;
	struct sip_data_t * sipData;
	char * tmp = (char*)malloc(4096);

	sipData = (struct sip_data_t *) arg;

	while (!sipData->stop_keepalive)
	{
		//如果没注册成功0，或注销2，都不发送keepalive
		if (sipData->registerFlag == 1)
		{
			//传送xml消息
			(sipData->sendAliveNum)++;

			ret = getMessageFromFile("./sendMeg/keepalive.txt", tmp);
			convertMessageToSipMeg(sipData, tmp);


			eXosip_lock(sipData->context_eXosip);
			sendMessage(sipData, tmp, "Application/MANSCDP+xml");
			eXosip_unlock(sipData->context_eXosip);
		}


		sleep(60);
	}

	free(tmp);
}




int statistic(int num)
{
	char tmp2[4096] = "";
	int logTotalNum = 0;
	double totalQps = 0;
	double successRate = 0;

	logTotalNum = num;

	if (g_stat_data.sendTotalNum)
		successRate = ((double)g_stat_data.recv200OkNum) * 100 / g_stat_data.sendTotalNum;

	if (totalConsumTime)
		totalQps = ((double)g_stat_data.recv200OkNum) / totalConsumTime;


	snprintf(tmp2, 4096,
		"sendTotalPacket : %d\r\n"
		"recv200OkPacket : %d\r\n"
		"RequestFailure  : %d\r\n"
		"successRate     : %f%\r\n"
		"totalQps        : %f\r\n",
		g_stat_data.sendTotalNum, g_stat_data.recv200OkNum,
		g_stat_data.recvFailNum, successRate, totalQps);

	printf("\n==================================================\n");

	printNowTime();

	printf("TotalClientNum : %d\n", logTotalNum);
	printf("RegisterOKNum  : %d\n", totalRegisterOK);
	printf("SendDelayTime  : %d(msec)\n", sendDelayTime);
	printf("consumTime     : %d(sec)\n", totalConsumTime);
	printf("\n%s", tmp2);

	printf("\n==================================================\n\n");

	return 0;
}



int startSend(void * arg)
{
	int ret = 0;
	int regFlag = 0;
	int i = 0;
	int consumTime = 0;
	char fileName[100] = "";
	int regNum = 3;
	pthread_t tid;	//线程号
	struct sip_data_t sipData = { 0 };

	int* num = (int*)arg;
	int tmnum = num;


	snprintf(fileName, 100, "./config/client%d.ini", tmnum);

	ret = initSipDataFromFile(fileName, &sipData);
	if (0 != ret)
	{
		printf("init sip fail!\n");
		return -1;
	}


	//注册消息
	regFlag = sipData.registerFlag;
	sipData.registerFlag = 1;
	ret = sipRegister(&sipData);

	while (regNum != 0 && ret != 0)
	{
		ret = sipRegister(&sipData);
		sleep(1);
		regNum--;
	}

	if (ret != 0)
	{
		sipData.registerFlag = regFlag;
		printf("[%s]register fail\n", sipData.deviceId);
		sipFree(&sipData);
		return -1;
	}


	//延时，让所有设备能正常注册，否则某些设备已开始集中发送会导致注册不成功
	sleep(10);


	//心跳线程
	ret = pthread_create(&sipData.tid_keepalive, NULL, keepAliveThread, &sipData);
	if (ret != 0)
	{
		printf("keepalive thread fail\n");
	}


	//响应消息线程
	ret = pthread_create(&sipData.tid_resp, NULL, sipResponseThread, &sipData);
	if (ret != 0)
	{
		printf("sipResponseThread fail\n");
	}


	consumTime = sendMessageAsWeight(&sipData, "./sendMeg/weight.ini", sendRunNumber);

	//延时，接收完在正在发送中的报文
	sleep(30);
	sipData.stop_keepalive = 1;
	sipData.stop_resp = 1;
	pthread_join(sipData.tid_keepalive, NULL);
	pthread_join(sipData.tid_resp, NULL);
	sipFree(&sipData);


	pthread_mutex_lock(&mutex);

	if (consumTime > totalConsumTime)
		totalConsumTime = consumTime;
	g_stat_data.sendTotalNum += sipData.sendTotalNum;
	g_stat_data.sendAliveNum += sipData.sendAliveNum;
	g_stat_data.recv200OkNum += sipData.recv200OkNum;
	g_stat_data.recvFailNum += sipData.recvFailNum;
	totalRegisterOK++;

	pthread_mutex_unlock(&mutex);

	return 0;

}



//参数: 设备个数(最大1K)，时延，发送报文个数
int main(int argc, char *argv[])
{

	int status, i;
	int TotalNum = 10;
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



	if (argc > 1)
	{
		TotalNum = atoi(argv[1]);

		if (argc > 2) sendDelayTime = atoi(argv[2]);
		if (argc > 3) sendRunNumber = atoi(argv[3]);

		sleepTime = (sendDelayTime*sendRunNumber) / 1000 + 120;
	}


	printf("==================================================\n");
	printNowTime();
	printf(" Start to create thread ...\n");


	for (i = 1; i <= TotalNum; i++)
	{
		ret = pthread_create(&pid, NULL, startSend, i);

		if (ret != 0)
		{
			printf("startSend thread fail\n");
		}
		else
		{
			pidList[i - 1] = pid;
		}

	}

	printf(" Sending packets, please wait ...\n");


	for (i = 1; i <= TotalNum; i++)
		pthread_join(pidList[i - 1], NULL);


	statistic(TotalNum);

	return 0;
}


