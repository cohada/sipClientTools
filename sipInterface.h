#include <eXosip2/eXosip.h>
#include <pthread.h>


#ifndef _AUTH_H_
#define _AUTH_H_

#ifdef __cplusplus
extern "C" {
#endif

struct sip_init_data_t {
	char* password;
	char* clientId;	
	char* clientAdress;
	int   clientPort;
	char* serverId;
	char* serverAdress;
	int   serverPort;
	char* userAgent;
	int   SNId ;
	int   expire;//ע��ʧЧʱ��

	int sendDelay;//����Ȩ�ر���֮���delayʱ��(΢��)
	int sendRunNumber;//��Ȩ�ط�������

	char *clientPhoneNumber;

};




struct sip_data_t {
  	struct eXosip_t *context_eXosip;
    pthread_t 	tid_keepalive;
    int 		stop_keepalive;
    pthread_t 	tid_resp;
    int 		stop_resp;
	char* 	password;
	char* 	clientId;	
	char* 	clientAdress;
	int   	clientPort;
	char* 	serverId;
	char* 	serverAdress;
	int   	serverPort;
	char* 	userAgent;
	int   	SNId ;
	int   	expire;//ע��ʧЧʱ��

	int 	call_id;
	int 	dialog_id;
	int 	registerFlag; //ע����

	int 	sendDelay;//����Ȩ�ر���֮���delayʱ��(΢��)
	int 	sendRunNumber;//��Ȩ�ط�������

	char *responseList[100];
	int resListNum;
	char *logFilePath;

	unsigned int sendTotalNum;
	unsigned int sendAliveNum;
	unsigned int recv200OkNum;
	unsigned int recvFailNum;

	char *clientPhoneNumber;

	int recv100Flag;/*-1��ʼ״̬��0û�յ���Ϣ��1�յ���Ϣ*/
	int recv180Flag;
	int recv200Flag;
	int mediaSendFlag;

};

struct statis_data_t {
	unsigned int sendTotalNum;
	unsigned int sendAliveNum;
	unsigned int recv200OkNum;
	unsigned int recvFailNum;

	unsigned int sendDelayTime;
	unsigned int sendRunNumber;
	unsigned int totalConsumTime;
	unsigned int totalRegisterOK;
	unsigned int deviceNum;
};


typedef struct phone_status_t {
	char *phoneNumber;
	int recv100Flag;/*-1��ʼ״̬��0û�յ���Ϣ��1�յ���Ϣ*/
	int recv180Flag;
	int recv200Flag;
	int needCallFlag;
	int callResult;

} PhoneStatusT;

typedef struct phone_title_t {
	char *col1Name;
	char *col2Name;
	char *col3Name;
	char *col4Name;
	char *col5Name;
	char *col6Name;

} PhoneTitleT;



int replace_string(char *result, char *source, char* s1, char *s2);

//��XML��Ϣ�в��ҹؼ���key��ֵ
int findStrFromMessage(char* message, char* key, char* value);
int getMessageFromFile(char *filePath, char *data)  ;
int convertMessageToSipMeg( struct sip_data_t * sipData, char *data)  ;

//ʹ�÷���������Ϣ���SNID
int convertMessageForResponse( struct sip_data_t * sipData, char *data, char *snid)  ;

int sipMessageResponse(struct sip_data_t * sipData,eXosip_event_t *je);
void* sipResponseThread(void * arg);

int initGlobalSipDataFromFile(char *filePath );
int initSipData(int number, struct sip_data_t * sipData ) ;


int sipRegister(struct sip_data_t * sipData)  ;
int sipInvite(struct sip_data_t * sipData, char* callNumber) ;
int sendInfo(struct sip_data_t * sipData, int dialog_id,char * mes,char * mesType);
int sendMessage(struct sip_data_t * sipData,char * mes,char * mesType);
void SendRegisterAnswer(struct eXosip_t *context_eXosip, eXosip_event_t *je, int status);
int sipFree(struct sip_data_t * sipData)  ;



int sendMessageAsWeight(struct sip_data_t * sipData, char* weightFile,int loop);
void* keepAliveThread(void * arg);
int printNowTime();
int statistic(int TotalClientNum);
int startSend(void * arg);







#ifdef __cplusplus
}
#endif

#endif
