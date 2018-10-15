#include "jauth.h"
#include "osip_md5.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

/* Private functions */
void CvtHex(IN HASH Bin, OUT HASHHEX Hex);

void CvtHex(IN HASH Bin, OUT HASHHEX Hex)
{
	unsigned short i;
	unsigned char j;

	for (i = 0; i < HASHLEN; i++)
	{
		j = (Bin[i] >> 4) & 0xf;
		if (j <= 9)
		{
			Hex[i * 2] = (j + '0');
		}
		else
		{
			Hex[i * 2] = (j + 'a' - 10);
		}
		j = Bin[i] & 0xf;
		if (j <= 9)
		{
			Hex[i * 2 + 1] = (j + '0');
		}
		else
		{
			Hex[i * 2 + 1] = (j + 'a' - 10);
		}
	};
	Hex[HASHHEXLEN] = '\0';
}

/* calculate H(A1) as per spec */
void DigestCalcHA1(IN const char *pszAlg,
                   IN const char *pszUserName,
                   IN const char *pszRealm,
                   IN const char *pszPassword,
                   IN const char *pszNonce,
                   IN const char *pszCNonce, OUT HASHHEX SessionKey)
{
	osip_MD5_CTX Md5Ctx;
	HASH HA1;

	osip_MD5Init(&Md5Ctx);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszUserName, strlen(pszUserName));
	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszRealm, strlen(pszRealm));
	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszPassword, strlen(pszPassword));
	osip_MD5Final((unsigned char *) HA1, &Md5Ctx);
	if ((pszAlg != NULL) && osip_strcasecmp(pszAlg, "md5-sess") == 0)
	{
		osip_MD5Init(&Md5Ctx);
		osip_MD5Update(&Md5Ctx, (unsigned char *) HA1, HASHLEN);
		osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
		osip_MD5Update(&Md5Ctx, (unsigned char *) pszNonce, strlen(pszNonce));
		osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
		osip_MD5Update(&Md5Ctx, (unsigned char *) pszCNonce, strlen(pszCNonce));
		osip_MD5Final((unsigned char *) HA1, &Md5Ctx);
	}
	CvtHex(HA1, SessionKey);
}

/* calculate request-digest/response-digest as per HTTP Digest spec */
void DigestCalcResponse(IN HASHHEX HA1,	/* H(A1) */
                        IN const char *pszNonce,	/* nonce from server */
                        IN const char *pszNonceCount,	/* 8 hex digits */
                        IN const char *pszCNonce,	/* client nonce */
                        IN const char *pszQop,	/* qop-value: "", "auth", "auth-int" */
                        IN int Aka,	/* Calculating AKAv1-MD5 response */
                        IN const char *pszMethod,	/* method from the request */
                        IN const char *pszDigestUri,	/* requested URL */
                        IN HASHHEX HEntity,	/* H(entity body) if qop="auth-int" */
                        OUT HASHHEX Response
                        /* request-digest or response-digest */)
{
	osip_MD5_CTX Md5Ctx;
	HASH HA2;
	HASH RespHash;
	HASHHEX HA2Hex;

	/* calculate H(A2) */
	osip_MD5Init(&Md5Ctx);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszMethod, strlen(pszMethod));
	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszDigestUri, strlen(pszDigestUri));

	if (pszQop == NULL)
	{
		goto auth_withoutqop;
	}
	else if (0 == osip_strcasecmp(pszQop, "auth-int"))
	{
		goto auth_withauth_int;
	}
	else if (0 == osip_strcasecmp(pszQop, "auth"))
	{
		goto auth_withauth;
	}

auth_withoutqop:
	osip_MD5Final((unsigned char *) HA2, &Md5Ctx);
	CvtHex(HA2, HA2Hex);

	/* calculate response */
	osip_MD5Init(&Md5Ctx);
	osip_MD5Update(&Md5Ctx, (unsigned char *) HA1, HASHHEXLEN);
	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszNonce, strlen(pszNonce));
	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);

	goto end;

auth_withauth_int:

	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	osip_MD5Update(&Md5Ctx, (unsigned char *) HEntity, HASHHEXLEN);

auth_withauth:
	osip_MD5Final((unsigned char *) HA2, &Md5Ctx);
	CvtHex(HA2, HA2Hex);

	/* calculate response */
	osip_MD5Init(&Md5Ctx);
	osip_MD5Update(&Md5Ctx, (unsigned char *) HA1, HASHHEXLEN);
	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszNonce, strlen(pszNonce));
	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	if (Aka == 0)
	{
		osip_MD5Update(&Md5Ctx, (unsigned char *) pszNonceCount,
		               strlen(pszNonceCount));
		osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
		osip_MD5Update(&Md5Ctx, (unsigned char *) pszCNonce, strlen(pszCNonce));
		osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
		osip_MD5Update(&Md5Ctx, (unsigned char *) pszQop, strlen(pszQop));
		osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	}
end:
	osip_MD5Update(&Md5Ctx, (unsigned char *) HA2Hex, HASHHEXLEN);
	osip_MD5Final((unsigned char *) RespHash, &Md5Ctx);
	CvtHex(RespHash, Response);
}

void DigestCalcMD5(IN const char *pszIN, OUT HASHHEX MD5)
{
	osip_MD5_CTX Md5Ctx;
	HASH HA1;

	osip_MD5Init(&Md5Ctx);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszIN, strlen(pszIN));
	osip_MD5Final((unsigned char *) HA1, &Md5Ctx);
	CvtHex(HA1, MD5);
}

/*"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";*/

static int base64_val(char x)
{
	switch (x)
	{
	case '=':
		return -1;
	case 'A':
		return OSIP_SUCCESS;
	case 'B':
		return 1;
	case 'C':
		return 2;
	case 'D':
		return 3;
	case 'E':
		return 4;
	case 'F':
		return 5;
	case 'G':
		return 6;
	case 'H':
		return 7;
	case 'I':
		return 8;
	case 'J':
		return 9;
	case 'K':
		return 10;
	case 'L':
		return 11;
	case 'M':
		return 12;
	case 'N':
		return 13;
	case 'O':
		return 14;
	case 'P':
		return 15;
	case 'Q':
		return 16;
	case 'R':
		return 17;
	case 'S':
		return 18;
	case 'T':
		return 19;
	case 'U':
		return 20;
	case 'V':
		return 21;
	case 'W':
		return 22;
	case 'X':
		return 23;
	case 'Y':
		return 24;
	case 'Z':
		return 25;
	case 'a':
		return 26;
	case 'b':
		return 27;
	case 'c':
		return 28;
	case 'd':
		return 29;
	case 'e':
		return 30;
	case 'f':
		return 31;
	case 'g':
		return 32;
	case 'h':
		return 33;
	case 'i':
		return 34;
	case 'j':
		return 35;
	case 'k':
		return 36;
	case 'l':
		return 37;
	case 'm':
		return 38;
	case 'n':
		return 39;
	case 'o':
		return 40;
	case 'p':
		return 41;
	case 'q':
		return 42;
	case 'r':
		return 43;
	case 's':
		return 44;
	case 't':
		return 45;
	case 'u':
		return 46;
	case 'v':
		return 47;
	case 'w':
		return 48;
	case 'x':
		return 49;
	case 'y':
		return 50;
	case 'z':
		return 51;
	case '0':
		return 52;
	case '1':
		return 53;
	case '2':
		return 54;
	case '3':
		return 55;
	case '4':
		return 56;
	case '5':
		return 57;
	case '6':
		return 58;
	case '7':
		return 59;
	case '8':
		return 60;
	case '9':
		return 61;
	case '+':
		return 62;
	case '/':
		return 63;
	}
	return OSIP_SUCCESS;
}


char *base64_decode_string(const char *buf, unsigned int len, int *newlen)
{
	unsigned int i, j;
	int x1, x2, x3, x4;
	char *out;
	out = (char *) osip_malloc((len * 3 / 4) + 8);
	if (out == NULL)
	{
		return NULL;
	}
	for (i = 0, j = 0; i + 3 < len; i += 4)
	{
		x1 = base64_val(buf[i]);
		x2 = base64_val(buf[i + 1]);
		x3 = base64_val(buf[i + 2]);
		x4 = base64_val(buf[i + 3]);
		out[j++] = (x1 << 2) | ((x2 & 0x30) >> 4);
		out[j++] = ((x2 & 0x0F) << 4) | ((x3 & 0x3C) >> 2);
		out[j++] = ((x3 & 0x03) << 6) | (x4 & 0x3F);
	}
	if (i < len)
	{
		x1 = base64_val(buf[i]);
		if (i + 1 < len)
		{
			x2 = base64_val(buf[i + 1]);
		}
		else
		{
			x2 = -1;
		}
		if (i + 2 < len)
		{
			x3 = base64_val(buf[i + 2]);
		}
		else
		{
			x3 = -1;
		}
		if (i + 3 < len)
		{
			x4 = base64_val(buf[i + 3]);
		}
		else
		{
			x4 = -1;
		}
		if (x2 != -1)
		{
			out[j++] = (x1 << 2) | ((x2 & 0x30) >> 4);
			if (x3 == -1)
			{
				out[j++] = ((x2 & 0x0F) << 4) | ((x3 & 0x3C) >> 2);
				if (x4 == -1)
				{
					out[j++] = ((x3 & 0x03) << 6) | (x4 & 0x3F);
				}
			}
		}
	}

	out[j++] = 0;
	*newlen = j;
	return out;
}

char base64[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64_encode_string(const char *buf, unsigned int len, int *newlen)
{
	int i, k;
	int triplets, rest;
	char *out, *ptr;

	triplets = len / 3;
	rest = len % 3;
	out = (char *) osip_malloc((triplets * 4) + 8);
	if (out == NULL)
	{
		return NULL;
	}

	ptr = out;
	for (i = 0; i < triplets * 3; i += 3)
	{
		k = (((unsigned char) buf[i]) & 0xFC) >> 2;
		*ptr = base64[k];
		ptr++;

		k = (((unsigned char) buf[i]) & 0x03) << 4;
		k |= (((unsigned char) buf[i + 1]) & 0xF0) >> 4;
		*ptr = base64[k];
		ptr++;

		k = (((unsigned char) buf[i + 1]) & 0x0F) << 2;
		k |= (((unsigned char) buf[i + 2]) & 0xC0) >> 6;
		*ptr = base64[k];
		ptr++;

		k = (((unsigned char) buf[i + 2]) & 0x3F);
		*ptr = base64[k];
		ptr++;
	}
	i = triplets * 3;
	switch (rest)
	{
	case 0:
		break;
	case 1:
		k = (((unsigned char) buf[i]) & 0xFC) >> 2;
		*ptr = base64[k];
		ptr++;

		k = (((unsigned char) buf[i]) & 0x03) << 4;
		*ptr = base64[k];
		ptr++;

		*ptr = '=';
		ptr++;

		*ptr = '=';
		ptr++;
		break;
	case 2:
		k = (((unsigned char) buf[i]) & 0xFC) >> 2;
		*ptr = base64[k];
		ptr++;

		k = (((unsigned char) buf[i]) & 0x03) << 4;
		k |= (((unsigned char) buf[i + 1]) & 0xF0) >> 4;
		*ptr = base64[k];
		ptr++;

		k = (((unsigned char) buf[i + 1]) & 0x0F) << 2;
		*ptr = base64[k];
		ptr++;

		*ptr = '=';
		ptr++;
		break;
	}

	*newlen = ptr - out;
	return out;
}



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
        printf("open file %s error  \n",filePath);  
        return -2;  
    }  

	if(NULL == data)
		return -1;
  
    fseek(fp,0,SEEK_END);  
    filesize = ftell(fp);  


	memset(data,0,filesize+1);  
    rewind(fp);  
    

	//fgets�����ɹ�������buf��ʧ�ܻ�����ļ���β����NULL��
    //������ǲ���ֱ��ͨ��fgets�ķ���ֵ���жϺ����Ƿ��ǳ������ֹ�ģ�
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
	ret = replace_string(data,tmp1,devIdFlag,sipData->deviceId);
	
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
        fprintf(stderr,"open file %s error! \n",filePath);  
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



/*����ע����ϢregisterFlag = 1: ע�� 0 : ע��*/
int sipFree(struct sip_data_t * sipData)  
{
	int i 				= 0;
	int size			= 100;
	
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
	if(NULL != sipData->deviceId)
	free(sipData->deviceId );
	if(NULL != sipData->userAgent)
	free(sipData->userAgent);
	if(NULL != sipData->logFilePath)
	free(sipData->logFilePath);

	eXosip_quit(sipData->context_eXosip);
        osip_free (sipData->context_eXosip);


	//printf();

	return 0;
}




/*��ʼ��������
�����ļ��еĲ�������ʼ��sipData�ṹ���е��������
�˺���Ҳ�費�ϵظ���*/
int initSipDataFromFile(char *filePath , struct sip_data_t * sipData )  
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

	time_t nowtim;
	struct tm *tm_now ;
	
	
	if(NULL == sipData)
		return -1;


	sipData->context_eXosip = eXosip_malloc ();
        sipData->stop_keepalive = 0;
        sipData->stop_resp = 0;
	sipData->clientId		= (char*)malloc(30);
	sipData->clientAdress	= (char*)malloc(30);
	sipData->password 		= (char*)malloc(30);
	sipData->serverId		= (char*)malloc(30);
	sipData->serverAdress 	= (char*)malloc(30);
	sipData->deviceId 		= (char*)malloc(40);
	sipData->userAgent 		= (char*)malloc(40);
	sipData->logFilePath	= (char*)malloc(100);
	sipData->selfPhoneNumber= (char*)malloc(100);
	
	/*�˴����file��û����Ӧֵ��Ĭ��ֵ*/
	sipData->clientPort		= 5060;
	sipData->serverPort		= 5060;
	sipData->SNId			= 0;
	sipData->expire			= 3600;//ע��ʧЧʱ��
	sipData->registerFlag 	= 0; //Ĭ�ϻ�û��ע��
	sipData->sendDelay		= 200;//΢��
	sipData->sendRunNumber	= 0;//��Ȩ�ط�������
	sipData->sendTotalNum	= 0;
	sipData->sendAliveNum	= 0;
	sipData->recv200OkNum	= 0;
	sipData->recvFailNum	= 0;
	sipData->selfPhoneNumber= "038804000001";


    //fprintf(stderr, "======Start to init sip project!======\n");
	//printf("======Start to user sip data file : %s init======\n",filePath);

	if ((fp=fopen(filePath,"r"))==NULL){  
        printf("open file %s error! \n",filePath);  
		sipFree(sipData);
        return -1;  
    }  

    fseek(fp,0,SEEK_END);  
    rewind(fp);  
     
    //�ַ����������ݻ�ȡ
    while((ret = fscanf(fp,"%s %s %s",para,speator,value)) == 3)
	{  	
		
        if(0 == strcmp(para,"clientId"))
        {
        	strcpy(sipData->clientId,value);
        }
		else if(0 == strcmp(para,"clientAdress"))
        {
        	strcpy(sipData->clientAdress,value);
        }
		else if(0 == strcmp(para,"password"))
        {
        	strcpy(sipData->password,value);
        }
		else if(0 == strcmp(para,"serverId"))
        {
        	strcpy(sipData->serverId,value);
        }
		else if(0 == strcmp(para,"serverAdress"))
        {
        	strcpy(sipData->serverAdress,value);
        }
		else if(0 == strcmp(para,"deviceId"))
        {
        	strcpy(sipData->deviceId,value);
        }
		else if(0 == strcmp(para,"userAgent"))
        {
        	strcpy(sipData->userAgent,value);
        }
		else if(0 == strcmp(para,"selfPhoneNumber"))
        {
        	strcpy(sipData->selfPhoneNumber,value);
        }

		//�������Ͳ�����ȡ
		if(0 == strcmp(para,"clientPort"))
		{
			sscanf( value, "%d", &tmp );   
			sipData->clientPort = tmp;
		}
		else if(0 == strcmp(para,"serverPort"))
		{
			sscanf( value, "%d", &tmp );
			sipData->serverPort = tmp;
		}
		else if(0 == strcmp(para,"SNId"))
		{
			sscanf( value, "%d", &tmp );
			sipData->SNId= tmp;
		}
		else if(0 == strcmp(para,"expire"))
		{
			sscanf( value, "%d", &tmp );
			sipData->expire = tmp;
		}
		else if(0 == strcmp(para,"sendDelay"))
		{
			sscanf( value, "%d", &tmp );
			sipData->sendDelay = tmp;
		}
		else if(0 == strcmp(para,"sendRunNumber"))
		{
			sscanf( value, "%d", &tmp );
			sipData->sendRunNumber = tmp;
		}


		//kkk����ֵΪ��ȡ��Ч���ݵĸ���
		//kkk = sscanf( value, "%d", &tmp );
		//printf("para=%s, value=%s\n",para,value);
		//fprintf(stderr, "para=%s, value=%s\n",para,value);
			
	}





	//��ʼ����Ӧ��response���������б�
	for(i = 0;i<size;i++)
		sipData->responseList[i] = (char*)malloc(50);
	

	resListNum = getResponseList("./ResponseMeg/responseList.ini", sipData->responseList,size) ;

	//fprintf(stderr,"resListNum =%d\n",resListNum);
	sipData->resListNum = resListNum;




    //��ʼ��
    i=eXosip_init(sipData->context_eXosip);

    if(i!=0)
    {
        fprintf(stderr,"Couldn't initialize eXosip!\n");
		sipFree(sipData);
        return -1;
    }
    else
    {
        //fprintf(stderr,"eXosip_init successfully!\n");
    }

    

	//���Լ��Ķ˿�ClientPort�������ж˿ڼ���
    ret = eXosip_listen_addr(sipData->context_eXosip, IPPROTO_UDP,NULL,sipData->clientPort,AF_INET,0);
    if(ret != 0)
    {
        eXosip_quit(sipData->context_eXosip);
        fprintf(stderr,"Couldn't initialize transport layer!\n");
		sipFree(sipData);
        return -1;
    }

	eXosip_set_user_agent(sipData->context_eXosip,sipData->userAgent);

    fclose(fp);  
	
	fflush(stdout);
	fflush(stderr);
	

    return 0;  
}  


int sipInvite(struct sip_data_t * sipData, char* callNumber)  
{   
    char fromuser[256]={0};  
    char proxy[256]={0};  
	osip_message_t *invite=NULL;
    osip_message_t *ack=NULL;
	int ret = 0;
	int flag1 = 0;
	eXosip_event_t *je;
	char tmp[4096]={0};

	//printf("[%s,%d]======send invite1()======\n",__FUNCTION__,__LINE__);  
	

	if(NULL == sipData->context_eXosip || NULL == sipData->clientId || NULL == sipData->clientAdress
		|| NULL == sipData->serverAdress || NULL == sipData->serverId|| NULL == sipData->deviceId
		|| NULL == sipData->selfPhoneNumber || NULL == callNumber)
		return -1;


    sprintf(proxy,"sip:%s@%s:%d",callNumber,sipData->serverAdress,sipData->serverPort);  
 	sprintf(fromuser,"sip:%s@%s",sipData->selfPhoneNumber,sipData->clientAdress);

	printf("fromuser --> %s\n",fromuser);
	printf("proxy --> %s\n",proxy);

	

	//sprintf(fromuser,"sip:038804000001@172.16.20.1"); //�����ſڻ�
	//sprintf(proxy,"sip:048804050501@192.168.0.247:5060");//���ڻ�
	//sprintf(proxy,"sip:019999999901@192.168.0.247:5060");//����
	//sprintf(proxy,"sip:019999998801@192.168.0.247:5060");//�����

	snprintf(tmp,4096,
				"v=0\r\n"
				"o=000211252111 0 0 IN IP4 172.16.20.237\r\n"
				"s=Talk session\r\n"
				"c=IN IP4 172.16.20.237\r\n"
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
				"a=sendrecv\r\n"
				);


	ret = eXosip_call_build_initial_invite(sipData->context_eXosip, &invite,proxy,fromuser,NULL,"This is a call invite");
	if(ret!=0)
	{
		printf("Initial INVITE failed!\n");
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
		printf("please invite firstly\n");
		return -1;
	}
	else
	{
		printf("****send the INFO ****\n%s\n\n",mes);
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

	
	//fprintf(stderr,"****send the MESSAGE ****\n%s\n\n",mes);

	if(NULL == sipData->context_eXosip || NULL == sipData->clientId || NULL == sipData->clientAdress
		|| NULL == sipData->serverAdress || NULL == sipData->serverId|| NULL == sipData->deviceId)
		return -1;

    sprintf(fromuser,"sip:%s@%s",sipData->clientId,sipData->clientAdress);  

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

	fflush(stdout);
	fflush(stderr);


	return 0;
}







/*����ע����ϢregisterFlag = 1: ע�� 0 : ע��*/
int sipRegister(struct sip_data_t * sipData)  
  
{   
    char fromuser[256]={0};  
    char proxy[256]={0};  
    char route[256]={0};  
	osip_message_t *reg = NULL;
	eXosip_event_t *je;
	int ret 		= 0;
	int flag1 		= 0;
	int regid		= 0;//ע��id 
	int expire		= 0;



	if(NULL == sipData->context_eXosip || NULL == sipData->clientId || NULL == sipData->clientAdress
		|| NULL == sipData->serverAdress || NULL == sipData->serverId|| NULL == sipData->deviceId)
		return -1;

	//printf("[%s,%d]======Register(%s:%d)======\n",__FUNCTION__,__LINE__,sipData->clientAdress,sipData->clientPort);  
	
	
	if(1 == sipData->registerFlag)
	{
		expire = sipData->expire;
	}

	/*
	sprintf(fromuser,"sip:%s@%s",user,"127.0.0.1");  
    sprintf(proxy,"sip:%s@%s","133","127.0.0.1:15061");  
    sprintf(route,"<sip:%s:%d;lr>","127.0.0.1:15061",35060);  
  	*/
 
    sprintf(fromuser,"sip:%s@%s",sipData->clientId,sipData->clientAdress);  

	if(sipData->serverPort > 0)
    	sprintf(proxy,"sip:%s@%s:%d",sipData->serverId,sipData->serverAdress,sipData->serverPort);  
	else
		sprintf(proxy,"sip:%s@%s",sipData->serverId,sipData->serverAdress);
  

	eXosip_clear_authentication_info(sipData->context_eXosip);  
      
    regid = eXosip_register_build_initial_register(sipData->context_eXosip, 
							fromuser, proxy, NULL, expire, &reg);  




	ret = eXosip_register_send_register(sipData->context_eXosip, regid, reg);
	if(ret !=0)  //����ʧ�ܣ�û��ע��ɹ�
	{
		fprintf(stderr,"[%s,%d]======Register err ret=%d======\n",__FUNCTION__,__LINE__,ret);  
    	return -1; 
	}


	//������ע����Ϣ���ȴ�Ӧ��
    flag1=1;
    while(flag1)
    {
    	//Wait for an eXosip event
        je=eXosip_event_wait(sipData->context_eXosip, 0, 200); 
        //(��ʱʱ���룬��ʱʱ�����)
        if(je==NULL)
        {
        	printf("[%s,%d]======No response or the timeout(%s:%d)!======\n",__FUNCTION__,__LINE__,sipData->clientAdress,sipData->clientPort);
			break;
        }

		
		//printf("registerrrr jeeeee type =%d\n",je->type);

		if(EXOSIP_REGISTRATION_SUCCESS == je->type)
		{
			//printf("[%s,%d]======register sccess(%s:%d)!=====\n",__FUNCTION__,__LINE__,sipData->clientAdress,sipData->clientPort);
			flag1=0; //�˳�Whileѭ��
			eXosip_event_free(je);
			break;
		}
        else if(EXOSIP_REGISTRATION_FAILURE == je->type)   //���ܻᵽ�����¼�����
        {
			//fprintf(stderr,"[%s,%d]======register fail Try rid=%d======\n",__FUNCTION__,__LINE__,je->rid);	

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
					fprintf(stderr,"[%s,%d]======eXosip_register_build_register fail=====\n",__FUNCTION__,__LINE__); 
					eXosip_event_free(je);

					continue;  
				}  

				
				//fprintf(stderr,"[%s,%d]======authenticate=%s  ver=%s======\n\n",__FUNCTION__,__LINE__,
				//				realm,reg->sip_version); 
	
				eXosip_register_send_register(sipData->context_eXosip, je->rid,reg);	
				eXosip_unlock(sipData->context_eXosip);   
			  
			}  
			else
			{
				fprintf(stderr,"[%s,%d]======other response(%s:%d)!======\n\n",__FUNCTION__,__LINE__,sipData->clientAdress,sipData->clientPort); 
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

		//printf("hvalue = %s\n",hvalue);
		
		sprintf(now, "%.4d-%.2d-%.2dT%.2d:%.2d:%.2d\n",
		    tm_now->tm_year+1900, tm_now->tm_mon+1,tm_now->tm_mday, tm_now->tm_hour, 
		    tm_now->tm_min, tm_now->tm_sec);

		osip_message_set_header(answer, "time", now);
		
		//osip_message_set_body(answer, now, strlen(now));
		//osip_message_set_content_type(answer, "Application/TIME");
		printf("1.server send 401 packet\n");
	}
	else if (status == 200)
	{

		time_t nowtim ;
        struct tm *tm_now ;
		char now[128] = {0};

        time(&nowtim) ;
        tm_now = localtime(&nowtim) ;
		
		
		sprintf(now, "%.4d-%.2d-%.2d %.2d:%.2d:%.2d\n",
					tm_now->tm_year+1900, tm_now->tm_mon+1,tm_now->tm_mday, tm_now->tm_hour, 
					tm_now->tm_min, tm_now->tm_sec);
				

		osip_message_set_header(answer, "time", now);
		//osip_message_set_body(answer, now, strlen(now));
		//osip_message_set_content_type(answer, "Application/TIME");
		printf("2.server send 200 packet\n");
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
	char deviceId[20]	=	"";
	char devIdFlag[20] 	= 	"===DEVID===";
	char tmp1[4096]		=	{0}; 
	char tmp2[4096]		=	{0}; 
	int ret = 0;


	strcpy(tmp1,data);

	//�滻�ı�message�е�SNid
	ret = replace_string(tmp2,tmp1,SNFlag,snid);

	//�滻�ı�message�е�deviceId
	ret = replace_string(tmp1,tmp2,devIdFlag,sipData->deviceId);

	strcpy(data,tmp1);
    return 0;  
}  



/*
���յ�Message������
�������󲻶����
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
	char *fileName 	= (char*)malloc(100);

	osip_body_t *body;
	osip_message_t *answer	= NULL;


	//fprintf(stderr,"######receive a message #####\n");
	
	if (MSG_IS_MESSAGE (je->request))
	{
		/*�ͻ���: ������ܵ�����Ϣ������MESSAGE*/
		osip_message_get_body (je->request, 0, &body);
		//fprintf(stderr,"The coming msg body is: \n%s\n", body->body);

		/*1.���չ�����Ҫ�ظ�OK��Ϣ*/
		eXosip_message_build_answer (sipData->context_eXosip,je->tid, 200,&answer);
		eXosip_message_send_answer (sipData->context_eXosip,je->tid, 200,answer);


		/*2.�����response ��Ϣ������Ҫ��һ�������ظ�*/
		ret = findStrFromMessage(body->body,Response,ResponseValue);
		if(0 == ret)
		{
			//fprintf(stderr,"This is a Response message\n");
			
			free(fileName);
			return 0;
		}

		/*2.�����notify ��Ϣ������Ҫ��һ�������ظ�*/
		ret = findStrFromMessage(body->body,Notify,NotifyValue);
		if(0 == ret)
		{
			fprintf(stderr,"This is a Notify(like keepalive) message\n");
			free(fileName);
			return 0;
		}



		findStrFromMessage(body->body,CmdType,Cmd);
		findStrFromMessage(body->body,SN,SNId);
		//fprintf(stderr,"CmdType =%s,SNId =%s\n", Cmd, SNId);

		/*3.���ݽ��յ�����Ϣ�壬��ȡ���е�SNId,Ȼ���һ���ظ���Ӧ��Ϣrespnse*/


		for(i = 0;i < sipData->resListNum;i++)
		{
			if(0==strcmp(Cmd,sipData->responseList[i]))
			{
				snprintf(fileName,100,"./ResponseMeg/%s.txt",Cmd);
				//printf("filename  =%s\n",fileName);

				getMessageFromFile(fileName,tmp);
				convertMessageForResponse(sipData,tmp,SNId);
				flag = 1;
				break;
			}

		}



		if(flag)
		{
			//fprintf(stderr,"====I will send message ==== \n %s\n",fileName);
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

			//printf("pszRes = %s\n Resp = %s\n", pszResponse, Response);


			
			if (strcmp(pszResponse, Response) == 0)
			{
				osip_via_t *via = NULL;

				osip_message_get_via(je->request, 0, &via);
				if (via)
				{
					
					osip_generic_param_t *received = NULL;
					osip_generic_param_t *rport = NULL;

					fprintf(stderr,"user:%s, host:%s, port:%s\n", pszUserName, via->host, via->port);


					osip_via_param_get_byname(via, "received", &received);
					osip_via_param_get_byname(via, "rport", &rport);
					if (received && rport)
					{
						//fprintf(stderr,"ip:%d, port:%d\n", received->gvalue, rport->gvalue);
					}
				}

				/*3.��Ȩ�ɹ����ظ�200 OK*/
				fprintf(stderr,"I will send 200 OK\n");
				SendRegisterAnswer(sipData->context_eXosip,je, 200);
			}
			else
			{
				/*3.��Ȩʧ�ܣ��ظ�403 ����*/
				fprintf(stderr,"user name pass error\n");
				fprintf(stderr,"I will send 403 error\n");
				SendRegisterAnswer(sipData->context_eXosip,je, 403);
			}
		}
	}

	fflush(stdout);
	fflush(stderr);
	free(fileName);

	
	return 0;
}


//���յ���Ϣ�������߳�
void* sipResponseThread(void * arg)
{
	int ret 				= 0;
	int call_id 			= 0;
	int dialog_id 			= 0;
	char tmp[4096]			= {0};
    int pos 				= 0;
	eXosip_event_t *je;
	osip_message_t *ack		= NULL;
	osip_message_t *answer 	= NULL;
	sdp_message_t *remote_sdp = NULL;
    osip_body_t *body;
	
	struct sip_data_t * sipData;
	
	
	sipData =(struct sip_data_t *) arg;
		


	while(!sipData->stop_resp)
    {
        //�����Ƿ�����Ϣ����
        //je = eXosip_event_wait (sipData->context_eXosip, 0, 50);
		je = eXosip_event_wait (sipData->context_eXosip, 0, 50);
		//û�н��յ���Ϣ
		if (je == NULL)
            continue;
		
        eXosip_lock (sipData->context_eXosip);
        eXosip_default_action (sipData->context_eXosip,je);	
        //eXosip_automatic_action(sipData->context_eXosip);
	
        //printf("jeeeee type =%d\n",je->type);
        switch (je->type)
        {
		/*1.invite:��Ϊ�������ˣ��յ�һ��INVITE����*/
		case EXOSIP_CALL_INVITE:
			//�õ����յ���Ϣ�ľ�����Ϣ
			fprintf(stderr,"Received a INVITE msg from %s:%s, UserName is %s, password is %s\n",je->request->req_uri->host,
					je->request->req_uri->port, je->request->req_uri->username, je->request->req_uri->password);
			//�õ���Ϣ��,��Ϊ����Ϣ����SDP��ʽ.
			remote_sdp = eXosip_get_remote_sdp (sipData->context_eXosip,je->did);
			call_id = je->cid;
			dialog_id = je->did;


			//eXosip_lock (sipData->context_eXosip);
			eXosip_call_send_answer (sipData->context_eXosip,je->tid, 180, NULL);
			ret = eXosip_call_build_answer (sipData->context_eXosip,je->tid, 200, &answer);
			if (ret != 0)
			{
				fprintf(stderr,"This request msg is invalid!Cann't response!\n");
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
				printf ("send 200 over!\n");
			}
			//eXosip_unlock (sipData->context_eXosip);

			
			pos=0;///add by kalen
			//��ʾ����sdp��Ϣ���е�attribute ������,����ƻ�������ǵ���Ϣ
			printf ("the INFO is :\n");
			while (!osip_list_eol ( &(remote_sdp->a_attributes), pos))
			{
				sdp_attribute_t *at;

				at = (sdp_attribute_t *) osip_list_get ( &remote_sdp->a_attributes, pos);
				printf ("%s : %s\n", at->a_att_field, at->a_att_value);//���������Ϊʲô��SDP��Ϣ��������a�����ű���������

				pos ++;
			}

			break;


		/*2.invite �ͻ��ˣ�����5��call��Ϣ���յ�����������������Ӧ��Ϣ*/
       case EXOSIP_CALL_PROCEEDING: //�յ�100 trying��Ϣ����ʾ�������ڴ�����
            printf("proceeding!\n");
            break;
        case EXOSIP_CALL_RINGING:   //�յ�180 RingingӦ�𣬱�ʾ���յ�INVITE�����UAS�����򱻽��û�����
            printf("ringing!\n");
            printf("call_id is %d,dialog_id is %d \n",je->cid,je->did);
			sipData->call_id = je->cid;
            sipData->dialog_id = je->did;


/*
			printf("Received a INVITE msg from %s:%s, UserName is %s, password is %s\n",je->request->req_uri->host,
					je->request->req_uri->port, je->request->req_uri->username, je->request->req_uri->password);

			//�õ���Ϣ��,��Ϊ����Ϣ����SDP��ʽ.
			remote_sdp = eXosip_get_remote_sdp (sipData->context_eXosip,je->did);
			pos=0;///add by kalen
			//��ʾ����sdp��Ϣ���е�attribute ������,����ƻ�������ǵ���Ϣ
			printf ("the INFO is :\n");
			while (!osip_list_eol ( &(remote_sdp->a_attributes), pos))
			{
				sdp_attribute_t *at;

				at = (sdp_attribute_t *) osip_list_get ( &remote_sdp->a_attributes, pos);
				printf ("%s : %s\n", at->a_att_field, at->a_att_value);//���������Ϊʲô��SDP��Ϣ��������a�����ű���������

				pos ++;
			}
*/
			
            break;
		case EXOSIP_CALL_ANSWERED: //�յ�200 OK����ʾ�����Ѿ����ɹ����ܣ��û�Ӧ��
            printf("ok!connected!\n");
            sipData->call_id = je->cid;
            sipData->dialog_id = je->did;
            printf("!!call_id is %d,dialog_id is %d \n",je->cid,je->did);

/*
			printf("Received a INVITE msg from %s:%s, UserName is %s, password is %s\n",je->request->req_uri->host,
					je->request->req_uri->port, je->request->req_uri->username, je->request->req_uri->password);
			//�õ���Ϣ��,��Ϊ����Ϣ����SDP��ʽ.

			remote_sdp = eXosip_get_remote_sdp (sipData->context_eXosip,je->did);
			pos=0;///add by kalen
			//��ʾ����sdp��Ϣ���е�attribute ������,����ƻ�������ǵ���Ϣ
			printf ("the INFO is :\n");
			while (!osip_list_eol ( &(remote_sdp->a_attributes), pos))
			{
				sdp_attribute_t *at;

				at = (sdp_attribute_t *) osip_list_get ( &remote_sdp->a_attributes, pos);
				printf ("%d: %s : %s\n", pos,at->a_att_field, at->a_att_value);//���������Ϊʲô��SDP��Ϣ��������a�����ű���������

				pos ++;
			}
*/
            //����ackӦ����Ϣ
            eXosip_call_build_ack(sipData->context_eXosip, je->did, &ack);
            eXosip_call_send_ack(sipData->context_eXosip, je->did, ack);
            //flag1=0; //�Ƴ�Whileѭ��
            break;

		case EXOSIP_CALL_CLOSED:
            printf ("the remote hold the session!\n");
            
			ret = eXosip_call_build_answer (sipData->context_eXosip, je->tid, 200, &answer);
            if (ret != 0)
            {
                printf ("This request msg is invalid!Cann't response!\n");
                eXosip_call_send_answer (sipData->context_eXosip, je->tid, 400, NULL);
            }
            else
            {
                eXosip_call_send_answer (sipData->context_eXosip, je->tid, 200, answer);
                printf ("bye send 200 over!\n");
            }
            break;
        case EXOSIP_CALL_ACK: //ACK received for 200ok to INVITE
            printf("ACK received!\n");
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
            //fprintf(stderr," EXOSIP_MESSAGE_NEW!\n");
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
             ��Ҳ���Ǻ����ף�����ǣ�
             EXOSIP_CALL_MESSAGE_NEW��һ�������е��µ���Ϣ����������ring trying���㣬�����ڽ��ܵ�������ж�
             ����Ϣ���ͣ�EXOSIP_MESSAGE_NEW���Ǳ�ʾ���Ǻ����ڵ���Ϣ������
            */
            fprintf(stderr," EXOSIP_CALL_MESSAGE_NEW\n");
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
                printf ("the body is %s\n", body->body);
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
			//printf("jee type =%d\n",je->type);
			fprintf(stderr,"Could not parse the msg!\n");
            break;
        }

		fflush(stdout);
		fflush(stderr);



		if(NULL!= je)
		eXosip_event_free(je);

		if(NULL!=remote_sdp)
			free(remote_sdp);
		if(NULL!=body)
			free(body);


		eXosip_unlock (sipData->context_eXosip);
	


		
    }


	//sipFree(sipData);
}








