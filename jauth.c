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



/*将字符串source中的s1子串替换为s2字串*/
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


/*从XML消息message中查找关键字key的值*/
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



/*把文件file中内容作为message data*/
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
    

	//fgets函数成功将返回buf，失败或读到文件结尾返回NULL。
    //因此我们不能直接通过fgets的返回值来判断函数是否是出错而终止的，
    //应该借助feof函数或者ferror函数来判断。  
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
将data的内容中的格式如===SNID===，
使用config中的相应参数替换,
此函数需不断完善
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
	
	//替换文本message中的SNid,deviceId
	snprintf(newSNId,20,"%d",sipData->SNId);
	
	strcpy(tmp1,data);
	ret = replace_string(data,tmp1,SNFlag,newSNId);
	
	strcpy(tmp1,data);
	ret = replace_string(data,tmp1,devIdFlag,sipData->deviceId);
	
	strcpy(tmp1,data);
	ret = replace_string(data,tmp1,timeFlag,now);
	

    return 0;  
}  


//获取响应的response报文名字列表
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



/*发送注册消息registerFlag = 1: 注册 0 : 注销*/
int sipFree(struct sip_data_t * sipData)  
{
	int i 				= 0;
	int size			= 100;
	
	//初始化响应的response报文名字列表
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




/*初始化函数，
根据文件中的参数来初始化sipData结构体中点参数变量
此函数也需不断地更新*/
int initSipDataFromFile(char *filePath , struct sip_data_t * sipData )  
{  
    FILE *fp;  
	char para[30] 		= ""; 	//参数名
	char value[30] 		= "";	    //参数值
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
	
	/*此处如果file中没有相应值得默认值*/
	sipData->clientPort		= 5060;
	sipData->serverPort		= 5060;
	sipData->SNId			= 0;
	sipData->expire			= 3600;//注册失效时间
	sipData->registerFlag 	= 0; //默认还没有注册
	sipData->sendDelay		= 200;//微秒
	sipData->sendRunNumber	= 0;//按权重发包开关
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
     
    //字符串类型数据获取
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

		//整数类型参数获取
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


		//kkk返回值为读取有效数据的个数
		//kkk = sscanf( value, "%d", &tmp );
		//printf("para=%s, value=%s\n",para,value);
		//fprintf(stderr, "para=%s, value=%s\n",para,value);
			
	}





	//初始化响应的response报文名字列表
	for(i = 0;i<size;i++)
		sipData->responseList[i] = (char*)malloc(50);
	

	resListNum = getResponseList("./ResponseMeg/responseList.ini", sipData->responseList,size) ;

	//fprintf(stderr,"resListNum =%d\n",resListNum);
	sipData->resListNum = resListNum;




    //初始化
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

    

	//绑定自己的端口ClientPort，并进行端口监听
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

	

	//sprintf(fromuser,"sip:038804000001@172.16.20.1"); //主叫门口机
	//sprintf(proxy,"sip:048804050501@192.168.0.247:5060");//室内机
	//sprintf(proxy,"sip:019999999901@192.168.0.247:5060");//大屏
	//sprintf(proxy,"sip:019999998801@192.168.0.247:5060");//管理机

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



/*必须先invite连接成功了，才能发送info消息*/
int sendInfo(struct sip_data_t * sipData, int dialog_id,char * mes,char * mesType)
{
	osip_message_t *info=NULL;
	int ret = 0;

	if(NULL == sipData->context_eXosip || NULL == mes|| NULL == mesType)
		return -1;

	

	//格式可以任意设定，mesType = text/plain代表文本信息;
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
	传输MESSAGE方法，也就是即时消息，
 	MESSAGE不用建立连接，直接传输信息
 	每发送一个message ，SNID 就要递增
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

	//每发送一个message ，SNID 就要递增
	(sipData->SNId)++;
	(sipData->sendTotalNum)++;

	fflush(stdout);
	fflush(stderr);


	return 0;
}







/*发送注册消息registerFlag = 1: 注册 0 : 注销*/
int sipRegister(struct sip_data_t * sipData)  
  
{   
    char fromuser[256]={0};  
    char proxy[256]={0};  
    char route[256]={0};  
	osip_message_t *reg = NULL;
	eXosip_event_t *je;
	int ret 		= 0;
	int flag1 		= 0;
	int regid		= 0;//注册id 
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
	if(ret !=0)  //发送失败，没有注册成功
	{
		fprintf(stderr,"[%s,%d]======Register err ret=%d======\n",__FUNCTION__,__LINE__,ret);  
    	return -1; 
	}


	//发送了注册消息，等待应答
    flag1=1;
    while(flag1)
    {
    	//Wait for an eXosip event
        je=eXosip_event_wait(sipData->context_eXosip, 0, 200); 
        //(超时时间秒，超时时间毫秒)
        if(je==NULL)
        {
        	printf("[%s,%d]======No response or the timeout(%s:%d)!======\n",__FUNCTION__,__LINE__,sipData->clientAdress,sipData->clientPort);
			break;
        }

		
		//printf("registerrrr jeeeee type =%d\n",je->type);

		if(EXOSIP_REGISTRATION_SUCCESS == je->type)
		{
			//printf("[%s,%d]======register sccess(%s:%d)!=====\n",__FUNCTION__,__LINE__,sipData->clientAdress,sipData->clientPort);
			flag1=0; //退出While循环
			eXosip_event_free(je);
			break;
		}
        else if(EXOSIP_REGISTRATION_FAILURE == je->type)   //可能会到来的事件类型
        {
			//fprintf(stderr,"[%s,%d]======register fail Try rid=%d======\n",__FUNCTION__,__LINE__,je->rid);	

			if(je->response && je->response->status_code==401)  
			{  
				char realm[256]; 
				osip_message_t *reg = NULL; 
				osip_www_authenticate_t *dest = NULL;  
				HASHHEX pwd_md5;
				

				//根据服务器返回的携带鉴权消息再重新发注册申请
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
		return -2;//不正确的返回，没有注册成功
	else
		return 0; //注册成功
} 



/*作为服务器端的调用，接收到注册消息后
	1.回复401带鉴权消息，
	2.回复200 OK 消息带系统时间*/
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



//使用发过来的消息里的SNID
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

	//替换文本message中的SNid
	ret = replace_string(tmp2,tmp1,SNFlag,snid);

	//替换文本message中的deviceId
	ret = replace_string(tmp1,tmp2,devIdFlag,sipData->deviceId);

	strcpy(data,tmp1);
    return 0;  
}  



/*
接收到Message处理函数
根据需求不断添加
此函数也需不断更新
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
		/*客户端: 如果接受到的消息类型是MESSAGE*/
		osip_message_get_body (je->request, 0, &body);
		//fprintf(stderr,"The coming msg body is: \n%s\n", body->body);

		/*1.按照规则，需要回复OK信息*/
		eXosip_message_build_answer (sipData->context_eXosip,je->tid, 200,&answer);
		eXosip_message_send_answer (sipData->context_eXosip,je->tid, 200,answer);


		/*2.如果是response 消息，则不需要进一步继续回复*/
		ret = findStrFromMessage(body->body,Response,ResponseValue);
		if(0 == ret)
		{
			//fprintf(stderr,"This is a Response message\n");
			
			free(fileName);
			return 0;
		}

		/*2.如果是notify 消息，则不需要进一步继续回复*/
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

		/*3.根据接收到的消息体，获取其中的SNId,然后进一步回复响应消息respnse*/


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
		/*服务器端: 此处是作为服务器端接收到注册请求后的处理*/
	
		osip_authorization_t *auth = NULL;
		osip_message_get_authorization(je->request, 0, &auth);

		/*1.如果没有鉴权消息回复401报文，回复的报文中携带服务器的鉴权消息*/
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


			/*2.如果有鉴权消息则对报文携带的鉴权消息进行判定*/

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

				/*3.鉴权成功，回复200 OK*/
				fprintf(stderr,"I will send 200 OK\n");
				SendRegisterAnswer(sipData->context_eXosip,je, 200);
			}
			else
			{
				/*3.鉴权失败，回复403 错误*/
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


//接收到消息处理函数线程
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
        //侦听是否有消息到来
        //je = eXosip_event_wait (sipData->context_eXosip, 0, 50);
		je = eXosip_event_wait (sipData->context_eXosip, 0, 50);
		//没有接收到消息
		if (je == NULL)
            continue;
		
        eXosip_lock (sipData->context_eXosip);
        eXosip_default_action (sipData->context_eXosip,je);	
        //eXosip_automatic_action(sipData->context_eXosip);
	
        //printf("jeeeee type =%d\n",je->type);
        switch (je->type)
        {
		/*1.invite:作为服务器端，收到一个INVITE请求*/
		case EXOSIP_CALL_INVITE:
			//得到接收到消息的具体信息
			fprintf(stderr,"Received a INVITE msg from %s:%s, UserName is %s, password is %s\n",je->request->req_uri->host,
					je->request->req_uri->port, je->request->req_uri->username, je->request->req_uri->password);
			//得到消息体,认为该消息就是SDP格式.
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

				//设置回复的SDP消息体,下一步计划分析消息体
				//没有分析消息体，直接回复原来的消息，这一块做的不好。
				osip_message_set_body (answer, tmp, strlen(tmp));
				osip_message_set_content_type (answer, "application/sdp");

				eXosip_call_send_answer (sipData->context_eXosip, je->tid, 200, answer);
				printf ("send 200 over!\n");
			}
			//eXosip_unlock (sipData->context_eXosip);

			
			pos=0;///add by kalen
			//显示出在sdp消息体中的attribute 的内容,里面计划存放我们的信息
			printf ("the INFO is :\n");
			while (!osip_list_eol ( &(remote_sdp->a_attributes), pos))
			{
				sdp_attribute_t *at;

				at = (sdp_attribute_t *) osip_list_get ( &remote_sdp->a_attributes, pos);
				printf ("%s : %s\n", at->a_att_field, at->a_att_value);//这里解释了为什么在SDP消息体中属性a里面存放必须是两列

				pos ++;
			}

			break;


		/*2.invite 客户端，以下5条call消息是收到服务器发过来的响应消息*/
       case EXOSIP_CALL_PROCEEDING: //收到100 trying消息，表示请求正在处理中
            printf("proceeding!\n");
            break;
        case EXOSIP_CALL_RINGING:   //收到180 Ringing应答，表示接收到INVITE请求的UAS正在向被叫用户振铃
            printf("ringing!\n");
            printf("call_id is %d,dialog_id is %d \n",je->cid,je->did);
			sipData->call_id = je->cid;
            sipData->dialog_id = je->did;


/*
			printf("Received a INVITE msg from %s:%s, UserName is %s, password is %s\n",je->request->req_uri->host,
					je->request->req_uri->port, je->request->req_uri->username, je->request->req_uri->password);

			//得到消息体,认为该消息就是SDP格式.
			remote_sdp = eXosip_get_remote_sdp (sipData->context_eXosip,je->did);
			pos=0;///add by kalen
			//显示出在sdp消息体中的attribute 的内容,里面计划存放我们的信息
			printf ("the INFO is :\n");
			while (!osip_list_eol ( &(remote_sdp->a_attributes), pos))
			{
				sdp_attribute_t *at;

				at = (sdp_attribute_t *) osip_list_get ( &remote_sdp->a_attributes, pos);
				printf ("%s : %s\n", at->a_att_field, at->a_att_value);//这里解释了为什么在SDP消息体中属性a里面存放必须是两列

				pos ++;
			}
*/
			
            break;
		case EXOSIP_CALL_ANSWERED: //收到200 OK，表示请求已经被成功接受，用户应答
            printf("ok!connected!\n");
            sipData->call_id = je->cid;
            sipData->dialog_id = je->did;
            printf("!!call_id is %d,dialog_id is %d \n",je->cid,je->did);

/*
			printf("Received a INVITE msg from %s:%s, UserName is %s, password is %s\n",je->request->req_uri->host,
					je->request->req_uri->port, je->request->req_uri->username, je->request->req_uri->password);
			//得到消息体,认为该消息就是SDP格式.

			remote_sdp = eXosip_get_remote_sdp (sipData->context_eXosip,je->did);
			pos=0;///add by kalen
			//显示出在sdp消息体中的attribute 的内容,里面计划存放我们的信息
			printf ("the INFO is :\n");
			while (!osip_list_eol ( &(remote_sdp->a_attributes), pos))
			{
				sdp_attribute_t *at;

				at = (sdp_attribute_t *) osip_list_get ( &remote_sdp->a_attributes, pos);
				printf ("%d: %s : %s\n", pos,at->a_att_field, at->a_att_value);//这里解释了为什么在SDP消息体中属性a里面存放必须是两列

				pos ++;
			}
*/
            //回送ack应答消息
            eXosip_call_build_ack(sipData->context_eXosip, je->did, &ack);
            eXosip_call_send_ack(sipData->context_eXosip, je->did, ack);
            //flag1=0; //推出While循环
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

		/*3.register:作为客户端，收到一个服务器的返回信息如下*/
        case EXOSIP_REGISTRATION_SUCCESS:// 注册成功
            //fprintf(stderr,"[%s,%d]======register sccess!=====\n",__FUNCTION__,__LINE__);	 
            //fprintf(stderr,"je->rid=%d\n", je->rid);
            break;

        case EXOSIP_REGISTRATION_FAILURE:// 注册失败
			//fprintf(stderr,"[%s,%d]======register fail ======\n",__FUNCTION__,__LINE__);	
            //fprintf(stderr,"je->rid=%d\n", je->rid);
            break;

			
        case EXOSIP_MESSAGE_NEW://新的消息到来
            //fprintf(stderr," EXOSIP_MESSAGE_NEW!\n");
            //***如果接受到的消息类型是MESSAGE***
            sipMessageResponse(sipData,je);
            break;
        
			
			

			
        case EXOSIP_CALL_MESSAGE_NEW:
            /*
            //至于该类型和EXOSIP_MESSAGE_NEW的区别，源代码这么解释的
            // request related events within calls (except INVITE)
             EXOSIP_CALL_MESSAGE_NEW,          < announce new incoming request.
            // response received for request outside calls
             EXOSIP_MESSAGE_NEW,          < announce new incoming request.
             我也不是很明白，理解是：
             EXOSIP_CALL_MESSAGE_NEW是一个呼叫中的新的消息到来，比如ring trying都算，所以在接受到后必须判断
             该消息类型，EXOSIP_MESSAGE_NEW而是表示不是呼叫内的消息到来。
            */
            fprintf(stderr," EXOSIP_CALL_MESSAGE_NEW\n");
            if (MSG_IS_INFO(je->request) ) //如果传输的是INFO方法
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








