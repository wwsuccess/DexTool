#include "stdafx.h"
#include "CDexInfo.h"



CDexInfo::CDexInfo(char* szFilePath)
{
  m_DexHeader = (DexHeader*)malloc(sizeof(DexHeader));
  m_DexMapList = NULL;
  m_DexStringId = NULL;
  m_DexTypeId = NULL;
  m_DexProtoId = NULL;
  m_DexTypeList = NULL;
  m_DexFieldId = NULL;
  m_DexMethodId = NULL;
  m_DexClassDef = NULL;
  m_DexClassData = NULL;
  strncpy(m_szFilePath, szFilePath, MAX_PATH);
}


CDexInfo::~CDexInfo()
{
  if (m_DexHeader != NULL)
    free(m_DexHeader);

  if (m_DexMapList != NULL)
    free(m_DexMapList);

  if (m_DexStringId != NULL)
    free(m_DexStringId);

  if (m_DexTypeId != NULL)
    free(m_DexTypeId);

  if (m_DexProtoId != NULL)
    free(m_DexProtoId);

  if (m_DexTypeList != NULL)
    free(m_DexTypeList);

  if (m_DexFieldId != NULL)
    free(m_DexFieldId);

  if (m_DexMethodId != NULL)
    free(m_DexMethodId);

  if (m_DexClassDef != NULL)
    free(m_DexClassDef);

  if (m_DexClassData != NULL)
    free(m_DexClassData);
}

/*
    ��ȡdex�ļ�
*/
int CDexInfo::ReadDexFile()
{
  bool bRet = false;
  DWORD dwBytesToRead = 0;
  char szDexMagic[] = { '\x64', '\x65', '\x78', '\xA', '\x30', '\x33', '\x35', '\x00' };

  //����ṹ��û�з����ڴ�
  if (m_DexHeader == NULL )
  {
      return DEX_FAILED;
  }

  m_hFile = CreateFile(
    m_szFilePath,
    GENERIC_READ,
    FILE_SHARE_READ,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    NULL);

  if (m_hFile == INVALID_HANDLE_VALUE)
  {
    //���ļ�ʧ��
    return DEX_FAILED;
  }

  bRet = ReadFile(
    m_hFile,
    m_DexHeader,
    sizeof(DexHeader),
    &dwBytesToRead,
    NULL);

  if (!bRet)
  {
    //��ȡ�ļ�ʧ��
    return DEX_FAILED;
  }

  if (memcmp((char*)m_DexHeader->magic, szDexMagic, sizeof(m_DexHeader->magic)) != 0)
  {
    //������Ч��dex�ļ�
    return ERROR_INVALID_FILE;
  }

 
  bRet = GetStringIdsInfo();
  if (!bRet)
  {
    return ERROR_GET_STRING_FAILED;
  }

  bRet = GetDexMapListInfo();
  if (!bRet)
  {
    return ERROR_GET_MAPLIST_FAILED;
  }

  bRet = GetDexTypeIdInfo();
  if (!bRet)
  {
    return ERROR_GET_TYPEID_FAILED;
  }

  bRet = GetProtoId();
  if (!bRet)
  {
    return ERROR_GET_PROTOID_FAILED;
  }

  bRet = GetFieldIdInfo();
  if (!bRet)
  {
    return ERROR_GET_FIELDID_FAILED;
  }

  bRet = GetMethodIdInfo();
  if (!bRet)
  {
    return ERROR_GET_METHODID_FAILED;
  }

  bRet = GetClassDefInfo();
  if (!bRet)
  {
    return ERROR_GET_CLASSDEF_FAILED;
  }

  return DEX_SUCCESS;
}

/*
  ��ȡstring ��Ϣ
*/
bool CDexInfo::GetStringIdsInfo()
{
  bool bRet = false;
  DWORD dwBytesToRead = 0;
  //string ids
  //����ṹ����Ҫ�Ĵ�С
  if (m_DexStringId == NULL)
  {
    //��С����m_DexHeader->stringIdsSizeָ��
    m_DexStringId = (DexStringId*)malloc(sizeof(DexStringId) * m_DexHeader->stringIdsSize);
    if (m_DexStringId == NULL)
      return bRet;
  }

  //�����ļ�ָ��
  SetFilePointer(m_hFile, m_DexHeader->stringIdsOff, NULL, FILE_BEGIN);
  bRet = ReadFile(
    m_hFile,
    m_DexStringId,
    sizeof(DexStringId) * m_DexHeader->stringIdsSize,
    &dwBytesToRead,
    NULL);

  return bRet;
}

/*
  ��ȡmaplist��Ϣ
*/
bool CDexInfo::GetDexMapListInfo()
{
  bool bRet = false;
  DWORD dwBytesToRead = 0;

  //�����ڴ�
  if (m_DexMapList == NULL)
  {
    m_DexMapList = (DexMapList*)malloc(sizeof(DexMapList));
    if (m_DexMapList == NULL)
      return bRet;
  }

  //�����ļ�ָ��
  SetFilePointer(m_hFile, m_DexHeader->mapOff, NULL, FILE_BEGIN);
  //����Ҫ����size����ȡ����ΪDexMapItem list[1]�����Сֻ��1
  bRet = ReadFile(
    m_hFile,
    m_DexMapList,
    sizeof(DexMapList),
    &dwBytesToRead,
    NULL);

  if (!bRet)
  {
    //��ȡ�ļ�ʧ��
    return bRet;
  }

  //�����С
  int  nMapListSize = m_DexMapList->size;
  free(m_DexMapList);
  m_DexMapList = NULL;

  //�����ڴ�
  if (m_DexMapList == NULL)
  {
    m_DexMapList = (DexMapList*)malloc(sizeof(DexMapList) + (sizeof(DexMapItem)*(nMapListSize - 1)));
    if (m_DexMapList == NULL)
      return bRet;
  }

  //��ȡ��size���ٶ�ȡ
  SetFilePointer(m_hFile, m_DexHeader->mapOff, NULL, FILE_BEGIN);
  bRet = ReadFile(
    m_hFile,
    m_DexMapList,
    sizeof(DexMapList) + (sizeof(DexMapItem)*(nMapListSize - 1)),
    &dwBytesToRead,
    NULL);

  return bRet;
}



bool CDexInfo::GetDexTypeIdInfo()
{
  bool bRet = false;
  DWORD dwBytesToRead = 0;

  if (m_DexTypeId == NULL)
  {
    m_DexTypeId = (DexTypeId*)malloc(sizeof(DexTypeId) * m_DexHeader->typeIdsSize);
    if (m_DexTypeId == NULL)
      return bRet;
  }

  SetFilePointer(m_hFile, m_DexHeader->typeIdsOff, NULL, FILE_BEGIN);

  bRet = ReadFile(
    m_hFile,
    m_DexTypeId,
    sizeof(DexTypeId) * m_DexHeader->typeIdsSize,
    &dwBytesToRead,
    NULL);

  
  return bRet;
}




bool CDexInfo::GetProtoId()
{
  bool bRet = false;
  DWORD dwBytesToRead = 0;

  if (m_DexProtoId == NULL)
  {
    m_DexProtoId = (DexProtoId*)malloc(sizeof(DexProtoId) * m_DexHeader->protoIdsSize);
    if (m_DexProtoId == NULL)
      return bRet;
  }

  SetFilePointer(m_hFile, m_DexHeader->protoIdsOff, NULL, FILE_BEGIN);

  bRet = ReadFile(
    m_hFile,
    m_DexProtoId,
    sizeof(DexProtoId) * m_DexHeader->protoIdsSize,
    &dwBytesToRead,
    NULL);

  return bRet;
}


/*
  ��ȡTypeList�ṹ��Ϣ

  ����1: ƫ��

  ����: �ɹ����ؽṹ��������ʧ�ܷ���0
*/
int CDexInfo::GetTypeListInfo(int nOffset)
{
  bool bRet = false;
  DWORD dwBytesToRead = 0;

  //��ȡtype list
  if (m_DexTypeList == NULL)
  {
    m_DexTypeList = (DexTypeList*)malloc(sizeof(DexTypeList));
    if (m_DexTypeList == NULL)
      return 0;
  }

  SetFilePointer(m_hFile, nOffset, NULL, FILE_BEGIN);
  //��ȡDexTypeList�ṹ����
  bRet = ReadFile(
    m_hFile,
    m_DexTypeList,
    sizeof(DexTypeList),
    &dwBytesToRead,
    NULL);

  if (!bRet)
  {
    return 0;
  }

  int nTypeListSize = m_DexTypeList->size;
  free(m_DexTypeList);
  m_DexTypeList = NULL;
  //��ȡ����DexTypeList�ṹ
  if (m_DexTypeList == NULL)
  {
    m_DexTypeList = (DexTypeList*)malloc(sizeof(DexTypeList) * nTypeListSize);
    if (m_DexTypeList == NULL)
      return 0;
  }

  SetFilePointer(m_hFile, (int)m_DexProtoId->parametersOff + sizeof(m_DexTypeList->size), NULL, FILE_BEGIN);
  //��ȡDexTypeList�ṹ����
  bRet = ReadFile(
    m_hFile,
    &m_DexTypeList->list,
    sizeof(DexTypeItem) * nTypeListSize,
    &dwBytesToRead,
    NULL);

  if (bRet)
  {
    return nTypeListSize;
  }
  else 
  {
    return 0;
  }

}

bool CDexInfo::GetFieldIdInfo()
{
  bool bRet = false;
  DWORD dwBytesToRead = 0;


  if (m_DexFieldId == NULL)
  {
    m_DexFieldId = (DexFieldId*)malloc(sizeof(DexFieldId) * m_DexHeader->fieldIdsSize);
    if (m_DexFieldId == NULL)
      return 0;
  }

  SetFilePointer(m_hFile, m_DexHeader->fieldIdsOff, NULL, FILE_BEGIN);
  //��ȡDexTypeList�ṹ����
  bRet = ReadFile(
    m_hFile,
    m_DexFieldId,
    sizeof(DexFieldId),
    &dwBytesToRead,
    NULL);


  return bRet;
}

/*
  ��ȡmethod id��Ϣ
*/
bool CDexInfo::GetMethodIdInfo()
{
  bool bRet = false;
  DWORD dwBytesToRead = 0;


  if (m_DexMethodId == NULL)
  {
    m_DexMethodId = (DexMethodId*)malloc(sizeof(DexMethodId) * m_DexHeader->methodIdsSize);
    if (m_DexMethodId == NULL)
      return 0;
  }

  SetFilePointer(m_hFile, m_DexHeader->methodIdsOff, NULL, FILE_BEGIN);
  //��ȡDexTypeList�ṹ����
  bRet = ReadFile(
    m_hFile,
    m_DexMethodId,
    sizeof(DexMethodId) * m_DexHeader->methodIdsSize,
    &dwBytesToRead,
    NULL);


  return bRet;
}

/*
  ��ȡclass def��Ϣ
*/
bool CDexInfo::GetClassDefInfo()
{
  bool bRet = false;
  DWORD dwBytesToRead = 0;


  if (m_DexClassDef == NULL)
  {
    m_DexClassDef = (DexClassDef*)malloc(sizeof(DexClassDef) * m_DexHeader->classDefsSize);
    if (m_DexClassDef == NULL)
      return 0;
  }

  SetFilePointer(m_hFile, m_DexHeader->classDefsOff, NULL, FILE_BEGIN);
  //��ȡDexTypeList�ṹ����
  bRet = ReadFile(
    m_hFile,
    m_DexClassDef,
    sizeof(DexClassDef) * m_DexHeader->classDefsSize,
    &dwBytesToRead,
    NULL);


  return bRet;
}

bool CDexInfo::GetClassDataInfo(int nOffset)
{
  bool bRet = false;
  DWORD dwBytesToRead = 0;


  if (m_DexClassData == NULL)
  {
    m_DexClassData = (DexClassData*)malloc(sizeof(DexClassData));
    if (m_DexClassData == NULL)
      return 0;
  }

  SetFilePointer(m_hFile, nOffset, NULL, FILE_BEGIN);
  //��ȡDexTypeList�ṹ����
  bRet = ReadFile(
    m_hFile,
    m_DexClassData,
    sizeof(DexClassData),
    &dwBytesToRead,
    NULL);

  return bRet;
}




/*
  stringDataOff�ֶ�ָ����ַ�����mutf-8

  ����1: ����ַ���

  ����2: Դ�ַ���
*/
bool CDexInfo::ReadString(IN int nOffset, OUT char Dst[])
{
  /*
    �ַ���ͷ����ŵ�����uleb128������ַ�����
    ���ַ�����ֵ�� 0x1 < 0x7f ֮������һ���ֽڱ��룬��ascii�����
    ���ַ�����ֵ��  0x80 < 0x7ff �ֽ�����2���ֽڱ���,
    ���ַ�����ֵ��  0x80 < 0xffff �ֽ�����3���ֽڱ���

  */

  //����ֱ�Ӱ���ascii��ȡ��
  bool bRet = 0;
  DWORD dwBytesToRead = 0;//��ȡ�ɹ����ֽ�
  char chSize = 0; //�ַ���ͷ����ŵĸ���

  SetFilePointer(m_hFile, nOffset, NULL, FILE_BEGIN);

  bRet = ReadFile(
    m_hFile,
    &chSize,
    sizeof(chSize),
    &dwBytesToRead,
    NULL);

  if (!bRet)
  {
    return bRet;
  }

  //ͷ����ŵ��Ǹ���
  SetFilePointer(m_hFile, nOffset+1, NULL, FILE_BEGIN);

  bRet = ReadFile(
    m_hFile,
    Dst,
    chSize,
    &dwBytesToRead,
    NULL);

  return bRet;
}
