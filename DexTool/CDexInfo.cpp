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
    读取dex文件
*/
int CDexInfo::ReadDexFile()
{
  bool bRet = false;
  DWORD dwBytesToRead = 0;
  char szDexMagic[] = { '\x64', '\x65', '\x78', '\xA', '\x30', '\x33', '\x35', '\x00' };

  //如果结构体没有分配内存
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
    //打开文件失败
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
    //读取文件失败
    return DEX_FAILED;
  }

  if (memcmp((char*)m_DexHeader->magic, szDexMagic, sizeof(m_DexHeader->magic)) != 0)
  {
    //不是有效的dex文件
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
  获取string 信息
*/
bool CDexInfo::GetStringIdsInfo()
{
  bool bRet = false;
  DWORD dwBytesToRead = 0;
  //string ids
  //申请结构体需要的大小
  if (m_DexStringId == NULL)
  {
    //大小根据m_DexHeader->stringIdsSize指定
    m_DexStringId = (DexStringId*)malloc(sizeof(DexStringId) * m_DexHeader->stringIdsSize);
    if (m_DexStringId == NULL)
      return bRet;
  }

  //设置文件指针
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
  获取maplist信息
*/
bool CDexInfo::GetDexMapListInfo()
{
  bool bRet = false;
  DWORD dwBytesToRead = 0;

  //申请内存
  if (m_DexMapList == NULL)
  {
    m_DexMapList = (DexMapList*)malloc(sizeof(DexMapList));
    if (m_DexMapList == NULL)
      return bRet;
  }

  //设置文件指针
  SetFilePointer(m_hFile, m_DexHeader->mapOff, NULL, FILE_BEGIN);
  //这里要根据size来读取，因为DexMapItem list[1]数组大小只有1
  bRet = ReadFile(
    m_hFile,
    m_DexMapList,
    sizeof(DexMapList),
    &dwBytesToRead,
    NULL);

  if (!bRet)
  {
    //读取文件失败
    return bRet;
  }

  //保存大小
  int  nMapListSize = m_DexMapList->size;
  free(m_DexMapList);
  m_DexMapList = NULL;

  //申请内存
  if (m_DexMapList == NULL)
  {
    m_DexMapList = (DexMapList*)malloc(sizeof(DexMapList) + (sizeof(DexMapItem)*(nMapListSize - 1)));
    if (m_DexMapList == NULL)
      return bRet;
  }

  //获取到size后再读取
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
  获取TypeList结构信息

  参数1: 偏移

  返回: 成功返回结构体数量，失败返回0
*/
int CDexInfo::GetTypeListInfo(int nOffset)
{
  bool bRet = false;
  DWORD dwBytesToRead = 0;

  //获取type list
  if (m_DexTypeList == NULL)
  {
    m_DexTypeList = (DexTypeList*)malloc(sizeof(DexTypeList));
    if (m_DexTypeList == NULL)
      return 0;
  }

  SetFilePointer(m_hFile, nOffset, NULL, FILE_BEGIN);
  //获取DexTypeList结构数量
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
  //获取所有DexTypeList结构
  if (m_DexTypeList == NULL)
  {
    m_DexTypeList = (DexTypeList*)malloc(sizeof(DexTypeList) * nTypeListSize);
    if (m_DexTypeList == NULL)
      return 0;
  }

  SetFilePointer(m_hFile, (int)m_DexProtoId->parametersOff + sizeof(m_DexTypeList->size), NULL, FILE_BEGIN);
  //获取DexTypeList结构数量
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
  //获取DexTypeList结构数量
  bRet = ReadFile(
    m_hFile,
    m_DexFieldId,
    sizeof(DexFieldId),
    &dwBytesToRead,
    NULL);


  return bRet;
}

/*
  获取method id信息
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
  //获取DexTypeList结构数量
  bRet = ReadFile(
    m_hFile,
    m_DexMethodId,
    sizeof(DexMethodId) * m_DexHeader->methodIdsSize,
    &dwBytesToRead,
    NULL);


  return bRet;
}

/*
  获取class def信息
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
  //获取DexTypeList结构数量
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
  //获取DexTypeList结构数量
  bRet = ReadFile(
    m_hFile,
    m_DexClassData,
    sizeof(DexClassData),
    &dwBytesToRead,
    NULL);

  return bRet;
}




/*
  stringDataOff字段指向的字符串是mutf-8

  参数1: 输出字符串

  参数2: 源字符串
*/
bool CDexInfo::ReadString(IN int nOffset, OUT char Dst[])
{
  /*
    字符串头部存放的是由uleb128编码的字符个数
    当字符编码值在 0x1 < 0x7f 之间则用一个字节编码，与ascii码兼容
    当字符编码值在  0x80 < 0x7ff 字节则用2个字节编码,
    当字符编码值在  0x80 < 0xffff 字节则用3个字节编码

  */

  //这里直接按照ascii读取了
  bool bRet = 0;
  DWORD dwBytesToRead = 0;//读取成功的字节
  char chSize = 0; //字符串头部存放的个数

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

  //头部存放的是个数
  SetFilePointer(m_hFile, nOffset+1, NULL, FILE_BEGIN);

  bRet = ReadFile(
    m_hFile,
    Dst,
    chSize,
    &dwBytesToRead,
    NULL);

  return bRet;
}
