#include <Windows.h>
#include <string>
#include "DexFile.h"
using namespace std;

/*
  返回错误的类型
*/
enum RetType
{
  DEX_SUCCESS,
  DEX_FAILED,
  ERROR_INVALID_FILE,
  ERROR_GET_STRING_FAILED,
  ERROR_GET_MAPLIST_FAILED,
  ERROR_GET_TYPEID_FAILED,
  ERROR_GET_PROTOID_FAILED,
  ERROR_GET_TYPELIST_FAILED,
  ERROR_GET_FIELDID_FAILED,
  ERROR_GET_METHODID_FAILED,
  ERROR_GET_CLASSDEF_FAILED,
  ERROR_GET_CLASSDATA_FAILED

};


class CDexInfo
{
public:
  CDexInfo(char* szFilePath);
  ~CDexInfo();

public:

  int ReadDexFile();  //读取文件
  bool GetStringIdsInfo();
  bool GetDexMapListInfo();
  bool GetDexTypeIdInfo();
  bool GetProtoId();
  int GetTypeListInfo(int nOffset);
  bool GetFieldIdInfo();
  bool GetMethodIdInfo();
  bool GetClassDefInfo();

  bool GetClassDataInfo(int nOffset);
  bool ReadString(int nOffset, OUT char Dst[]);

public:
  DexHeader* m_DexHeader;
  DexMapList* m_DexMapList;
  DexStringId* m_DexStringId;
  DexTypeId* m_DexTypeId;
  DexProtoId* m_DexProtoId;
  DexTypeList* m_DexTypeList;
  DexFieldId* m_DexFieldId;
  DexMethodId* m_DexMethodId;
  DexClassDef* m_DexClassDef;
  DexClassData* m_DexClassData;
private:
  HANDLE m_hFile;//文件句柄
  char  m_szFilePath[MAX_PATH];//文件路径
};

