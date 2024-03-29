
// DexToolDlg.cpp: 实现文件
//

#include "stdafx.h"
#include "DexTool.h"
#include "DexToolDlg.h"
#include "afxdialogex.h"
#include <map>
#include <string>
using namespace std;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


//递归展开所有节点
void CDexToolDlg::ExpandAllNode(HTREEITEM hTreeItem)
{
  if (!m_TreeView.ItemHasChildren(hTreeItem))//如果树控件根节点没有子节点则返回
  {
    return;
  }
  HTREEITEM hNextItem = m_TreeView.GetChildItem(hTreeItem);//若树控件的根节点有子节点则获取根节点的子节点
  while (hNextItem != NULL)
  {
    ExpandAllNode(hNextItem);//递归，展开子节点下的所有子节点
    hNextItem = m_TreeView.GetNextItem(hNextItem, TVGN_NEXT);//获取根节点的下一个子节点
  }
  m_TreeView.Expand(hTreeItem, TVE_EXPAND);//展开节点
}

/*
    初始化tree控件

    参数1:文件名
  
    返回true成功,false失败
*/
bool CDexToolDlg::InitializeTree(char * szFileName)
{
  HTREEITEM hRoot;
  HTREEITEM hNtHeader;
  HTREEITEM hDosHeader;
  HTREEITEM hChild;
  m_TreeView.DeleteAllItems();
  m_TreeView.ModifyStyle(NULL, TVS_HASBUTTONS | TVS_LINESATROOT | TVS_HASLINES);

  //根节点
  hRoot = m_TreeView.InsertItem(szFileName, TVI_ROOT);

  hDosHeader = m_TreeView.InsertItem("Dex Header", hRoot);
  m_TreeView.SetItemData(hDosHeader, DEX_HEADER);

  hNtHeader = m_TreeView.InsertItem("String ids", hRoot);
  m_TreeView.SetItemData(hNtHeader, STRING_IDS);

  //hChild = m_TreeView.InsertItem("File Header", hNtHeader);
  //m_TreeView.SetItemData(hChild, FILE_HEADER);
  //hChild = m_TreeView.InsertItem("Optional Header", hNtHeader);
  ////向子节点添加数据
  //m_TreeView.SetItemData(hChild, OPTION_HEADER);
  //hChild = m_TreeView.InsertItem("Data Directory", hChild);
  ////向子节点添加数据
  //m_TreeView.SetItemData(hChild, DATA_DIRECTORY);


  hChild = m_TreeView.InsertItem("Type ids", hRoot);
  m_TreeView.SetItemData(hChild, TYPE_IDS);

  hChild = m_TreeView.InsertItem("Proto ids", hRoot);
  m_TreeView.SetItemData(hChild, PROTO_IDS);

  hChild = m_TreeView.InsertItem("Field ids", hRoot);
  m_TreeView.SetItemData(hChild, FIELD_IDS);

  hChild = m_TreeView.InsertItem("Method ids", hRoot);
  m_TreeView.SetItemData(hChild, METHOD_IDS);

  hChild = m_TreeView.InsertItem("Class def", hRoot);
  m_TreeView.SetItemData(hChild, CLASS_DEF);

  hChild = m_TreeView.InsertItem("Class Data", hChild);
  //向子节点添加数据
  m_TreeView.SetItemData(hChild, CLASS_METHOD);

  hChild = m_TreeView.InsertItem("Map list", hRoot);
  m_TreeView.SetItemData(hChild, MAP_LIST);

  //展开所有节点
  ExpandAllNode(hRoot);
  return TRUE;
}

/*
    初始化list控件

    参数1: 要显示的类型id (参考 DexType枚举)

    返回: true成功，false失败
*/

bool CDexToolDlg::InitializeList(int nTypeId)
{
  bool bRet = true;

  //清空内容
  m_ListView.DeleteAllItems();

  switch (nTypeId)
  {
    case DEX_HEADER:
    {
      ShowDexHeaderInfo();
      break;
    }
    case MAP_LIST:
    {
      ShowMapListInfo();
      break;
    }
    case STRING_IDS:
    {
      ShowStringDataInfo();
      break;
    }
    case TYPE_IDS:
    {
      ShowTypeIdInfo();
      break;
    }
    case PROTO_IDS:
    {
      ShowProtoIdInfo();
      break;
    }
    case FIELD_IDS:
    {
      ShowFieldIdInfo();
      break;
    }
    case METHOD_IDS:
    {
      ShowMethodIdInfo();
      break;
    }
    case CLASS_DEF:
    {
      ShowClassDefInfo();
      break;
    }
    case CLASS_METHOD:
    {
      ShowClassDataInfo();
      break;
    }
    default:
      bRet = false;
      break;
  }

  return bRet;
}


/*
  char数组转十六进制同值字符串
*/

int arrayToStr(unsigned char *buf, unsigned int buflen, char *out)
{
  char strBuf[33] = { 0 };
  char pbuf[32];
  int i;

  for (i = 0; i < buflen; i++)
  {
    sprintf(pbuf, "%02X", buf[i]);
    strncat(strBuf, pbuf, 2);
  }

  strncpy(out, strBuf, buflen * 2);
  return buflen * 2;
}

/*
  显示dexheader结构体信息到界面
*/
void CDexToolDlg::ShowDexHeaderInfo()
{
  CString strCMD;
  int nItemCount = 0;//item数量
  int nOffset = 0;  //成员文件偏移
  DWORD dwStartAddr = (DWORD)m_DexInfo->m_DexHeader;
  char szBuffer[100] = { 0 };
  char szMemberName[][24] = { "uchar magic[8]", "uint checksum", "SHA1 signature", "uint fileSize", 
                            "uint headerSize", "uint endianTag", "uint linkSize", "uint linkOff", "uint mapOff", 
                            "uint stringIdsSize", "uint stringIdsOff", "uint typeIdsSize", "uint typeIdsOff",
                            "uint protoIdsSize", "uint protoIdsOff", "uint fieldIdsSize", "uint fieldIdsOff",
                            "uint methodIdsSize", "uint methodIdsOff", "uint classDefsSize", "uint classDefsOff",
                            "uint dataSize", "uint dataOff"};
  m_ListView.InsertColumn(0, "Member", LVCFMT_LEFT, 200);
  m_ListView.InsertColumn(1, "Value", LVCFMT_LEFT, 200);
  m_ListView.InsertColumn(2, "Offset", LVCFMT_LEFT, 200);
  //m_ListView.InsertColumn(3, "Size",  LVCFMT_LEFT, 100);
  for (int i = 0; i < 23; i++)
  {
    nItemCount = m_ListView.GetItemCount();
    m_ListView.InsertItem(nItemCount, szMemberName[i]);

    if (i == 0)
    {
      //value
      m_ListView.SetItemText(nItemCount, 1, (char*)m_DexInfo->m_DexHeader->magic);
      //offset
      memset(szBuffer, 0, sizeof(szBuffer));
      sprintf(szBuffer, "0x%08X", nOffset);
      m_ListView.SetItemText(nItemCount, 2, szBuffer);

      nOffset += sizeof(m_DexInfo->m_DexHeader->magic);
    }
    else if (i == 2)
    {
      char szTempBuf[10] = { 0 };

      //value
      memset(szBuffer, 0, sizeof(szBuffer));
      arrayToStr(m_DexInfo->m_DexHeader->signature, 16, szBuffer);
      m_ListView.SetItemText(nItemCount, 1, szBuffer);
      

      //offset
      memset(szBuffer, 0, sizeof(szBuffer));
      sprintf(szBuffer, "0x%08X", nOffset);
      m_ListView.SetItemText(nItemCount, 2, szBuffer);

      nOffset += sizeof(m_DexInfo->m_DexHeader->signature);
    }
    else 
    {
      //value
      memset(szBuffer, 0, sizeof(szBuffer));
      sprintf(szBuffer, "0x%08X", *(DWORD*)(dwStartAddr + nOffset));
      m_ListView.SetItemText(nItemCount, 1, szBuffer);

      //offset
      memset(szBuffer, 0, sizeof(szBuffer));
      sprintf(szBuffer, "0x%08X", nOffset);
      m_ListView.SetItemText(nItemCount, 2, szBuffer);

      nOffset += 4;
    }

  }

}


/*
  显示MapList信息
*/
void CDexToolDlg::ShowMapListInfo()
{

  int nItemCount = 0;
  char szBuffer[30] = { 0 };
  map<int, string> TypeMap;

  //建立一个hash表，根据enum值显示类型
  TypeMap[0x0000] = "kDexTypeHeaderItem";
  TypeMap[0x0001] = "kDexTypeStringIdItem";
  TypeMap[0x0002] = "kDexTypeTypeIdItem";
  TypeMap[0x0003] = "kDexTypeProtoIdItem";
  TypeMap[0x0004] = "kDexTypeFieldIdItem";
  TypeMap[0x0005] = "kDexTypeMethodIdItem";
  TypeMap[0x0006] = "kDexTypeClassDefItem";
  TypeMap[0x1000] = "kDexTypeMapList";
  TypeMap[0x1001] = "kDexTypeTypeList";
  TypeMap[0x1002] = "kDexTypeAnnotationSetRefList";
  TypeMap[0x1003] = "kDexTypeAnnotationSetItem";
  TypeMap[0x2000] = "kDexTypeClassDataItem";
  TypeMap[0x2001] = "kDexTypeCodeItem";
  TypeMap[0x2002] = "kDexTypeStringDataItem";
  TypeMap[0x2003] = "kDexTypeDebugInfoItem";
  TypeMap[0x2004] = "kDexTypeAnnotationItem";
  TypeMap[0x2005] = "kDexTypeEncodedArrayItem";
  TypeMap[0x2006] = "kDexTypeAnnotationsDirectoryItem";

  
  m_ListView.InsertColumn(0, "Item", LVCFMT_LEFT, 200);
  m_ListView.InsertColumn(1, "enum Type", LVCFMT_LEFT, 200);
  m_ListView.InsertColumn(2, "ushort unused", LVCFMT_LEFT, 200);
  m_ListView.InsertColumn(3, "uint size", LVCFMT_LEFT, 200);
  m_ListView.InsertColumn(4, "uint offset", LVCFMT_LEFT, 200);

  for (int i = 0; i < m_DexInfo->m_DexMapList->size; i++)
  {
    nItemCount = m_ListView.GetItemCount();
    //item
    sprintf(szBuffer, "map_item_list[%d]", i);
    m_ListView.InsertItem(nItemCount, szBuffer);

    //enum Type
    map<int, string>::iterator iter;
    iter = TypeMap.find(m_DexInfo->m_DexMapList->list[i].type);
    if (iter != TypeMap.end())
    {
      m_ListView.SetItemText(nItemCount, 1, (iter->second).c_str());
    }
    
    //unused
    memset(szBuffer, 0, sizeof(szBuffer));
    sprintf(szBuffer, "0x%04X", m_DexInfo->m_DexMapList->list[i].unused);
    m_ListView.SetItemText(nItemCount, 2, szBuffer);

    //size
    memset(szBuffer, 0, sizeof(szBuffer));
    sprintf(szBuffer, "0x%08X", m_DexInfo->m_DexMapList->list[i].size);
    m_ListView.SetItemText(nItemCount, 3, szBuffer);

    //offset
    memset(szBuffer, 0, sizeof(szBuffer));
    sprintf(szBuffer, "0x%08X", m_DexInfo->m_DexMapList->list[i].offset);
    m_ListView.SetItemText(nItemCount, 4, szBuffer);
  }
}


/*
  显示stringdata
*/
void CDexToolDlg::ShowStringDataInfo()
{
  int nItemCount = 0;
  char szBuffer[100] = { 0 };
  m_ListView.InsertColumn(0, "ids", LVCFMT_LEFT, 200);
  m_ListView.InsertColumn(1, "Offset", LVCFMT_LEFT, 200);
  m_ListView.InsertColumn(2, "string", LVCFMT_LEFT, 300);

  for (int i = 0; i < m_DexInfo->m_DexHeader->stringIdsSize; i++)
  {
    nItemCount = m_ListView.GetItemCount();
    //ids
    sprintf(szBuffer, "%d", i);
    m_ListView.InsertItem(nItemCount, szBuffer);

    //offset
    memset(szBuffer, 0, sizeof(szBuffer));
    sprintf(szBuffer, "0x%08X", m_DexInfo->m_DexStringId[i].stringDataOff);
    m_ListView.SetItemText(nItemCount, 1, szBuffer);

    //string
    memset(szBuffer, 0, sizeof(szBuffer));
    m_DexInfo->ReadString(m_DexInfo->m_DexStringId[i].stringDataOff, szBuffer);
    m_ListView.SetItemText(nItemCount, 2, szBuffer);
  }

}

/*
  显示type id信息
*/
void CDexToolDlg::ShowTypeIdInfo()
{
  int nItemCount = 0;
  char szBuffer[100] = { 0 };
  m_ListView.InsertColumn(0, "type ids", LVCFMT_LEFT, 100);
  m_ListView.InsertColumn(1, "string ids", LVCFMT_LEFT, 150);
  m_ListView.InsertColumn(2, "string", LVCFMT_LEFT, 300);

  for (int i = 0; i < m_DexInfo->m_DexHeader->typeIdsSize; i++)
  {
    nItemCount = m_ListView.GetItemCount();
    //type ids
    sprintf(szBuffer, "%d", i);
    m_ListView.InsertItem(nItemCount, szBuffer);

    //string ids
    int descriptorIdx = m_DexInfo->m_DexTypeId[i].descriptorIdx;
    sprintf(szBuffer, "%d", descriptorIdx);
    m_ListView.SetItemText(nItemCount, 1, szBuffer);

    //string 
    memset(szBuffer, 0, sizeof(szBuffer));
    m_DexInfo->ReadString(m_DexInfo->m_DexStringId[descriptorIdx].stringDataOff, szBuffer);
    m_ListView.SetItemText(nItemCount, 2, szBuffer);
  }
}

/*
  显示proto id信息
*/
void CDexToolDlg::ShowProtoIdInfo()
{
  int nItemCount = 0;
  int n = 0;
  char szBuffer[100] = { 0 };
  m_ListView.InsertColumn(0, "ids", LVCFMT_LEFT, 100);
  m_ListView.InsertColumn(1, "method", LVCFMT_LEFT, 200);
  m_ListView.InsertColumn(2, "return type", LVCFMT_LEFT, 200);
  m_ListView.InsertColumn(3, "parameter", LVCFMT_LEFT, 300);

  for (int i = 0; i < m_DexInfo->m_DexHeader->protoIdsSize; i++)
  {
    nItemCount = m_ListView.GetItemCount();
    //ids
    sprintf(szBuffer, "%d", i);
    m_ListView.InsertItem(nItemCount, szBuffer);

    //method
    memset(szBuffer, 0, sizeof(szBuffer));
    int nStringId = m_DexInfo->m_DexProtoId[i].shortyIdx;
    m_DexInfo->ReadString(m_DexInfo->m_DexStringId[nStringId].stringDataOff, szBuffer);
    m_ListView.SetItemText(nItemCount, 1, szBuffer);

    //return type
    memset(szBuffer, 0, sizeof(szBuffer));
    int nTypeId = m_DexInfo->m_DexProtoId[i].returnTypeIdx;
    nStringId = m_DexInfo->m_DexTypeId[nTypeId].descriptorIdx;
    m_DexInfo->ReadString(m_DexInfo->m_DexStringId[nStringId].stringDataOff, szBuffer);
    m_ListView.SetItemText(nItemCount, 2, szBuffer);

    //parameter
    //获取结构体数量
    if (m_DexInfo->m_DexProtoId[i].parametersOff != 0)
    {
      int nSize = m_DexInfo->GetTypeListInfo(m_DexInfo->m_DexProtoId[i].parametersOff);
      CString strText;

      for (n = 0; n < nSize; n++)
      {
        nTypeId = m_DexInfo->m_DexTypeList->list[n].typeIdx;
        //从DexTypeId结构中获取索引id，在根据typeid从stringids中获取字符串
        nStringId = m_DexInfo->m_DexTypeId[nTypeId].descriptorIdx;

        memset(szBuffer, 0, sizeof(szBuffer));
        m_DexInfo->ReadString(m_DexInfo->m_DexStringId[nStringId].stringDataOff, szBuffer);
        //显示
        strText.Append(szBuffer);

        if (n != nSize - 1)
        {
          strText.Append("、");
        }

      }

      m_ListView.SetItemText(nItemCount, 3, strText);

    }
    else
    {
      //没有参数
      m_ListView.SetItemText(nItemCount, 3, "no parameter");
    }

  }

}

/*
  显示field信息
*/
void CDexToolDlg::ShowFieldIdInfo()
{
  int nItemCount = 0;
  int n = 0;
  char szBuffer[100] = { 0 };
  m_ListView.InsertColumn(0, "class type", LVCFMT_LEFT, 200);
  m_ListView.InsertColumn(1, "field type", LVCFMT_LEFT, 200);
  m_ListView.InsertColumn(2, "field name", LVCFMT_LEFT, 200);

  for (int i = 0; i < m_DexInfo->m_DexHeader->fieldIdsSize; i++)
  {
    nItemCount = m_ListView.GetItemCount();
    m_ListView.InsertItem(nItemCount, "");

    //class type
    memset(szBuffer, 0, sizeof(szBuffer));
    int nStringId = m_DexInfo->m_DexTypeId[m_DexInfo->m_DexFieldId->classIdx].descriptorIdx;
    m_DexInfo->ReadString(m_DexInfo->m_DexStringId[nStringId].stringDataOff, szBuffer);
    m_ListView.SetItemText(nItemCount, 0, szBuffer);

    //field type
    memset(szBuffer, 0, sizeof(szBuffer));
    nStringId = m_DexInfo->m_DexTypeId[m_DexInfo->m_DexFieldId->typeIdx].descriptorIdx;
    m_DexInfo->ReadString(m_DexInfo->m_DexStringId[nStringId].stringDataOff, szBuffer);
    m_ListView.SetItemText(nItemCount, 1, szBuffer);

    //field name
    memset(szBuffer, 0, sizeof(szBuffer));
    m_DexInfo->ReadString(m_DexInfo->m_DexStringId[m_DexInfo->m_DexFieldId->nameIdx].stringDataOff, szBuffer);
    m_ListView.SetItemText(nItemCount, 2, szBuffer);
  }

}

/*
   显示method信息
*/
void CDexToolDlg::ShowMethodIdInfo()
{
  int nItemCount = 0;
  int n = 0;
  char szBuffer[100] = { 0 };
  m_ListView.InsertColumn(0, "class type", LVCFMT_LEFT, 200);
  m_ListView.InsertColumn(1, "method decare", LVCFMT_LEFT, 200);
  m_ListView.InsertColumn(2, "method name", LVCFMT_LEFT, 200);

  for (int i = 0; i < m_DexInfo->m_DexHeader->methodIdsSize; i++)
  {
    nItemCount = m_ListView.GetItemCount();
    m_ListView.InsertItem(nItemCount, "");

    //class type
    memset(szBuffer, 0, sizeof(szBuffer));
    int nStringId = m_DexInfo->m_DexTypeId[m_DexInfo->m_DexMethodId[i].classIdx].descriptorIdx;
    m_DexInfo->ReadString(m_DexInfo->m_DexStringId[nStringId].stringDataOff, szBuffer);
    m_ListView.SetItemText(nItemCount, 0, szBuffer);

    //method decare
    memset(szBuffer, 0, sizeof(szBuffer));
    nStringId = m_DexInfo->m_DexProtoId[m_DexInfo->m_DexMethodId[i].protoIdx].shortyIdx;
    m_DexInfo->ReadString(m_DexInfo->m_DexStringId[nStringId].stringDataOff, szBuffer);
    m_ListView.SetItemText(nItemCount, 1, szBuffer);

    //method name
    memset(szBuffer, 0, sizeof(szBuffer));
    m_DexInfo->ReadString(m_DexInfo->m_DexStringId[m_DexInfo->m_DexMethodId[i].nameIdx].stringDataOff, szBuffer);
    m_ListView.SetItemText(nItemCount, 2, szBuffer);
  }
}


/*
  显示class信息
*/
void CDexToolDlg::ShowClassDefInfo()
{
  int nItemCount = 0;
  int n = 0;
  char szBuffer[100] = { 0 };
  map<int, string> TypeMap;

  //建立一个hash表，根据enum值显示类型
  TypeMap[0x00000001] = "ACC_PUBLIC";
  TypeMap[0x00000002] = "ACC_PRIVATE";
  TypeMap[0x00000004] = "ACC_PROTECTED";
  TypeMap[0x00000008] = "ACC_STATIC";
  TypeMap[0x00000010] = "ACC_FINAL";
  TypeMap[0x00000020] = "ACC_SUPER";
  TypeMap[0x00000040] = "ACC_VOLATILE";
  TypeMap[0x00000040] = "ACC_BRIDGE";
  TypeMap[0x00000080] = "ACC_VARARGS";
  TypeMap[0x00000080] = "ACC_VARARGS";
  TypeMap[0x00000100] = "ACC_NATIVE";
  TypeMap[0x00000200] = "ACC_INTERFACE";
  TypeMap[0x00000400] = "ACC_ABSTRACT";
  TypeMap[0x00000800] = "ACC_STRICT";
  TypeMap[0x00001000] = "ACC_SYNTHETIC";
  TypeMap[0x00002000] = "ACC_ANNOTATION";
  TypeMap[0x00004000] = "ACC_ENUM";
  TypeMap[0x00010000] = "ACC_CONSTRUCTOR";
  TypeMap[0x00020000] = "ACC_DECLARED_SYNCHRONIZED";

  TypeMap[ACC_PUBLIC | ACC_FINAL | ACC_INTERFACE | ACC_ABSTRACT
    | ACC_SYNTHETIC | ACC_ANNOTATION | ACC_ENUM] = "ACC_CLASS_MASK";
  TypeMap[ACC_CLASS_MASK | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC] = "ACC_INNER_CLASS_MASK";

  TypeMap[ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL
    | ACC_VOLATILE | ACC_TRANSIENT | ACC_SYNTHETIC | ACC_ENUM] = "ACC_FIELD_MASK";
  TypeMap[ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL
    | ACC_SYNCHRONIZED | ACC_BRIDGE | ACC_VARARGS | ACC_NATIVE
    | ACC_ABSTRACT | ACC_STRICT | ACC_SYNTHETIC | ACC_CONSTRUCTOR
    | ACC_DECLARED_SYNCHRONIZED] = "ACC_METHOD_MASK";


  m_ListView.InsertColumn(0, "class", LVCFMT_LEFT, 100);
  m_ListView.InsertColumn(1, "access flags", LVCFMT_LEFT, 100);
  m_ListView.InsertColumn(2, "superclass type", LVCFMT_LEFT, 100);
  m_ListView.InsertColumn(3, "interaces off", LVCFMT_LEFT, 100);
  m_ListView.InsertColumn(4, "source file", LVCFMT_LEFT, 100);
  m_ListView.InsertColumn(5, "annotation off", LVCFMT_LEFT, 100);
  m_ListView.InsertColumn(6, "static value", LVCFMT_LEFT, 100);
  for (int i = 0; i < m_DexInfo->m_DexHeader->classDefsSize; i++)
  {
    nItemCount = m_ListView.GetItemCount();
    m_ListView.InsertItem(nItemCount, "");
    
    //class
    memset(szBuffer, 0, sizeof(szBuffer));
    int nStringId = m_DexInfo->m_DexTypeId[m_DexInfo->m_DexClassDef[i].classIdx].descriptorIdx;
    m_DexInfo->ReadString(m_DexInfo->m_DexStringId[nStringId].stringDataOff, szBuffer);
    m_ListView.SetItemText(nItemCount, 0, szBuffer);

    //access flags
    map<int, string>::iterator iter;
    iter = TypeMap.find(m_DexInfo->m_DexClassDef[i].accessFlags);
    if (iter != TypeMap.end())
    {
      m_ListView.SetItemText(nItemCount, 1, (iter->second).c_str());
    }

    //superclass type
    memset(szBuffer, 0, sizeof(szBuffer));
    nStringId = m_DexInfo->m_DexTypeId[m_DexInfo->m_DexClassDef[i].superclassIdx].descriptorIdx;
    m_DexInfo->ReadString(m_DexInfo->m_DexStringId[nStringId].stringDataOff, szBuffer);
    m_ListView.SetItemText(nItemCount, 2, szBuffer);

    //interaces off
    if (m_DexInfo->m_DexClassDef[i].interfacesOff != 0)
    {
      memset(szBuffer, 0, sizeof(szBuffer));
      int nStringId = m_DexInfo->m_DexTypeList[m_DexInfo->m_DexClassDef[i].interfacesOff].list->typeIdx;
      m_DexInfo->ReadString(m_DexInfo->m_DexStringId[nStringId].stringDataOff, szBuffer);
      m_ListView.SetItemText(nItemCount, 3, szBuffer);
    }
    else
    {
      m_ListView.SetItemText(nItemCount, 3, "0");

    }

    //source file
    memset(szBuffer, 0, sizeof(szBuffer));
    m_DexInfo->ReadString(m_DexInfo->m_DexStringId[m_DexInfo->m_DexClassDef[i].sourceFileIdx].stringDataOff, szBuffer);
    m_ListView.SetItemText(nItemCount, 4, szBuffer);

    //annotation off
    if (m_DexInfo->m_DexClassDef[i].annotationsOff != 0)
    {
      memset(szBuffer, 0, sizeof(szBuffer));
      sprintf(szBuffer, "0x%X", m_DexInfo->m_DexClassDef[i].annotationsOff);
      m_ListView.SetItemText(nItemCount, 5, szBuffer);
    }
    else
    {
      m_ListView.SetItemText(nItemCount, 5, "0");

    }

    //static value
    if (m_DexInfo->m_DexClassDef[i].annotationsOff != 0)
    {
      memset(szBuffer, 0, sizeof(szBuffer));
      sprintf(szBuffer, "0x%X", m_DexInfo->m_DexClassDef[i].staticValuesOff);
      m_ListView.SetItemText(nItemCount, 6, szBuffer);
    }
    else
    {
      m_ListView.SetItemText(nItemCount, 6, "0");

    }
  }
}

/*
  显示class data信息
*/
void CDexToolDlg::ShowClassDataInfo()
{
  int nItemCount = 0;
  int n = 0;
  char szBuffer[100] = { 0 };

  m_ListView.InsertColumn(0, "static fields", LVCFMT_LEFT, 200);
  m_ListView.InsertColumn(1, "instance fields", LVCFMT_LEFT, 200);
  m_ListView.InsertColumn(2, "direct methods", LVCFMT_LEFT, 200);
  m_ListView.InsertColumn(3, "virtual methods", LVCFMT_LEFT, 200);

  for (int i = 0; i < m_DexInfo->m_DexHeader->classDefsSize; i++)
  {
    nItemCount = m_ListView.GetItemCount();
    m_ListView.InsertItem(nItemCount, "");
    if (m_DexInfo->GetClassDataInfo(m_DexInfo->m_DexClassDef[i].classDataOff))
    {
      memset(szBuffer, 0, sizeof(szBuffer));
      sprintf(szBuffer, "%d", m_DexInfo->m_DexClassData->header.staticFieldSize);
      m_ListView.SetItemText(nItemCount, 0, szBuffer);

      memset(szBuffer, 0, sizeof(szBuffer));
      sprintf(szBuffer, "%d", m_DexInfo->m_DexClassData->header.instanceFieldsSize);
      m_ListView.SetItemText(nItemCount, 1, szBuffer);

      memset(szBuffer, 0, sizeof(szBuffer));
      sprintf(szBuffer, "%d", m_DexInfo->m_DexClassData->header.directMethodsSize);
      m_ListView.SetItemText(nItemCount, 2, szBuffer);

      memset(szBuffer, 0, sizeof(szBuffer));
      sprintf(szBuffer, "%d", m_DexInfo->m_DexClassData->header.virtualMethodsSize);
      m_ListView.SetItemText(nItemCount, 3, szBuffer);
    }
  }
}

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CDexToolDlg 对话框



CDexToolDlg::CDexToolDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DEXTOOL_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CDexToolDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);

  //绑定控件
  DDX_Control(pDX, IDC_LIST1, m_ListView);
  DDX_Control(pDX, IDC_TREE1, m_TreeView);
}

BEGIN_MESSAGE_MAP(CDexToolDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
  ON_WM_DROPFILES()
  ON_NOTIFY(NM_CLICK, IDC_TREE1, &CDexToolDlg::OnNMClickTree1)
END_MESSAGE_MAP()


// CDexToolDlg 消息处理程序

BOOL CDexToolDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码


  //解决win10无法使用文件拖放的问题
  ChangeWindowMessageFilter(WM_DROPFILES, MSGFLT_ADD);
  ChangeWindowMessageFilter(0x0049, MSGFLT_ADD);


	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CDexToolDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CDexToolDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CDexToolDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



//从路径中获取文件名
bool CDexToolDlg::GetFileNameToPath(char* szPath)
{
  DWORD dwLength = 0;
  DWORD dwIndex = 0;
  char szTempPath[MAX_PATH] = { 0 };

  dwLength = strlen(szPath);
  if (dwLength == 0)
  {
    return FALSE;
  }

  strcpy(szTempPath, szPath);
  //从尾部开始获取"\\"的位置
  for (int i = dwLength; i >= 0; i--)
  {
    if ((unsigned char)szTempPath[i] == '\\')
    {
      dwIndex = i;
      break;
    }
  }

  strcpy(szPath, &szTempPath[dwIndex + 1]);
  return TRUE;
}

//接收拖放进来的文件
void CDexToolDlg::OnDropFiles(HDROP hDropInfo)
{
  // TODO: 在此添加消息处理程序代码和/或调用默认值
  char szFilePath[MAX_PATH] = { 0 };

  CDialogEx::OnDropFiles(hDropInfo);

  //获取拖放文件的路径
  DragQueryFileA(hDropInfo, 0, szFilePath, sizeof(szFilePath));

  m_strFilePath = szFilePath;
  //从路径中获取文件名
  if (GetFileNameToPath(szFilePath))
  {
    InitializeTree(szFilePath);
    //读取.dex文件信息
    m_DexInfo = new CDexInfo(m_strFilePath.GetBuffer());
    m_DexInfo->ReadDexFile();
  }
}


//tree控件节点被单击
void CDexToolDlg::OnNMClickTree1(NMHDR *pNMHDR, LRESULT *pResult)
{
  // TODO: 在此添加控件通知处理程序代码
  *pResult = 0;

  CString strBuffer;
  CPoint pt;
  UINT uFlag = 0;
  HTREEITEM hSelItem = NULL;
  //DWORD dwType = 0;

  hSelItem = m_TreeView.GetSelectedItem();
  pt = GetCurrentMessage()->pt;
  m_TreeView.ScreenToClient(&pt);
  hSelItem = m_TreeView.HitTest(pt, &uFlag);
  if (hSelItem != NULL)
  {
    //m_CurSelItem = hSelItem;
    //删除所有列
    while (m_ListView.DeleteColumn(0))
    {

    }

    //m_nCurSelType = m_TreeView.GetItemData(hSelItem);
    InitializeList(m_TreeView.GetItemData(hSelItem));
  }
}
