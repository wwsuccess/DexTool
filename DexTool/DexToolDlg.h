
// DexToolDlg.h: 头文件
//

#include "CDexInfo.h"


enum DexType
{
  DEX_HEADER,
  STRING_IDS,
  TYPE_IDS,
  PROTO_IDS,
  FIELD_IDS,
  METHOD_IDS,
  CLASS_DEF,
  CLASS_METHOD,
  MAP_LIST
};


// CDexToolDlg 对话框
class CDexToolDlg : public CDialogEx
{
// 构造
public:
	CDexToolDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DEXTOOL_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


public:
  //list控件
  CListCtrl m_ListView;
  //tree控件
  CTreeCtrl m_TreeView;
  //保存拖放进来的文件路径
  CString m_strFilePath;
  //dex类
  CDexInfo* m_DexInfo;
public:
  //展开tree节点
  void ExpandAllNode(HTREEITEM hTreeItem);
  //初始化树控件
  bool InitializeTree(char * szFileName);
  //初始化list控件
  bool InitializeList(int nTypeId);
  //文件路径中获取文件名
  bool GetFileNameToPath(char* szPath);
  //显示DexHeader信息
  void ShowDexHeaderInfo();
  //显示MapList信息
  void ShowMapListInfo();
  //显示string data信息
  void ShowStringDataInfo();
  //显示typeid 信息
  void ShowTypeIdInfo();
  //显示protoid信息
  void ShowProtoIdInfo();
  //显示field信息
  void ShowFieldIdInfo();
  //显示method信息
  void ShowMethodIdInfo();
  //显示class信息
  void ShowClassDefInfo();
  //显示class data
  void ShowClassDataInfo();
// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
  afx_msg void OnDropFiles(HDROP hDropInfo);
  afx_msg void OnNMClickTree1(NMHDR *pNMHDR, LRESULT *pResult);
};
