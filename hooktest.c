#include<linux/sched.h>  
#include<asm/unistd.h>  
#include<linux/fs.h>
#include<linux/err.h>
#include<linux/errno.h>
#include<linux/fcntl.h>
#include<linux/unistd.h>
#include<linux/string.h>
#include<linux/time.h>
#include<linux/timex.h>
#include<linux/rtc.h>
#include<linux/string.h>
#include<linux/slab.h>
#include<linux/kthread.h>
#include<linux/kernel.h>
#include<linux/module.h>
#include<linux/init.h>
#include<linux/fdtable.h>
#include<linux/file.h>
#include<linux/dcache.h>
#include<linux/fs_struct.h>
#include<linux/types.h>
#include <linux/delay.h>


MODULE_LICENSE("GPL");

#define F_LEN  3096

#define GET_CR0(val)\
	__asm__ __volatile__("movl %%cr0, %0":"=r"(val))

#define SET_CR0(val)\
	__asm__ __volatile__("movl %0, %%cr0"::"r"(val))




enum OPERATION_TYPE
{
	file_READ=1,file_OPEN,file_WRITE,
	file_RMDIR,file_MKDIR,file_CHMOD,file_CHOWN,
	file_MV,file_CP	
};


typedef struct Result
{

	int nFlag; //主机唯一表示符

	enum OPERATION_TYPE type;

	//	int nType;//文件操作类型
	int nIsOut; //文件是否为外存
	char arrPathName[F_LEN];//被操作文件的的路径
	char arrProName[F_LEN];//操作文件的进程名
	char arrProPathName[F_LEN];//被操作文件的进程路径
	char arrTime[F_LEN];//时间


}Res;


typedef asmlinkage long (*sys_read)(unsigned int fd,char *buf,size_t count);

typedef asmlinkage long (*sys_open)(const char *filename,int flags,mode_t mode);//

typedef asmlinkage long (*sys_write)(unsigned int fd,const char *buf,size_t count);

typedef asmlinkage long (*sys_rmdir)(const char *pathname);

typedef asmlinkage long (*sys_mkdir)(const char *pathname,mode_t mode);

typedef asmlinkage long (*sys_chmod)(const char *filename,mode_t mode);

typedef asmlinkage long (*sys_chown)(const char *filename,uid_t user,gid_t group);

typedef asmlinkage long (*sys_execve)(const char *filename,char*const argv[],char *const envp[]);

typedef asmlinkage long (*sys_getcwd)(char *buf,unsigned long size);





asmlinkage long my_read(unsigned int fd,char *buf,size_t count);

asmlinkage long my_open(const char *filename,int flags,mode_t mode);//

asmlinkage long my_write(unsigned int fd,const char *buf,size_t count);

asmlinkage long my_rmdir(const char *pathname);

asmlinkage long my_mkdir(const char *pathname,mode_t mode);

asmlinkage long my_chmod(const char *filename,mode_t mode);

asmlinkage long my_chown(const char *filename,uid_t user,gid_t group);

asmlinkage long my_execve(const char *filename,char *const argv[],char*const envp[]);


sys_read sys_read_pointer=NULL;
sys_open sys_open_pointer=NULL;
sys_write sys_write_pointer=NULL;
sys_rmdir sys_rmdir_pointer=NULL;
sys_mkdir sys_mkdir_pointer=NULL;
sys_chmod sys_chmod_pointer=NULL;
sys_chown sys_chown_pointer=NULL;
sys_execve sys_execve_pointer=NULL;
sys_getcwd sys_getcwd_pointer=NULL;

unsigned int get_idt_base(void);

unsigned int get_sys_call_entry(unsigned int idt_base);

unsigned int get_sys_call_table_entry(unsigned int sys_call_entry,char * exp,char exp_len,unsigned int cope);

unsigned int clear_cr0_save(void);

void setback_cr0(unsigned int val);

static void Change_Syscall_And_Mycall_Pointer(unsigned long * table);

static void Return_Syscall(void);


static char * Get_File_Path(void);

static char * Get_Current_Work_Path(void);


unsigned int sys_table;

unsigned long * table;

//static char* get_path(int fd);

static bool Isusb (const char *path);

static char * get_procpath(void);


static bool record (Res *);//记录数据

static Res* assign_struct(int flag,enum OPERATION_TYPE type,int isout,char arrpathname[F_LEN]);


static void my_operate(const char *pathname,enum OPERATION_TYPE type);


struct idt
{
	unsigned short limit;
	unsigned int base;
}__attribute__((packed));

struct idt_gate
{
	unsigned short off1;
	unsigned short sel;
	unsigned char nome,flags;
	unsigned short off2;
}__attribute__((packed));


unsigned int get_idt_base(void)
{
	unsigned int base;
	struct idt idt_table;
	__asm__ __volatile__("sidt %0":"=m"(idt_table));
	base=idt_table.base;
	return base;
}

unsigned int get_sys_call_entry(unsigned int idt_base)
{
	struct idt_gate sys_call;
	unsigned int sys_call_entry;

	unsigned int size;

	void *idt_Pointer;
	idt_Pointer=(void*)idt_base+8*0x80;

	size=sizeof(struct idt_gate);////////////////修改
	memcpy(&sys_call,idt_Pointer,size);//////

	sys_call_entry=(sys_call.off2 << 16) | sys_call.off1;
	return sys_call_entry;
}

unsigned int get_sys_call_table_entry(unsigned int sys_call_entry,char * exp,char exp_len,unsigned int cope)
{
	char * begin=(char *)sys_call_entry;

	char * end=(char *)sys_call_entry+cope;

	for(;begin<end;begin++)
	{
		if(begin[0]==exp[0]&&begin[1]==exp[1]&&begin[2]==exp[2])
		  return *((unsigned int *)(begin+3));
	}
	return 0;
}


void setback_cr0(unsigned int val)
{
	asm volatile ("movl %%eax, %%cr0"
				:
				: "a"(val)
				);
}


unsigned int clear_cr0_save(void)
{
	unsigned int cr0 = 0;
	unsigned int ret;
	__asm__ __volatile__ ("movl %%cr0, %%eax":"=a"(cr0));
	ret = cr0;

	cr0 &= 0xfffeffff;
	asm volatile ("movl %%eax, %%cr0":: "a"(cr0));
	return ret;
}


//static char* get_path(int fd)//文件路径
//{
//
//	struct task_struct * mytask=current;
//
//	struct file* file;
//	struct dentry* p_dentry;
//
//	int i=6;//循环次数，linux下目录最大为6层
//
//	char paspath[F_LEN];
//	char root_path[80];
//	file=fget(fd);
//
//	if(file==NULL)
//	{
//		printk(KERN_ALERT "this is fget\n");
//		return NULL;
//	}
//
//	p_dentry=file->f_dentry;
//
//	strcpy(root_path,p_dentry->d_sb->s_root->d_iname);
//
//	sprintf(paspath,"root is  %s",p_dentry->d_iname);
//
//	while(i>=1)
//	{
//		p_dentry=p_dentry->d_parent;
//		sprintf(paspath,"%s/%s",p_dentry->d_iname,paspath);
//		i--;
//
//
//	}
//
//	printk(KERN_ALERT "this is path %s\n",paspath);
//
//	return paspath;
//
//
//
//
//}

static char * get_procpath(void)//Process Path
{


	struct task_struct * task=current;

	char *path = NULL,*ptr = NULL;
	char *read_buf = NULL;

	read_buf = (char*)kmalloc(PAGE_SIZE,GFP_KERNEL);

	if (!read_buf)
	{
		printk("KK Read Buf Alloc Error!\r\n");
		return NULL;
	}

	path =(char*)kmalloc(PAGE_SIZE,GFP_KERNEL);
	if (!path)
	{
		printk("KK Allocate Error\r\n");
		return NULL;
	}

	if (task && task->mm && task->mm->exe_file)
	{
		if (task->mm->exe_file)
		{
			ptr = d_path(&task->mm->exe_file->f_path,path,PAGE_SIZE);
		}
		else
		{
			printk(KERN_ALERT "KK path is NULL");
		}
	}
	else
	{
		printk(KERN_ALERT "task list NULL \r\n");

	}


	kfree(path);

	path=NULL;
	kfree(read_buf);

	read_buf=NULL;


	return IS_ERR(ptr)?"NULL":ptr;



}


static bool Isusb (const char *path)//判断usb 
{

	char despath[F_LEN];

	char despath_work[F_LEN];

	int i,j,len,flag=0;




	for(i=0;i<strlen(path)+1;i++)
	{


		if(path[i]=='/')flag++;

		despath[i]=path[i];

		if(flag==2)break;

	}

	if( strlen(despath)!=0)
	{
		despath[strlen(despath)]='\0';

		if(strcmp(despath,"/media/")==0)//||strcmp(despath_work,"/media/")==0)//判断是否usb（可以封装成一个函>数）
		{
			return true;


		}
		else
		{

			return false;
		}
	}
	else
	{
		printk(KERN_ALERT "路径问题！");
		return false;
	}


}




static Res* assign_struct(int flag,enum OPERATION_TYPE type,int isout,char arrpathname[F_LEN])
{
	Res temp;
	Res *result=NULL;	

	struct timex txc;
	struct rtc_time tm;

	char * proc_path;


	char buf[F_LEN];


	temp.nFlag=flag;//主机唯一标示

	temp.type=type;//文件操作类型

	temp.nIsOut=isout;//是否为外部存储

	if(arrpathname!=NULL)
	{
		strcpy(temp.arrPathName,arrpathname);//文件路径

	}	
	else
	{

		printk(KERN_ALERT "arrpathname is null\n");
	}


	strcpy(temp.arrProName,current->comm);//进程名称



	proc_path= get_procpath();//进程路径

	if(proc_path!=NULL)
	{
		strcpy(temp.arrProPathName,proc_path);

	}


	do_gettimeofday(&(txc.time));
	rtc_time_to_tm(txc.time.tv_sec,&tm);

	sprintf(buf,"%d-%d-%d %d:%d:%d\n",tm.tm_year+1900,tm.tm_mon+1, tm.tm_mday,tm.tm_hour+8,tm.tm_min,tm.tm_sec);

	if(strlen(buf)>0)
	{
		buf[strlen(buf)]='\0';
	}
	else
	{
		printk(KERN_ALERT "时间截取出错");
	}

	strcpy(temp.arrTime,buf);// 时间




	result=&temp;




	return result;
}







static bool record(Res * result)
{


	struct file *filp;
	mm_segment_t fs;
	loff_t pos;
	char * filename=NULL;
	char * buf=NULL;

	buf=(char *)kmalloc(F_LEN,GFP_KERNEL);//GFP_KERNEL 按内核内存分配空间

	sprintf(buf,"04@@%d@@%d@@%d@@%s@@%s@@%s@@%s\n",result->nFlag,result->type,result->nIsOut,result->arrPathName,result->arrProName,result->arrProPathName,result->arrTime);

	filename="/home/my_record";

	filp=filp_open(filename,O_RDWR|O_APPEND|O_CREAT,0644);
	if(IS_ERR(filp))
	{
		printk(KERN_ALERT "open error\n");
		return false;
	}

	fs=get_fs();
	set_fs(KERNEL_DS);//扩大内存范围,保护内核空间
	pos=0;
	vfs_write(filp,buf,strlen(buf),&pos);
	set_fs(fs);
	filp_close(filp,NULL);

	kfree(buf);
	buf=NULL;

	return true;

}


static char * Get_File_Path(void)
{

	struct task_struct * my_current=current;



	char *File_Path_pointer=NULL;
	char *Tmp_pointer=NULL;

	Tmp_pointer=(char*)kmalloc(F_LEN,GFP_KERNEL);


	//File_Path_pointer=d_path(&my_current->fs->pwd,Tmp_pointer,F_LEN);

	File_Path_pointer=d_path(&my_current->fs->root,Tmp_pointer,F_LEN);
	//	printk("devname %s\n",my_current->fs->pwd.mnt->mnt_devname);

	//File_Path_pointer=d_absolute_path(&my_current->fs->pwd,Tmp_pointer
	//			,F_LEN);

	return File_Path_pointer;


}

static char * Get_Current_Work_Path(void)
{
	char current_work_path[1024];	
	int len;

	mm_segment_t old_fs;

	sys_getcwd_pointer=(sys_getcwd)table[__NR_getcwd];
	old_fs=get_fs();

	set_fs(KERNEL_DS);


	(*sys_getcwd_pointer)(current_work_path,1024);

	set_fs(old_fs);

	len=strlen(current_work_path);

	current_work_path[len]='\0';

	if(current_work_path==NULL)
	  printk("current path is null\n");


	return current_work_path;

}









static int Jude_Mv_CP(const char *path,char*const content[],char *const envp[])
{

	char *File_Path_Pointer=NULL;

	enum OPERATION_TYPE type;


	if((path[0]=='/'&&path[5]=='m'&&path[6]=='v')||(path[0]=='/'&&path[5]=='c'&&path[6]=='p')||(path[0]=='/'&&path[5]=='r'&&path[6]=='m'))
	{

		File_Path_Pointer=Get_File_Path();

		printk("this is FILE_PAth %s\n",File_Path_Pointer
			  );

		if(File_Path_Pointer==NULL)
		{
			printk("File_Path_Pointer in Jude_Mv_Cp is NULL\n");
			return 0;
		}

		if(Isusb(File_Path_Pointer))
		{

			if(path[5]=='m'&&path[6]=='v')
			{

				type = file_MV;

				my_operate(File_Path_Pointer,type);

				return 1;

			}
			else if(path[5]=='c'&&path[6]=='p')
			{
				type=file_CP;

				my_operate(File_Path_Pointer,type);

				return 1;

			}
			else
			{
				type=file_RMDIR;
				my_operate(File_Path_Pointer,type);

				return 1;


			}
		}

		else
		{

			return 0;
		}

	}
	else
	{
		return 0;
	}
}

static void my_operate(const char *pathname,enum OPERATION_TYPE Operation_type)
{

	enum  OPERATION_TYPE Opt_type;

	char  *file_path=NULL;

	Res   *Result_struct=NULL;



	if(Isusb(pathname)==true)//判断是否来自USB
	{
		file_path=Get_File_Path();//

		Opt_type=Operation_type;

		Result_struct=assign_struct(1,Opt_type,0,file_path);

		if(NULL==Result_struct)
		{
			printk("Result_struct is NULL \n");

			return ;
		}
		if(false==record(Result_struct))
		{

			printk("record false\n");

			return;
		}
	}
	else
	{

		return;
	}


}



asmlinkage long 
my_read(unsigned int fd,char *buf,size_t count)
{
	char *pathname=Get_File_Path();

	enum OPERATION_TYPE type=file_READ;

	if(pathname==NULL)
	  return (*sys_read_pointer)(fd,buf,count);


	my_operate(pathname,type);



	return (*sys_read_pointer)(fd,buf,count);

}


asmlinkage long 
my_open(const char *filename,int flags,mode_t mode)
{
	printk("this is filename %s\n",filename);

	printk("this is current work Path %s \n",Get_Current_Work_Path());
	enum OPERATION_TYPE type=file_OPEN;

	my_operate(filename,type);

	return (*sys_open_pointer)(filename,flags,mode);
}//

asmlinkage long 
my_write(unsigned int fd,const char *buf,size_t count)
{

	char *pathname=Get_File_Path();

	enum OPERATION_TYPE type=file_WRITE;

	if(NULL==pathname)

	  return (*sys_write_pointer)(fd,buf,count);

	my_operate(pathname,type);

	return (*sys_write_pointer)(fd,buf,count);
}


asmlinkage long 
my_rmdir(const char *pathname)
{

	enum OPERATION_TYPE type=file_RMDIR;

	my_operate(pathname,type);


	return (*sys_rmdir_pointer)(pathname);
}


asmlinkage long 
my_mkdir(const char *pathname,mode_t mode)
{

	enum OPERATION_TYPE type=file_MKDIR;

	my_operate(pathname,type);

	return (*sys_mkdir_pointer)(pathname,mode);
}

asmlinkage long 
my_chmod(const char *filename,mode_t mode)
{


	printk("this is file name chmod %s\n",filename);

	enum OPERATION_TYPE type=file_CHMOD;

	my_operate(filename,type);

	return (*sys_chmod_pointer)(filename,mode);
}

asmlinkage long 
my_chown(const char *filename,uid_t user,gid_t group)
{

	enum OPERATION_TYPE type=file_CHOWN;

	my_operate(filename,type);



	return (*sys_chown_pointer)(filename,user,group);
}

asmlinkage long 
my_execve(const char *filename,char *const argv[],char*const envp[])
{

	Jude_Mv_CP(filename,argv,envp);



	return (*sys_execve_pointer)(filename,argv,envp);

}






static void Change_Syscall_And_Mycall_Pointer(unsigned long * table)
{

	//记录原函数地址
	sys_read_pointer=(sys_read)table[__NR_read];

	sys_open_pointer=(sys_open)table[__NR_open];

	sys_write_pointer=(sys_write)table[__NR_write];

	sys_rmdir_pointer=(sys_rmdir)table[__NR_rmdir];

	sys_mkdir_pointer=(sys_mkdir)table[__NR_mkdir];

	sys_chmod_pointer=(sys_chmod)table[__NR_chmod];

	sys_chown_pointer=(sys_chown)table[__NR_chown];

	sys_execve_pointer=(sys_execve)table[__NR_execve];


	//sys_getcwd_pointer=(sys_getcwd)table[__NR_getcwd];


	//将自己的函数地址赋值给系统调用函数



	table[__NR_read]=(unsigned long)my_read;

	table[__NR_open]=(unsigned long)my_open;

	table[__NR_write]=(unsigned long)my_write;

	table[__NR_rmdir]=(unsigned long)my_rmdir;

	table[__NR_mkdir]=(unsigned long)my_mkdir;

	table[__NR_chmod]=(unsigned long)my_chmod;

	table[__NR_chown]=(unsigned long)my_chown;

	table[__NR_execve]=(unsigned long)my_execve;




}

static int __init syscall_info_init_module(void)
{
	unsigned int cr0=0;

	unsigned int idt_base=get_idt_base();


	unsigned int sys_call_entry=get_sys_call_entry(idt_base);




	sys_table=get_sys_call_table_entry(sys_call_entry,"\xff\x14\x85",3,100);


	table=(unsigned long*)sys_table;

	//wp clear
	cr0=clear_cr0_save();

	//改变地址



	Change_Syscall_And_Mycall_Pointer(table);


	//set wp bit
	
	setback_cr0(cr0);

	printk("this is current work Path %s \n",Get_Current_Work_Path());


	printk(KERN_ALERT "the sys table  is %x\n",sys_table );


	return 0;
}


static void __exit  syscall_info_exit_module(void)
{


	printk(KERN_DEBUG "Module syscall_info exit\n" );


	Return_Syscall();
}


static void Return_Syscall(void)
{

	unsigned int cr0=0;

	unsigned int idt_base=get_idt_base();


	unsigned int sys_call_entry=get_sys_call_entry(idt_base);


	sys_table=get_sys_call_table_entry(sys_call_entry,"\xff\x14\x85",3,100);


	table=(unsigned long*)sys_table;

	//wp clear
	cr0=clear_cr0_save();

	//改变地址


	table[__NR_read]=(unsigned long)sys_read_pointer;

	table[__NR_open]=(unsigned long)sys_open_pointer;

	table[__NR_write]=(unsigned long)sys_write_pointer;

	table[__NR_rmdir]=(unsigned long)sys_rmdir_pointer;

	table[__NR_mkdir]=(unsigned long)sys_mkdir_pointer;

	table[__NR_chmod]=(unsigned long)sys_chmod_pointer;

	table[__NR_chown]=(unsigned long)sys_chown_pointer;

	table[__NR_execve]=(unsigned long)sys_execve_pointer;


	//set wp bit

	setback_cr0(cr0);
}

module_init(syscall_info_init_module);
module_exit(syscall_info_exit_module);

