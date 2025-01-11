import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import sys
import io
from datetime import datetime
import threading
import ctypes
import os
import traceback
import subprocess
from typing import List, Dict, Tuple
import os.path
from pathlib import Path
import glob
import json
import psutil

# 初始化 pywin32
try:
    import pythoncom
    pythoncom.CoInitialize()
    
    # 确保 win32com.gen_py 目录存在
    import win32com
    gen_py_path = os.path.join(os.path.dirname(win32com.__file__), 'gen_py')
    if not os.path.exists(gen_py_path):
        os.makedirs(gen_py_path)
except Exception as e:
    print(f"初始化 COM 时出错: {str(e)}")

# 导入 win32 相关模块
try:
    import win32api
    import win32con
    import win32security
    import win32service
    import win32serviceutil
    import winreg
    import win32event
    import winerror
    import win32com.client
    import win32gui
except ImportError as e:
    print(f"导入 win32 模块时出错: {str(e)}")
    sys.exit(1)

# 先检查必要的包是否安装
required_packages = {
    'psutil': 'psutil',
    'win32api': 'pywin32',
    'win32com': 'pywin32',
    'win32gui': 'pywin32',
    'win32con': 'pywin32',
    'win32security': 'pywin32',
    'win32service': 'pywin32',
    'win32serviceutil': 'pywin32',
    'winreg': 'pywin32',
    'win32event': 'pywin32',
    'winerror': 'pywin32'
}

def check_required_packages():
    missing_packages = []
    for module, package in required_packages.items():
        try:
            __import__(module)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        error_msg = f"缺少必要的包，请运行以下命令安装：\n\npip install {' '.join(missing_packages)}"
        print(error_msg)
        try:
            if not hasattr(tk, '_default_root') or not tk._default_root:
                root = tk.Tk()
                root.withdraw()
            messagebox.showerror("错误", error_msg)
        except:
            pass
        sys.exit(1)

# 检查必要的包
check_required_packages()

# 导入其他必要的模块
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import sys
import io
from datetime import datetime
import threading
import ctypes
import os
import traceback
import subprocess
from typing import List, Dict, Tuple
import os.path
from pathlib import Path
import glob
import json
import psutil
import win32api
import win32con
import win32security
import win32service
import win32serviceutil
import winreg

def is_admin() -> bool:
    """检查是否具有管理员权限"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception as e:
        print(f"检查管理员权限时出错: {str(e)}")
        return False

def find_wps_processes() -> List[psutil.Process]:
    """查找所有WPS相关进程"""
    wps_process_names = [
        'wps', 'wpp', 'et',  # 主程序
        'wpspdf', 'wpscloudsvr',  # PDF和云服务
        'wpsoffice', 'wpsnotify',  # 办公套件和通知
        'wpscenter', 'wpscloudlaunch'  # 服务中心和云启动器
    ]
    
    # 获取当前程序的进程ID
    current_pid = os.getpid()
    
    wps_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            # 跳过当前程序进程
            if proc.info['pid'] == current_pid:
                continue
                
            proc_name = proc.info['name'].lower()
            # 确保进程名完全匹配，避免误杀
            if any(proc_name.startswith(wps_name) for wps_name in wps_process_names):
                wps_processes.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            continue
    return wps_processes

def kill_wps_processes(processes: List[psutil.Process]) -> None:
    """终止WPS相关进程"""
    # 获取当前程序的进程ID
    current_pid = os.getpid()
    
    for proc in processes:
        try:
            # 再次检查确保不会终止自己
            if proc.info['pid'] == current_pid:
                continue
                
            print(f"正在终止进程: {proc.info['name']} (PID: {proc.info['pid']})")
            proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"无法终止进程 {proc.info['name']}: {str(e)}")
            print("尝试使用管理员权限终止...")
            try:
                # 再次确认不是当前进程
                if proc.info['pid'] != current_pid:
                    result = run_command_silently(
                        ['taskkill', '/F', '/PID', str(proc.info['pid'])]
                    )
                    if result and result.returncode == 0:
                        print(f"成功终止进程 {proc.info['name']}")
                    else:
                        print(f"终止进程失败: {result.stderr if result else '未知错误'}")
            except Exception as e:
                print(f"终止进程失败: {str(e)}")

def check_registry_autostart() -> Dict[str, str]:
    """检查注册表中的自启动项"""
    autostart_locations = [
        # 当前用户自启动
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        # 系统自启动
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        # WOW64重定向
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        # 启动审批
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"),
        # WPS特定
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Kingsoft\Office"),
        (winreg.HKEY_CURRENT_USER, r"Software\Kingsoft\Office")
    ]
    
    wps_autostart = {}
    
    def decode_registry_value(value) -> str:
        """解码注册表值，处理字节串和字符串"""
        if isinstance(value, bytes):
            try:
                return value.decode('utf-16le')  # REG_SZ 通常使用 UTF-16LE
            except UnicodeDecodeError:
                try:
                    return value.decode('gbk')  # 尝试 GBK
                except UnicodeDecodeError:
                    return value.hex()  # 如果无法解码，返回十六进制字符串
        return str(value)
    
    for hkey, path in autostart_locations:
        try:
            with winreg.OpenKey(hkey, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        # 确保 name 和 value 都是字符串
                        name = decode_registry_value(name) if isinstance(name, bytes) else str(name)
                        value = decode_registry_value(value) if isinstance(value, bytes) else str(value)
                        
                        if any(keyword in (name.lower() + value.lower()) for keyword in ['wps', 'kingsoft', 'office']):
                            reg_path = f"{path}\\{name}"
                            if hkey == winreg.HKEY_CURRENT_USER:
                                reg_path = "HKEY_CURRENT_USER\\" + reg_path
                            else:
                                reg_path = "HKEY_LOCAL_MACHINE\\" + reg_path
                            wps_autostart[reg_path] = value
                        i += 1
                    except WindowsError:
                        break
        except WindowsError as e:
            if e.winerror != 2:  # 忽略"找不到文件"错误
                print(f"访问注册表路径出错 {path}: {str(e)}")
            continue
            
    return wps_autostart

def get_service_details(service_name: str) -> Tuple[str, str, str]:
    """获取服务的详细信息"""
    try:
        # 打开服务控制管理器
        sc_handle = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
        
        try:
            # 打开服务
            service_handle = win32service.OpenService(
                sc_handle,
                service_name,
                win32service.SERVICE_QUERY_CONFIG | win32service.SERVICE_QUERY_STATUS
            )
            
            try:
                # 获取服务配置
                config = win32service.QueryServiceConfig(service_handle)
                # 获取服务描述
                try:
                    description = win32service.QueryServiceConfig2(
                        service_handle,
                        win32service.SERVICE_CONFIG_DESCRIPTION
                    )
                    desc = description['Description'] if description else "无描述"
                except (win32service.error, KeyError, TypeError):
                    desc = "无描述"

                # 获取服务状态
                status = win32service.QueryServiceStatus(service_handle)
                
                start_type = {
                    win32service.SERVICE_AUTO_START: "自动",
                    win32service.SERVICE_DEMAND_START: "手动",
                    win32service.SERVICE_DISABLED: "禁用",
                    win32service.SERVICE_BOOT_START: "系统启动",
                    win32service.SERVICE_SYSTEM_START: "系统启动"
                }.get(config[2], "未知")
                
                status_text = {
                    win32service.SERVICE_RUNNING: "运行中",
                    win32service.SERVICE_STOPPED: "已停止",
                    win32service.SERVICE_START_PENDING: "正在启动",
                    win32service.SERVICE_STOP_PENDING: "正在停止",
                    win32service.SERVICE_PAUSE_PENDING: "正在暂停",
                    win32service.SERVICE_PAUSED: "已暂停",
                    win32service.SERVICE_CONTINUE_PENDING: "正在继续"
                }.get(status[1], "未知状态")
                
                return start_type, status_text, desc
                
            finally:
                win32service.CloseServiceHandle(service_handle)
                
        finally:
            win32service.CloseServiceHandle(sc_handle)
            
    except win32service.error as e:
        return "未知", "无法获取", f"错误: {str(e)}"

def check_services() -> List[str]:
    """检查WPS相关的系统服务"""
    wps_services = []
    
    try:
        # 打开服务控制管理器
        sc_handle = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
        
        try:
            # 枚举所有服务
            services = win32service.EnumServicesStatus(
                sc_handle,
                win32service.SERVICE_WIN32,
                win32service.SERVICE_STATE_ALL
            )
            
            for service in services:
                service_name = service[0]
                display_name = service[1]
                
                try:
                    # 打开服务句柄
                    service_handle = win32service.OpenService(
                        sc_handle, 
                        service_name, 
                        win32service.SERVICE_QUERY_CONFIG | win32service.SERVICE_QUERY_STATUS
                    )
                    
                    try:
                        # 获取服务配置
                        config = win32service.QueryServiceConfig(service_handle)
                        binary_path = config[3].lower() if config[3] else ""
                        
                        # 检查是否是WPS相关服务
                        if any(keyword in (service_name + display_name + binary_path).lower() 
                              for keyword in ['wps', 'kingsoft']):
                            
                            # 获取服务详细信息
                            start_type, status, desc = get_service_details(service_name)
                            
                            service_info = (
                                f"服务名: {service_name}\n"
                                f"显示名称: {display_name}\n"
                                f"启动类型: {start_type}\n"
                                f"当前状态: {status}\n"
                                f"描述: {desc}\n"
                                f"可执行文件路径: {binary_path}\n"
                            )
                            wps_services.append(service_info)
                    
                    finally:
                        win32service.CloseServiceHandle(service_handle)
                        
                except win32service.error as e:
                    print(f"获取服务 {service_name} 信息时出错: {str(e)}")
                    continue
                    
        finally:
            win32service.CloseServiceHandle(sc_handle)
            
    except win32service.error as e:
        print(f"枚举服务时出错: {str(e)}")
    
    return wps_services

def open_services_manager():
    """打开Windows服务管理器"""
    try:
        # 使用 Win32 API 打开服务管理器
        import win32api
        win32api.ShellExecute(0, 'open', 'services.msc', None, None, 1)
    except Exception as e:
        print(f"打开服务管理器失败: {str(e)}")

def open_service_in_manager(service_name: str):
    """打开指定服务的属性页面"""
    try:
        # 使用 Win32 API 打开服务管理器
        import win32api
        win32api.ShellExecute(0, 'open', 'services.msc', None, None, 1)
    except Exception as e:
        print(f"打开服务属性页面失败: {str(e)}")

def check_scheduled_tasks() -> List[str]:
    """检查计划任务中的WPS相关任务"""
    wps_tasks = []
    try:
        scheduler = win32com.client.Dispatch('Schedule.Service')
        scheduler.Connect()
        root_folder = scheduler.GetFolder("\\")
        tasks = root_folder.GetTasks(0)
        
        for task in tasks:
            try:
                if any(keyword in task.Path.lower() for keyword in ['wps', 'kingsoft']):
                    task_info = (
                        f"任务名称: {task.Name}\n"
                        f"任务路径: {task.Path}\n"
                        f"下次运行时间: {task.NextRunTime}\n"
                        f"状态: {'启用' if task.Enabled else '禁用'}\n"
                        f"上次运行时间: {task.LastRunTime}\n"
                        f"上次运行结果: {task.LastTaskResult}\n"
                    )
                    wps_tasks.append(task_info)
            except Exception as e:
                print(f"读取任务 {task.Name} 信息时出错: {str(e)}")
                
    except Exception as e:
        print(f"检查计划任务时出错: {str(e)}")
    
    return wps_tasks

def check_startup_folders() -> List[str]:
    """检查启动文件夹中的WPS相关项目"""
    startup_items = []
    
    # 获取所有可能的启动文件夹路径
    startup_paths = [
        os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup'),
        r'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp'
    ]
    
    for startup_path in startup_paths:
        try:
            if os.path.exists(startup_path):
                for item in os.listdir(startup_path):
                    item_path = os.path.join(startup_path, item)
                    if any(keyword in item.lower() for keyword in ['wps', 'kingsoft']):
                        try:
                            item_type = "文件夹" if os.path.isdir(item_path) else "文件"
                            item_info = (
                                f"名称: {item}\n"
                                f"类型: {item_type}\n"
                                f"位置: {item_path}\n"
                            )
                            if os.path.isfile(item_path):
                                # 如果是快捷方式，尝试获取目标
                                if item.lower().endswith('.lnk'):
                                    try:
                                        shell = win32com.client.Dispatch("WScript.Shell")
                                        shortcut = shell.CreateShortCut(item_path)
                                        item_info += f"目标路径: {shortcut.Targetpath}\n"
                                    except Exception:
                                        pass
                            startup_items.append(item_info)
                        except Exception as e:
                            print(f"读取启动项 {item} 信息时出错: {str(e)}")
        except Exception as e:
            print(f"检查启动文件夹 {startup_path} 时出错: {str(e)}")
    
    return startup_items

def check_wmi_subscriptions() -> List[str]:
    """检查WMI事件订阅（使用PowerShell替代WMI）"""
    wmi_items = []
    try:
        # 使用静默执行 PowerShell 命令
        ps_command = 'Get-WmiObject -Namespace root\subscription -Class __EventConsumer | Select-Object Name, __CLASS, CommandLineTemplate | ConvertTo-Json'
        result = run_command_silently(['powershell', '-Command', ps_command], shell=False)
        
        if result and result.returncode == 0:
            try:
                consumers = json.loads(result.stdout)
                if not isinstance(consumers, list):
                    consumers = [consumers]
                
                for consumer in consumers:
                    if any(keyword in str(consumer).lower() for keyword in ['wps', 'kingsoft']):
                        consumer_info = (
                            f"WMI消费者名称: {consumer.get('Name', 'Unknown')}\n"
                            f"类型: {consumer.get('__CLASS', 'Unknown')}\n"
                            f"命令行: {consumer.get('CommandLineTemplate', 'N/A')}\n"
                        )
                        wmi_items.append(consumer_info)
            except json.JSONDecodeError:
                pass
        
        # 检查事件过滤器
        ps_command = 'Get-WmiObject -Namespace root\subscription -Class __EventFilter | Select-Object Name, Query, QueryLanguage | ConvertTo-Json'
        result = run_command_silently(['powershell', '-Command', ps_command], shell=False)
        
        if result and result.returncode == 0:
            try:
                filters = json.loads(result.stdout)
                if not isinstance(filters, list):
                    filters = [filters]
                
                for filter in filters:
                    if any(keyword in str(filter).lower() for keyword in ['wps', 'kingsoft']):
                        filter_info = (
                            f"WMI过滤器名称: {filter.get('Name', 'Unknown')}\n"
                            f"查询语句: {filter.get('Query', 'Unknown')}\n"
                            f"查询语言: {filter.get('QueryLanguage', 'Unknown')}\n"
                        )
                        wmi_items.append(filter_info)
            except json.JSONDecodeError:
                pass
                
    except Exception as e:
        print(f"检查WMI订阅时出错: {str(e)}")
    
    return wmi_items

def check_com_objects() -> List[str]:
    """检查COM对象自启动项"""
    com_items = []
    clsid_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\CLSID"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Classes\CLSID"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Classes\CLSID")
    ]
    
    for hkey, path in clsid_paths:
        try:
            with winreg.OpenKey(hkey, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                i = 0
                while True:
                    try:
                        clsid = winreg.EnumKey(key, i)
                        try:
                            with winreg.OpenKey(key, f"{clsid}\\InprocServer32", 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as subkey:
                                value = winreg.QueryValue(subkey, "")
                                if any(keyword in value.lower() for keyword in ['wps', 'kingsoft']):
                                    # 获取COM对象名称
                                    try:
                                        with winreg.OpenKey(key, clsid, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as namekey:
                                            name = winreg.QueryValue(namekey, "")
                                    except:
                                        name = "未知"
                                    
                                    com_info = (
                                        f"COM对象名称: {name}\n"
                                        f"CLSID: {clsid}\n"
                                        f"路径: {value}\n"
                                    )
                                    com_items.append(com_info)
                        except WindowsError:
                            pass
                        i += 1
                    except WindowsError:
                        break
        except WindowsError as e:
            if e.winerror != 2:  # 忽略"找不到文件"错误
                print(f"访问COM注册表路径出错 {path}: {str(e)}")
            continue
    
    return com_items

def check_browser_extensions() -> List[str]:
    """检查浏览器扩展"""
    extension_items = []
    
    # Chrome扩展路径
    chrome_paths = [
        os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions'),
        os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\User Data\*\Extensions')
    ]
    
    # Edge扩展路径
    edge_paths = [
        os.path.expandvars(r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Extensions'),
        os.path.expandvars(r'%LOCALAPPDATA%\Microsoft\Edge\User Data\*\Extensions')
    ]
    
    def check_extension_folder(folder_path: str, browser_name: str):
        try:
            for ext_path in glob.glob(folder_path):
                if os.path.exists(ext_path):
                    for ext_id in os.listdir(ext_path):
                        manifest_paths = glob.glob(os.path.join(ext_path, ext_id, "*", "manifest.json"))
                        for manifest_path in manifest_paths:
                            try:
                                with open(manifest_path, 'r', encoding='utf-8') as f:
                                    manifest = json.load(f)
                                    if any(keyword in str(manifest).lower() for keyword in ['wps', 'kingsoft']):
                                        ext_info = (
                                            f"浏览器: {browser_name}\n"
                                            f"扩展名称: {manifest.get('name', '未知')}\n"
                                            f"扩展ID: {ext_id}\n"
                                            f"版本: {manifest.get('version', '未知')}\n"
                                            f"描述: {manifest.get('description', '无描述')}\n"
                                            f"位置: {manifest_path}\n"
                                        )
                                        extension_items.append(ext_info)
                            except Exception as e:
                                print(f"读取扩展信息时出错 {manifest_path}: {str(e)}")
        except Exception as e:
            print(f"检查扩展文件夹时出错 {folder_path}: {str(e)}")
    
    # 检查Chrome扩展
    for path in chrome_paths:
        check_extension_folder(path, "Chrome")
    
    # 检查Edge扩展
    for path in edge_paths:
        check_extension_folder(path, "Edge")
    
    return extension_items

def check_group_policy() -> List[str]:
    """检查组策略脚本"""
    policy_items = []
    
    policy_paths = [
        r'C:\Windows\System32\GroupPolicy\User\Scripts',
        r'C:\Windows\System32\GroupPolicy\Machine\Scripts'
    ]
    
    for base_path in policy_paths:
        try:
            if os.path.exists(base_path):
                # 检查登录/注销脚本
                for script_type in ['Logon', 'Logoff']:
                    script_path = os.path.join(base_path, script_type)
                    if os.path.exists(script_path):
                        # 检查脚本文件
                        for file in os.listdir(script_path):
                            file_path = os.path.join(script_path, file)
                            try:
                                if os.path.isfile(file_path):
                                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                        content = f.read()
                                        if any(keyword in content.lower() for keyword in ['wps', 'kingsoft']):
                                            policy_info = (
                                                f"策略类型: {script_type}\n"
                                                f"脚本名称: {file}\n"
                                                f"位置: {file_path}\n"
                                            )
                                            policy_items.append(policy_info)
                            except Exception as e:
                                print(f"读取策略脚本时出错 {file_path}: {str(e)}")
        except Exception as e:
            print(f"检查组策略路径时出错 {base_path}: {str(e)}")
    
    return policy_items

def check_drivers() -> List[str]:
    """检查驱动程序"""
    driver_items = []
    try:
        # 使用静默执行命令
        result = run_command_silently(['sc', 'query', 'type=', 'driver'])
        
        if result and result.returncode == 0:
            current_driver = {}
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith('SERVICE_NAME:'):
                    if current_driver and any(keyword in str(current_driver).lower() for keyword in ['wps', 'kingsoft']):
                        driver_info = (
                            f"驱动名称: {current_driver.get('DISPLAY_NAME', 'Unknown')}\n"
                            f"系统名称: {current_driver.get('SERVICE_NAME', 'Unknown')}\n"
                            f"状态: {current_driver.get('STATE', 'Unknown')}\n"
                            f"类型: {current_driver.get('TYPE', 'Unknown')}\n"
                            f"路径: {current_driver.get('BINARY_PATH_NAME', 'Unknown')}\n"
                        )
                        driver_items.append(driver_info)
                    current_driver = {'SERVICE_NAME': line.split(':', 1)[1].strip()}
                elif ':' in line:
                    key, value = line.split(':', 1)
                    current_driver[key.strip()] = value.strip()
            
            # 检查最后一个驱动
            if current_driver and any(keyword in str(current_driver).lower() for keyword in ['wps', 'kingsoft']):
                driver_info = (
                    f"驱动名称: {current_driver.get('DISPLAY_NAME', 'Unknown')}\n"
                    f"系统名称: {current_driver.get('SERVICE_NAME', 'Unknown')}\n"
                    f"状态: {current_driver.get('STATE', 'Unknown')}\n"
                    f"类型: {current_driver.get('TYPE', 'Unknown')}\n"
                    f"路径: {current_driver.get('BINARY_PATH_NAME', 'Unknown')}\n"
                )
                driver_items.append(driver_info)
                
    except Exception as e:
        print(f"检查驱动程序时出错: {str(e)}")
    
    return driver_items

def check_user_login_scripts() -> List[str]:
    """检查用户登录脚本"""
    script_items = []
    
    # 检查本地用户登录脚本
    script_paths = [
        os.path.expandvars(r'%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'),
        os.path.expandvars(r'%SystemDrive%\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'),
        r'C:\Windows\System32\GroupPolicy\User\Scripts\Logon',
        r'C:\Windows\System32\GroupPolicy\User\Scripts\Logoff'
    ]
    
    # 检查域登录脚本（如果在域环境中）
    try:
        import win32net
        dc_info = win32net.NetGetDCName(None, None)
        if dc_info:
            script_paths.append(rf'{dc_info}\SYSVOL\scripts')
    except:
        pass
    
    for script_path in script_paths:
        try:
            if os.path.exists(script_path):
                for root, dirs, files in os.walk(script_path):
                    for file in files:
                        if file.lower().endswith(('.bat', '.cmd', '.vbs', '.ps1', '.js')):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    if any(keyword in content.lower() for keyword in ['wps', 'kingsoft']):
                                        script_info = (
                                            f"脚本名称: {file}\n"
                                            f"脚本类型: {os.path.splitext(file)[1]}\n"
                                            f"位置: {file_path}\n"
                                        )
                                        script_items.append(script_info)
                            except Exception as e:
                                print(f"读取脚本文件时出错 {file_path}: {str(e)}")
        except Exception as e:
            print(f"检查脚本路径时出错 {script_path}: {str(e)}")
    
    return script_items

def check_firefox_extensions() -> List[str]:
    """检查Firefox浏览器扩展"""
    extension_items = []
    
    # Firefox配置文件路径
    firefox_paths = [
        os.path.expandvars(r'%APPDATA%\Mozilla\Firefox\Profiles'),
        os.path.expandvars(r'%LOCALAPPDATA%\Mozilla\Firefox\Profiles')
    ]
    
    for base_path in firefox_paths:
        try:
            if os.path.exists(base_path):
                # 遍历所有配置文件
                for profile in os.listdir(base_path):
                    profile_path = os.path.join(base_path, profile, 'extensions')
                    if os.path.exists(profile_path):
                        # 检查扩展文件
                        for ext in os.listdir(profile_path):
                            ext_path = os.path.join(profile_path, ext)
                            try:
                                if ext.endswith('.xpi'):
                                    # 解析XPI文件（实际上是ZIP文件）
                                    import zipfile
                                    with zipfile.ZipFile(ext_path, 'r') as z:
                                        try:
                                            manifest = json.loads(z.read('manifest.json').decode('utf-8'))
                                            if any(keyword in str(manifest).lower() for keyword in ['wps', 'kingsoft']):
                                                ext_info = (
                                                    f"浏览器: Firefox\n"
                                                    f"扩展名称: {manifest.get('name', '未知')}\n"
                                                    f"扩展ID: {ext}\n"
                                                    f"版本: {manifest.get('version', '未知')}\n"
                                                    f"描述: {manifest.get('description', '无描述')}\n"
                                                    f"位置: {ext_path}\n"
                                                )
                                                extension_items.append(ext_info)
                                        except:
                                            # 尝试读取旧版本的 install.rdf
                                            try:
                                                install_rdf = z.read('install.rdf').decode('utf-8')
                                                if 'wps' in install_rdf.lower() or 'kingsoft' in install_rdf.lower():
                                                    ext_info = (
                                                        f"浏览器: Firefox\n"
                                                        f"扩展ID: {ext}\n"
                                                        f"位置: {ext_path}\n"
                                                        f"注意: 旧版本扩展，无法读取详细信息\n"
                                                    )
                                                    extension_items.append(ext_info)
                                            except:
                                                pass
                            except Exception as e:
                                print(f"读取Firefox扩展时出错 {ext_path}: {str(e)}")
        except Exception as e:
            print(f"检查Firefox配置文件夹时出错 {base_path}: {str(e)}")
    
    return extension_items

def check_environment_variables() -> List[str]:
    """检查系统环境变量"""
    env_items = []
    
    # 检查系统环境变量
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    if any(keyword in str(value).lower() for keyword in ['wps', 'kingsoft']):
                        env_info = (
                            f"变量名: {name}\n"
                            f"变量值: {value}\n"
                            f"类型: 系统环境变量\n"
                        )
                        env_items.append(env_info)
                    i += 1
                except WindowsError:
                    break
    except WindowsError as e:
        print(f"检查系统环境变量时出错: {str(e)}")
    
    # 检查用户环境变量
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Environment', 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    if any(keyword in str(value).lower() for keyword in ['wps', 'kingsoft']):
                        env_info = (
                            f"变量名: {name}\n"
                            f"变量值: {value}\n"
                            f"类型: 用户环境变量\n"
                        )
                        env_items.append(env_info)
                    i += 1
                except WindowsError:
                    break
    except WindowsError as e:
        print(f"检查用户环境变量时出错: {str(e)}")
    
    return env_items

def delete_scheduled_tasks() -> List[str]:
    """删除WPS相关的计划任务"""
    deleted_tasks = []
    try:
        scheduler = win32com.client.Dispatch('Schedule.Service')
        scheduler.Connect()
        root_folder = scheduler.GetFolder("\\")
        tasks = root_folder.GetTasks(0)
        
        for task in tasks:
            try:
                if any(keyword in task.Path.lower() for keyword in ['wps', 'kingsoft']):
                    task_info = (
                        f"任务名称: {task.Name}\n"
                        f"任务路径: {task.Path}\n"
                    )
                    # 删除任务
                    try:
                        root_folder.DeleteTask(task.Name, 0)
                        task_info += "状态: 已成功删除\n"
                    except Exception as e:
                        task_info += f"状态: 删除失败 - {str(e)}\n"
                    
                    deleted_tasks.append(task_info)
            except Exception as e:
                print(f"处理任务 {task.Name} 时出错: {str(e)}")
                
    except Exception as e:
        print(f"删除计划任务时出错: {str(e)}")
    
    return deleted_tasks

def clean_all_wps():
    """一键清理所有WPS相关项目"""
    cleanup_results = {
        'processes': [],
        'tasks': [],
        'services': [],
        'registry': []
    }
    
    try:
        # 1. 终止进程
        wps_processes = find_wps_processes()
        if wps_processes:
            # 过滤掉当前程序进程
            current_pid = os.getpid()
            wps_processes = [proc for proc in wps_processes if proc.info['pid'] != current_pid]
            
            if wps_processes:  # 如果还有其他WPS进程
                kill_wps_processes(wps_processes)
                cleanup_results['processes'] = [
                    f"{proc.info['name']} (PID: {proc.info['pid']})"
                    for proc in wps_processes
                ]
        
        # 2. 删除计划任务
        deleted_tasks = delete_scheduled_tasks()
        if deleted_tasks:
            cleanup_results['tasks'] = deleted_tasks
        
        # 3. 停止并禁用服务
        try:
            sc_handle = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
            services = win32service.EnumServicesStatus(
                sc_handle,
                win32service.SERVICE_WIN32,
                win32service.SERVICE_STATE_ALL
            )
            
            for service in services:
                service_name = service[0]
                try:
                    service_handle = win32service.OpenService(
                        sc_handle, 
                        service_name, 
                        win32service.SERVICE_ALL_ACCESS
                    )
                    
                    config = win32service.QueryServiceConfig(service_handle)
                    binary_path = config[3].lower() if config[3] else ""
                    
                    if any(keyword in (service_name + binary_path).lower() 
                          for keyword in ['wps', 'kingsoft']):
                        try:
                            # 停止服务
                            win32service.ControlService(service_handle, win32service.SERVICE_CONTROL_STOP)
                        except:
                            pass
                        
                        try:
                            # 禁用服务
                            win32service.ChangeServiceConfig(
                                service_handle,
                                win32service.SERVICE_NO_CHANGE,
                                win32service.SERVICE_DISABLED,
                                win32service.SERVICE_NO_CHANGE,
                                None,
                                None,
                                0,
                                None,
                                None,
                                None,
                                None
                            )
                            cleanup_results['services'].append(
                                f"服务名: {service_name}\n状态: 已停止并禁用"
                            )
                        except Exception as e:
                            cleanup_results['services'].append(
                                f"服务名: {service_name}\n状态: 禁用失败 - {str(e)}"
                            )
                            
                    win32service.CloseServiceHandle(service_handle)
                except:
                    continue
                    
            win32service.CloseServiceHandle(sc_handle)
        except Exception as e:
            print(f"处理服务时出错: {str(e)}")
        
        # 4. 清理注册表
        autostart_entries = check_registry_autostart()
        if autostart_entries:
            for reg_path, value in autostart_entries.items():
                try:
                    # 解析注册表路径
                    if reg_path.startswith("HKEY_LOCAL_MACHINE\\"):
                        hkey = winreg.HKEY_LOCAL_MACHINE
                        reg_path = reg_path[len("HKEY_LOCAL_MACHINE\\"):]
                    elif reg_path.startswith("HKEY_CURRENT_USER\\"):
                        hkey = winreg.HKEY_CURRENT_USER
                        reg_path = reg_path[len("HKEY_CURRENT_USER\\"):]
                    
                    # 分离键路径和值名称
                    key_path = "\\".join(reg_path.split("\\")[:-1])
                    value_name = reg_path.split("\\")[-1]
                    
                    # 删除注册表项
                    with winreg.OpenKey(hkey, key_path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
                        winreg.DeleteValue(key, value_name)
                        cleanup_results['registry'].append(
                            f"已删除: {reg_path}\n原值: {value}"
                        )
                except Exception as e:
                    cleanup_results['registry'].append(
                        f"删除失败: {reg_path}\n错误: {str(e)}"
                    )
                    
    except Exception as e:
        print(f"清理过程中出错: {str(e)}")
    
    return cleanup_results

def run_command_silently(command, shell=True):
    """静默执行命令，不显示命令行窗口"""
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    
    try:
        result = subprocess.run(
            command,
            shell=shell,
            capture_output=True,
            text=True,
            encoding='gbk',
            errors='ignore',
            creationflags=subprocess.CREATE_NO_WINDOW,
            startupinfo=startupinfo
        )
        return result
    except Exception as e:
        print(f"执行命令失败: {str(e)}")
        return None

class RedirectText:
    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.buffer = io.StringIO()

    def write(self, string):
        try:
            self.buffer.write(string)
            if hasattr(self, 'text_widget') and self.text_widget:
                self.text_widget.delete(1.0, tk.END)
                self.text_widget.insert(tk.END, self.buffer.getvalue())
                self.text_widget.see(tk.END)
                self.text_widget.update()
        except Exception as e:
            print(f"日志写入错误: {str(e)}")

    def flush(self):
        pass

class WPSKillerGUI:
    def __init__(self, root):
        self.root = root
        # 设置窗口最小尺寸
        self.root.minsize(800, 600)
        # 配置窗口缩放权重
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        # 设置窗口样式
        self.setup_styles()
        self.create_widgets()
    
    def setup_styles(self):
        """设置自定义样式"""
        style = ttk.Style()
        # 主题设置
        if 'vista' in style.theme_names():
            style.theme_use('vista')
        elif 'winnative' in style.theme_names():
            style.theme_use('winnative')
        
        # 按钮样式
        style.configure('Action.TButton',
                       padding=6,
                       font=('Microsoft YaHei UI', 9))
        
        # 标签样式
        style.configure('Status.TLabel',
                       font=('Microsoft YaHei UI', 10),
                       padding=5)
        
        # 标签框样式
        style.configure('Custom.TLabelframe',
                       padding=8)
        style.configure('Custom.TLabelframe.Label',
                       font=('Microsoft YaHei UI', 9, 'bold'))
        
    def create_widgets(self):
        # 创建主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(2, weight=1)  # 让日志区域可以自适应

        # 状态标签
        self.status_label = ttk.Label(
            main_frame,
            text="准备就绪",
            style='Status.TLabel'
        )
        self.status_label.grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))

        # 按钮框架
        button_frame = ttk.LabelFrame(main_frame, text="操作面板", style='Custom.TLabelframe')
        button_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10), padx=2)
        
        # 创建两行按钮框架
        row1_frame = ttk.Frame(button_frame)
        row1_frame.pack(fill=tk.X, padx=5, pady=(5, 2))
        row1_frame.grid_columnconfigure((0,1,2,3), weight=1)
        
        row2_frame = ttk.Frame(button_frame)
        row2_frame.pack(fill=tk.X, padx=5, pady=(2, 5))
        row2_frame.grid_columnconfigure((0,1,2,3), weight=1)

        # 第一行按钮
        btn1 = ttk.Button(row1_frame, text="终止 WPS 进程", width=15,
                         command=lambda: self.run_task(self.kill_wps), style='Action.TButton')
        btn1.grid(row=0, column=0, padx=2, sticky='ew')
        
        btn2 = ttk.Button(row1_frame, text="检查自启动项", width=15,
                         command=lambda: self.run_task(self.check_autostart), style='Action.TButton')
        btn2.grid(row=0, column=1, padx=2, sticky='ew')
        
        btn3 = ttk.Button(row1_frame, text="检查系统服务", width=15,
                         command=lambda: self.run_task(self.check_service), style='Action.TButton')
        btn3.grid(row=0, column=2, padx=2, sticky='ew')
        
        btn4 = ttk.Button(row1_frame, text="打开服务管理器", width=15,
                         command=open_services_manager, style='Action.TButton')
        btn4.grid(row=0, column=3, padx=2, sticky='ew')

        # 第二行按钮
        btn5 = ttk.Button(row2_frame, text="全面检查自启动", width=15,
                         command=lambda: self.run_task(self.check_all_startup_locations), style='Action.TButton')
        btn5.grid(row=0, column=0, padx=2, sticky='ew')
        
        btn6 = ttk.Button(row2_frame, text="刷新状态", width=15,
                         command=self.refresh_all, style='Action.TButton')
        btn6.grid(row=0, column=1, padx=2, sticky='ew')
        
        btn7 = ttk.Button(row2_frame, text="清理计划任务", width=15,
                         command=lambda: self.run_task(self.clean_scheduled_tasks), style='Action.TButton')
        btn7.grid(row=0, column=2, padx=2, sticky='ew')
        
        btn8 = ttk.Button(row2_frame, text="全面强制清理", width=15,
                         command=lambda: self.run_task(self.clean_all), style='Action.TButton')
        btn8.grid(row=0, column=3, padx=2, sticky='ew')

        # 日志框架
        log_frame = ttk.LabelFrame(main_frame, text="操作日志", style='Custom.TLabelframe')
        log_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 5), padx=2)
        
        # 创建日志文本框和滚动条
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            width=80,
            height=20,
            font=("Consolas", 10)
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 重定向标准输出到日志文本框
        sys.stdout = RedirectText(self.log_text)
        
        # 检查管理员权限
        if not is_admin():
            self.status_label.config(
                text="警告: 程序没有以管理员权限运行，某些操作可能失败",
                foreground="red"
            )
            print("建议：请右键以管理员身份运行此程序\n")
        
        # 添加版本信息
        print(f"Python 版本: {sys.version}")
        print(f"操作系统: {os.name} - {sys.platform}")
        print("程序初始化完成\n")

    def run_task(self, task):
        """在新线程中运行任务"""
        try:
            # 禁用所有按钮
            self.disable_buttons()
            
            # 在新线程中运行任务
            thread = threading.Thread(target=self.task_wrapper, args=(task,))
            thread.daemon = True
            thread.start()
        except Exception as e:
            print(f"启动任务失败: {str(e)}")
            self.enable_buttons()
    
    def task_wrapper(self, task):
        """任务包装器，处理任务执行的状态和错误"""
        try:
            self.status_label.config(text="正在执行操作...", foreground="blue")
            task()
            self.status_label.config(text="操作完成", foreground="green")
        except Exception as e:
            self.status_label.config(text=f"操作失败: {str(e)}", foreground="red")
            print(f"\n错误详情:\n{traceback.format_exc()}")
        finally:
            # 重新启用所有按钮
            self.root.after(0, self.enable_buttons)
    
    def disable_buttons(self):
        """禁用所有按钮"""
        for child in self.root.winfo_children():
            for subchild in child.winfo_children():
                if isinstance(subchild, ttk.LabelFrame):
                    for frame in subchild.winfo_children():
                        for button in frame.winfo_children():
                            if isinstance(button, ttk.Button):
                                button.state(['disabled'])
    
    def enable_buttons(self):
        """启用所有按钮"""
        for child in self.root.winfo_children():
            for subchild in child.winfo_children():
                if isinstance(subchild, ttk.LabelFrame):
                    for frame in subchild.winfo_children():
                        for button in frame.winfo_children():
                            if isinstance(button, ttk.Button):
                                button.state(['!disabled'])
    
    def kill_wps(self):
        """终止WPS进程"""
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 开始查找并终止 WPS 进程...")
        wps_processes = find_wps_processes()
        if wps_processes:
            kill_wps_processes(wps_processes)
            print(f"已终止 {len(wps_processes)} 个 WPS 相关进程")
        else:
            print("未发现正在运行的 WPS 进程")
    
    def check_autostart(self):
        """检查自启动项"""
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 开始检查注册表自启动项...")
        autostart_entries = check_registry_autostart()
        if autostart_entries:
            print("\n发现以下 WPS 相关自启动项：")
            for path, value in autostart_entries.items():
                print(f"位置: {path}")
                print(f"命令: {value}\n")
        else:
            print("未发现 WPS 相关自启动项")
    
    def check_service(self):
        """检查系统服务"""
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 开始检查系统服务...")
        wps_services = check_services()
        if wps_services:
            print("\n发现以下 WPS 相关服务：")
            for service in wps_services:
                # 从服务信息中提取服务名
                service_name = service.split('\n')[0].split(': ')[1]
                
                # 先插入服务信息
                self.log_text.insert(tk.END, service)
                
                # 插入可点击的链接
                link_text = f"[点击此处打开服务属性页面]"
                start_index = self.log_text.index("end-1c")
                self.log_text.insert(tk.END, f"\n{link_text}\n\n")
                
                # 计算链接的开始和结束位置
                end_index = self.log_text.index("end-2c")
                start_index_link = f"{start_index}-{len(link_text)}c"
                
                # 为链接添加标签
                tag_name = f"link_{service_name}"
                self.log_text.tag_add(tag_name, start_index_link, end_index)
                self.log_text.tag_config(tag_name, foreground="blue", underline=1)
                self.log_text.tag_bind(tag_name, "<Button-1>", 
                                     lambda e, name=service_name: open_service_in_manager(name))
                self.log_text.tag_bind(tag_name, "<Enter>", 
                                     lambda e: self.log_text.config(cursor="hand2"))
                self.log_text.tag_bind(tag_name, "<Leave>", 
                                     lambda e: self.log_text.config(cursor=""))
        else:
            print("未发现 WPS 相关服务")
    
    def refresh_all(self):
        """刷新所有状态"""
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 刷新状态...")
        self.kill_wps()
        self.check_autostart()
        self.check_service()
    
    def check_all_startup_locations(self):
        """检查所有可能的自启动位置"""
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 开始全面检查自启动项...")
        
        # 1. 检查计划任务
        print("\n=== 检查计划任务 ===")
        tasks = check_scheduled_tasks()
        if tasks:
            print("\n发现以下 WPS 相关计划任务：")
            for task in tasks:
                print(f"{task}\n")
        else:
            print("未发现 WPS 相关计划任务")
        
        # 2. 检查启动文件夹
        print("\n=== 检查启动文件夹 ===")
        startup_items = check_startup_folders()
        if startup_items:
            print("\n发现以下 WPS 相关启动项：")
            for item in startup_items:
                print(f"{item}\n")
        else:
            print("未发现 WPS 相关启动项")
        
        # 3. 检查注册表自启动项
        print("\n=== 检查注册表自启动项 ===")
        self.check_autostart()
        
        # 4. 检查系统服务
        print("\n=== 检查系统服务 ===")
        self.check_service()

        # 5. 检查WMI事件订阅
        print("\n=== 检查WMI事件订阅 ===")
        wmi_items = check_wmi_subscriptions()
        if wmi_items:
            print("\n发现以下 WPS 相关WMI订阅：")
            for item in wmi_items:
                print(f"{item}\n")
        else:
            print("未发现 WPS 相关WMI订阅")

        # 6. 检查COM对象
        print("\n=== 检查COM对象 ===")
        com_items = check_com_objects()
        if com_items:
            print("\n发现以下 WPS 相关COM对象：")
            for item in com_items:
                print(f"{item}\n")
        else:
            print("未发现 WPS 相关COM对象")

        # 7. 检查浏览器扩展
        print("\n=== 检查浏览器扩展 ===")
        extension_items = check_browser_extensions()
        if extension_items:
            print("\n发现以下 WPS 相关浏览器扩展：")
            for item in extension_items:
                print(f"{item}\n")
        else:
            print("未发现 WPS 相关浏览器扩展")

        # 8. 检查组策略脚本
        print("\n=== 检查组策略脚本 ===")
        policy_items = check_group_policy()
        if policy_items:
            print("\n发现以下 WPS 相关组策略脚本：")
            for item in policy_items:
                print(f"{item}\n")
        else:
            print("未发现 WPS 相关组策略脚本")

        # 9. 检查驱动程序
        print("\n=== 检查驱动程序 ===")
        driver_items = check_drivers()
        if driver_items:
            print("\n发现以下 WPS 相关驱动程序：")
            for item in driver_items:
                print(f"{item}\n")
        else:
            print("未发现 WPS 相关驱动程序")

        # 10. 检查用户登录脚本
        print("\n=== 检查用户登录脚本 ===")
        script_items = check_user_login_scripts()
        if script_items:
            print("\n发现以下 WPS 相关登录脚本：")
            for item in script_items:
                print(f"{item}\n")
        else:
            print("未发现 WPS 相关登录脚本")

        # 11. 检查Firefox扩展
        print("\n=== 检查Firefox扩展 ===")
        firefox_items = check_firefox_extensions()
        if firefox_items:
            print("\n发现以下 WPS 相关Firefox扩展：")
            for item in firefox_items:
                print(f"{item}\n")
        else:
            print("未发现 WPS 相关Firefox扩展")

        # 12. 检查环境变量
        print("\n=== 检查环境变量 ===")
        env_items = check_environment_variables()
        if env_items:
            print("\n发现以下 WPS 相关环境变量：")
            for item in env_items:
                print(f"{item}\n")
        else:
            print("未发现 WPS 相关环境变量")

    def clean_scheduled_tasks(self):
        """清理WPS相关的计划任务"""
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 开始清理 WPS 相关计划任务...")
        
        # 先列出所有相关任务
        tasks = check_scheduled_tasks()
        if not tasks:
            print("未发现 WPS 相关计划任务")
            return
        
        print("\n发现以下 WPS 相关计划任务：")
        for task in tasks:
            print(f"{task}\n")
        
        # 询问用户是否确认删除
        if messagebox.askyesno("确认", "是否删除以上所有 WPS 相关计划任务？"):
            deleted_tasks = delete_scheduled_tasks()
            if deleted_tasks:
                print("\n清理结果：")
                for task in deleted_tasks:
                    print(f"{task}\n")
                print("计划任务清理完成")
            else:
                print("清理过程中出现错误，请查看详细日志")
        else:
            print("已取消清理操作")

    def clean_all(self):
        """一键清理所有WPS相关项目"""
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 开始全面清理 WPS...")
        
        # 创建自定义对话框
        dialog = tk.Toplevel(self.root)
        dialog.title("确认清理")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.attributes('-topmost', True)  # 窗口置顶
        
        # 设置对话框大小和位置
        dialog_width = 350
        dialog_height = 350
        screen_width = dialog.winfo_screenwidth()
        screen_height = dialog.winfo_screenheight()
        x = (screen_width - dialog_width) // 2
        y = (screen_height - dialog_height) // 2
        dialog.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")
        
        # 禁止调整窗口大小
        dialog.resizable(False, False)
        
        # 设置对话框样式
        dialog.configure(bg='#f0f0f0')
        dialog_frame = ttk.Frame(dialog, padding="15")  # 减小内边距
        dialog_frame.pack(fill=tk.BOTH, expand=True)  # 使用pack替代grid以获得更好的布局控制
        
        # 创建标题框架
        title_frame = ttk.Frame(dialog_frame)
        title_frame.pack(fill=tk.X, pady=(0, 15))
        
        # 添加图标和标题
        try:
            warning_icon = ttk.Label(
                title_frame,
                image=self.root.tk.call('tk', 'getImage', 'warning'),
                padding=(0, 0, 10, 0)
            )
            warning_icon.pack(side=tk.LEFT)
        except:
            pass
        
        # 添加标题
        title_label = ttk.Label(
            title_frame,
            text="即将执行全面清理",
            font=("Microsoft YaHei UI", 12, "bold"),
            foreground="#333333"
        )
        title_label.pack(side=tk.LEFT)
        
        # 添加说明文本
        desc_frame = ttk.Frame(dialog_frame)
        desc_frame.pack(fill=tk.BOTH, expand=True)
        
        desc_label = ttk.Label(
            desc_frame,
            text="此操作将清理所有WPS相关的：",
            font=("Microsoft YaHei UI", 10),
            wraplength=300  # 从 350 减小到 300
        )
        desc_label.pack(anchor=tk.W)
        
        # 添加清理项目列表
        items_frame = ttk.Frame(desc_frame)
        items_frame.pack(fill=tk.X, pady=(5, 0))
        
        for i, item in enumerate([
            "正在运行的进程",
            "计划任务",
            "系统服务",
            "注册表自启动项"
        ]):
            item_label = ttk.Label(
                items_frame,
                text=f"{i+1}. {item}",
                font=("Microsoft YaHei UI", 10),
                padding=(20, 2)
            )
            item_label.pack(anchor=tk.W)
        
        # 添加警告文本
        warning_frame = ttk.Frame(dialog_frame)
        warning_frame.pack(fill=tk.X, pady=(15, 0))
        
        warning_label = ttk.Label(
            warning_frame,
            text="请立即保存你正在运行的文件，\n然后再点击确定清理。\n否则你正在编写的文件将无法保存进度。",
            font=("Microsoft YaHei UI", 10, "bold"),
            foreground="red",
            wraplength=300  # 从 350 减小到 300
        )
        warning_label.pack(fill=tk.X)
        
        # 添加按钮框架
        button_frame = ttk.Frame(dialog_frame)
        button_frame.pack(fill=tk.X, pady=(15, 0))
        
        def on_yes():
            dialog.result = True
            dialog.destroy()
            
        def on_no():
            dialog.result = False
            dialog.destroy()
        
        # 创建按钮样式
        style = ttk.Style()
        style.configure('Yes.TButton', padding=5)
        style.configure('No.TButton', padding=5)
        
        # 按钮容器使用居中对齐
        button_container = ttk.Frame(button_frame)
        button_container.pack(side=tk.TOP, anchor=tk.CENTER)
        
        no_button = ttk.Button(
            button_container,
            text="取消",
            command=on_no,
            style='No.TButton',
            width=10
        )
        no_button.pack(side=tk.LEFT, padx=5)
        
        yes_button = ttk.Button(
            button_container,
            text="确定清理",
            command=on_yes,
            style='Yes.TButton',
            width=10
        )
        yes_button.pack(side=tk.LEFT)
        
        # 设置默认焦点到"取消"按钮
        no_button.focus_set()
        
        # 添加快捷键
        dialog.bind('<Return>', lambda e: on_no())
        dialog.bind('<Escape>', lambda e: on_no())
        
        # 等待对话框关闭
        dialog.wait_window()
        
        # 处理结果
        if hasattr(dialog, 'result') and dialog.result:
            results = clean_all_wps()
            
            print("\n=== 清理结果 ===")
            
            if results['processes']:
                print("\n已终止的进程：")
                for proc in results['processes']:
                    print(f"- {proc}")
            
            if results['tasks']:
                print("\n已清理的计划任务：")
                for task in results['tasks']:
                    print(f"{task}")
            
            if results['services']:
                print("\n已处理的服务：")
                for service in results['services']:
                    print(f"{service}\n")
            
            if results['registry']:
                print("\n已清理的注册表项：")
                for reg in results['registry']:
                    print(f"{reg}\n")
            
            if not any(results.values()):
                print("\n未发现需要清理的项目")
            else:
                print("\n清理完成")
        else:
            print("已取消清理操作")

def check_windows_compatibility():
    """检查Windows系统兼容性"""
    try:
        import platform
        win_ver = platform.win32_ver()[0]
        win_build = platform.version().split('.')[-1]
        
        # 检查是否是Windows 10或更高版本
        if int(win_ver) < 10:
            messagebox.showwarning(
                "系统兼容性警告",
                "此程序设计用于Windows 10及更高版本。\n"
                "在较低版本的Windows上可能无法正常工作。"
            )
            return False
            
        return True
        
    except Exception as e:
        print(f"检查系统兼容性时出错: {str(e)}")
        return True  # 如果无法检查，则默认允许运行

def prevent_multiple_instances():
    """防止程序重复运行"""
    try:
        # 创建一个全局互斥体
        mutex_name = "Global\\WPSKillerGUI_SingleInstance"
        mutex = win32event.CreateMutex(None, False, mutex_name)
        last_error = win32api.GetLastError()
        
        # 如果互斥体已存在，说明程序已在运行
        if last_error == winerror.ERROR_ALREADY_EXISTS:
            # 查找当前运行的程序窗口并激活
            try:
                import win32gui
                import win32con
                
                def enum_windows_callback(hwnd, window_list):
                    if win32gui.IsWindowVisible(hwnd):
                        window_text = win32gui.GetWindowText(hwnd)
                        if "WPS进程清理工具" in window_text:
                            window_list.append(hwnd)
                    return True
                
                window_list = []
                win32gui.EnumWindows(enum_windows_callback, window_list)
                
                if window_list:
                    # 找到窗口，激活它
                    hwnd = window_list[0]
                    # 如果窗口被最小化，恢复它
                    if win32gui.IsIconic(hwnd):
                        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
                    # 将窗口置于前台
                    win32gui.SetForegroundWindow(hwnd)
            except:
                pass
                
            # 创建置顶的提示窗口
            root = tk.Tk()
            root.withdraw()  # 隐藏主窗口
            root.attributes('-topmost', True)  # 设置为最顶层
            messagebox.showinfo("提示", "程序已在运行中")
            root.destroy()
            sys.exit(1)  # 使用非零退出码表示程序已在运行
            
        return mutex
        
    except Exception as e:
        print(f"检查程序实例时出错: {str(e)}")
        return None

def main():
    """主程序入口"""
    try:
        # 检查是否已有实例在运行
        mutex = prevent_multiple_instances()
        if mutex is None:
            sys.exit(1)
            
        # 检查系统兼容性
        if not check_windows_compatibility():
            sys.exit(1)
            
        # 基本初始化
        root = None
        try:
            # 创建主窗口
            root = tk.Tk()
            root.title("WPS进程清理工具")
            root.geometry("800x600")
            
            # 初始化GUI
            app = WPSKillerGUI(root)
            
            # 启动主循环
            root.mainloop()
            
        except Exception as e:
            error_msg = f"创建主窗口失败: {str(e)}"
            print(error_msg)
            print(traceback.format_exc())
            if root:
                try:
                    messagebox.showerror("错误", error_msg)
                except:
                    pass
            sys.exit(1)
            
    except Exception as e:
        print(f"程序启动失败: {str(e)}")
        print(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main() 