import psutil
import winreg
import subprocess
import os
from typing import List, Dict, Tuple
import win32serviceutil
import win32service
import win32security

def find_wps_processes() -> List[psutil.Process]:
    """查找所有WPS相关进程"""
    wps_process_names = [
        'wps', 'wpp', 'et',  # 主程序
        'wpspdf', 'wpscloudsvr',  # PDF和云服务
        'wpsoffice', 'wpsnotify',  # 办公套件和通知
        'wpscenter', 'wpscloudlaunch'  # 服务中心和云启动器
    ]
    
    wps_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            proc_name = proc.info['name'].lower()
            if any(wps_name in proc_name for wps_name in wps_process_names):
                wps_processes.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            continue
    return wps_processes

def kill_wps_processes(processes: List[psutil.Process]) -> None:
    """终止WPS相关进程"""
    for proc in processes:
        try:
            print(f"正在终止进程: {proc.info['name']} (PID: {proc.info['pid']})")
            proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"无法终止进程 {proc.info['name']}: {str(e)}")
            print("尝试使用管理员权限终止...")
            try:
                subprocess.run(['taskkill', '/F', '/PID', str(proc.info['pid'])], 
                             check=True, capture_output=True)
                print(f"成功终止进程 {proc.info['name']}")
            except subprocess.CalledProcessError as e:
                print(f"使用管理员权限终止失败: {e.stderr.decode('gbk', errors='ignore')}")

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
    
    for hkey, path in autostart_locations:
        try:
            with winreg.OpenKey(hkey, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        if any(keyword in (name + value).lower() for keyword in ['wps', 'kingsoft', 'office']):
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
        config = win32serviceutil.QueryServiceConfig(service_name)
        description = win32serviceutil.QueryServiceConfig2(service_name, win32service.SERVICE_CONFIG_DESCRIPTION)
        status = win32serviceutil.QueryServiceStatus(service_name)
        
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
        
        desc = description or "无描述"
        
        return start_type, status_text, desc
        
    except win32service.error as e:
        return "未知", "无法获取", f"错误: {str(e)}"

def check_services() -> List[str]:
    """检查WPS相关的系统服务"""
    wps_services = []
    
    try:
        services = win32serviceutil.EnumServicesStatus()
        for service in services:
            service_name = service[0]
            display_name = service[1]
            
            try:
                service_info = win32serviceutil.QueryServiceConfig(service_name)
                binary_path = service_info[3].lower() if service_info[3] else ""
                
                if any(keyword in (service_name + display_name + binary_path).lower() 
                      for keyword in ['wps', 'kingsoft']):
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
                    
            except win32service.error as e:
                print(f"获取服务 {service_name} 信息时出错: {str(e)}")
                continue
    except win32service.error as e:
        print(f"枚举服务时出错: {str(e)}")
    
    return wps_services

def main():
    # 检查是否具有管理员权限
    try:
        is_admin = win32security.IsUserAnAdmin()
        if not is_admin:
            print("警告: 程序没有以管理员权限运行，某些操作可能失败\n")
    except:
        print("警告: 无法检查管理员权限状态\n")

    print("=== WPS 进程清理工具 ===")
    print("\n1. 查找并终止 WPS 进程...")
    wps_processes = find_wps_processes()
    if wps_processes:
        kill_wps_processes(wps_processes)
        print(f"已终止 {len(wps_processes)} 个 WPS 相关进程")
    else:
        print("未发现正在运行的 WPS 进程")
    
    print("\n2. 检查注册表自启动项...")
    autostart_entries = check_registry_autostart()
    if autostart_entries:
        print("\n发现以下 WPS 相关自启动项：")
        for path, value in autostart_entries.items():
            print(f"位置: {path}")
            print(f"命令: {value}\n")
    else:
        print("未发现 WPS 相关自启动项")
    
    print("\n3. 检查系统服务...")
    wps_services = check_services()
    if wps_services:
        print("\n发现以下 WPS 相关服务：")
        for service in wps_services:
            print(f"{service}\n")
    else:
        print("未发现 WPS 相关服务")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"程序运行出错: {str(e)}")
        import traceback
        print("\n详细错误信息:")
        print(traceback.format_exc())
    
    input("\n按回车键退出...") 