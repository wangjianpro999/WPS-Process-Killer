# WPS进程清理工具 (WPS Process Killer)

一个用于清理WPS相关进程和自启动项的图形界面工具。该工具可以帮助你彻底清理WPS的各种进程、服务和自启动项，解决WPS后台常驻导致的各种问题。

## 功能特点

- 查找并终止所有WPS相关进程
- 检查注册表中的自启动项
- 检查和管理WPS相关的系统服务
- 检查计划任务中的WPS相关任务
- 检查启动文件夹中的WPS项目
- 检查浏览器扩展
- 一键清理所有WPS相关项目
- 友好的图形用户界面
- 支持管理员权限运行以获得完整功能
- 详细的操作日志

## 系统要求

- Windows操作系统（Windows 7/8/10/11）
- Python 3.6+
- 管理员权限（用于某些清理操作）

## 依赖包

```
pywin32>=305
psutil>=5.9.0
tkinter (Python标准库)
```

## 安装

1. 克隆仓库：
```bash
git clone https://github.com/wangjianpro999/WPS-Process-Killer.git
```

2. 安装依赖：
```bash
pip install -r requirements.txt
```

## 使用方法

### 方法1：直接运行Python脚本
```bash
python wps_killer_gui.py
```

### 方法2：使用编译后的可执行文件
1. 运行`build.bat`进行编译
2. 编译后的程序将在`dist`目录中
3. 双击运行可执行文件（建议使用管理员权限运行）

## 功能说明

1. **终止WPS进程**
   - 查找并终止所有WPS相关进程
   - 包括主程序、PDF阅读器、云服务等
   - 智能识别WPS相关进程
   - 支持强制结束顽固进程

2. **检查自启动项**
   - 检查注册表中的自启动项
   - 检查启动文件夹
   - 检查计划任务
   - 检查服务自启动项
   - 支持一键禁用自启动

3. **服务管理**
   - 检查WPS相关的系统服务
   - 提供服务启动/停止功能
   - 修改服务启动类型
   - 删除不需要的服务

4. **一键清理**
   - 一次性清理所有WPS相关项目
   - 包括进程、服务、自启动项等
   - 自动备份重要配置
   - 清理后自动生成报告

## 高级功能

- **智能检测**：自动识别WPS的各种组件和服务
- **安全模式**：可以在安全模式下运行，避免对系统造成影响
- **日志记录**：详细记录所有操作，方便追踪和调试
- **自动更新**：检查并提示新版本更新
- **配置导出**：支持导出当前系统的WPS配置信息

## 注意事项

- 使用管理员权限运行可以获得完整的清理功能
- 清理操作不可逆，请谨慎操作
- 建议在清理前保存所有WPS文档
- 如果使用WPS云服务，请确保数据已同步
- 建议在操作前创建系统还原点

## 常见问题

1. **为什么需要管理员权限？**
   - 某些系统级操作（如服务管理、注册表修改）需要管理员权限
   
2. **清理后会影响WPS的正常使用吗？**
   - 清理后需要重新启动WPS，但不会影响正常使用
   - 可能需要重新登录WPS账号

3. **如何确保清理安全？**
   - 程序会自动备份重要配置
   - 提供了安全模式选项
   - 详细的操作日志便于追踪问题

## 许可证

MIT License

## 贡献

欢迎提交问题和改进建议！您可以通过以下方式参与：

1. 提交 Issue
2. 提交 Pull Request
3. 完善文档
4. 分享使用经验

## 更新日志

### v1.0.0 (2025-01-11)
- 初始版本发布
- 实现基本的进程清理功能
- 添加自启动项管理
- 添加服务管理功能
- 实现一键清理功能
