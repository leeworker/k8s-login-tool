#!/usr/bin/env python3
# coding: utf-8
"""
快速登录 Kubernetes Pod 的工具

使用方法:
    python k8s_login.py <pod_name> [namespace]
    
参数:
    pod_name: Pod 名称（必填）
    namespace: 命名空间（选填，默认为 default）
"""

import argparse
import subprocess
import sys
import re
import os


# 在文件开头添加颜色类
class Colors:
    """终端颜色定义"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def setup_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='快速登录 Kubernetes Pod 工具, 作者: lee_worker, 版本: 1.0.0 欢迎使用, 反馈Bug')
    parser.add_argument('pod_name', nargs='?', help='Pod 名称（可选）')
    parser.add_argument('namespace', nargs='?', help='命名空间（可选）')
    return parser.parse_args()

def parse_kubectl_output(line):
    """解析 kubectl 输出的单行数据"""
    line = line.strip()
    
    # 首先尝试分离namespace（如果存在）
    if ' ' not in line:
        return None
        
    # 使用正则表达式匹配各个字段
    pattern = r'''
        ^(?:(\S+)\s+)?                    # Namespace (可选)
        ([^\s](?:.*?[^\s])?)\s+          # Name (可能包含空格)
        (\d+/\d+)\s+                      # Ready
        (\S+)\s+                          # Status
        (\d+(?:\s+\(\d+\w+\s+ago\))?)\s+ # Restarts (可能包含时间信息)
        (\S+)\s+                          # Age
        (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?\s* # IP (可选)
        (.*)$                             # Node (剩余所有内容)
    '''
    
    match = re.match(pattern, line.strip(), re.VERBOSE)
    if not match:
        return None
        
    namespace, name, ready, status, restarts, age, ip, node = match.groups()
    
    # # 处理重启次数，提取纯数字部分
    # if restarts:
    #     print(restarts)
    #     restarts = restarts.split()[0]  # 只取第一个数字部分
        # restarts = f"{restarts.split()[0]}-{restarts.split()[1]}" if restarts.split()[1] else f"{restarts.split()[0]}" 

    # 处理节点名称，只取第一个有效部分
    if node:
        node = node.split()[0]
        if node == '<none>':
            node = ''
            
    return {
        'namespace': namespace or '',
        'name': name.strip(),
        'ready': ready,
        'status': status,
        'restarts': restarts,
        'age': age,
        'ip': ip or '',
        'node': node
    }

def print_table(headers, rows):
    """打印表格，带边框和分隔线，使用不同颜色区分状态"""
    # 计算每列的最大宽度
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    
    # 增加一些填充
    widths = [w + 2 for w in widths]
    
    # 表格总宽度
    total_width = sum(widths) + len(headers) + 1
    
    # 水平分隔线
    separator = "+" + "+".join("-" * w for w in widths) + "+"
    
    # 打印表头
    print(separator)
    header_cells = [h.center(widths[i]) for i, h in enumerate(headers)]
    print(f"|{Colors.BOLD}{'|'.join(header_cells)}{Colors.ENDC}|")
    print(separator)
    
    # 打印数据行
    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            cell_str = str(cell)
            if headers[i] == "READY":
                # Ready 状态颜色处理
                if '/' in cell_str:
                    current, total = map(int, cell_str.split('/'))
                    if current == total:
                        cell_str = f"{Colors.GREEN}{cell_str.center(widths[i])}{Colors.ENDC}"
                    elif current == 0:
                        cell_str = f"{Colors.FAIL}{cell_str.center(widths[i])}{Colors.ENDC}"
                    else:
                        cell_str = f"{Colors.WARNING}{cell_str.center(widths[i])}{Colors.ENDC}"
                else:
                    cell_str = cell_str.center(widths[i])
            # 根据列的类型使用不同的颜色
            if i == 0:  # 序号：蓝色，居中对齐
                cells.append(f"{Colors.BLUE}{cell_str.center(widths[i])}{Colors.ENDC}")
            elif i == 1:  # NAMESPACE：绿色，左对齐
                cells.append(f"{Colors.GREEN}{cell_str.center(widths[i])}{Colors.ENDC}")
            elif i == 2:  # NAME：绿色，左对齐
                cells.append(f"{Colors.GREEN}{cell_str.center(widths[i])}{Colors.ENDC}")
            elif i == 4:  # STATUS：根据状态使用不同颜色
                color = Colors.GREEN if cell_str == "Running" else Colors.WARNING
                cells.append(f"{color}{cell_str.center(widths[i])}{Colors.ENDC}")
            elif i == 5:  # RESTARTS：根据重启次数使用不同颜色
                try:
                    restarts = int(cell_str)
                    color = Colors.GREEN if restarts == 0 else Colors.WARNING if restarts < 5 else Colors.FAIL
                except ValueError:
                    color = Colors.WARNING
                cells.append(f"{color}{cell_str.center(widths[i])}{Colors.ENDC}")
            elif i == 7:  # IP：蓝色，居中对齐
                cells.append(f"{Colors.BLUE}{cell_str.center(widths[i])}{Colors.ENDC}")
            elif i == 8:  # NODE：紫色，居中对齐
                cells.append(f"{Colors.HEADER}{cell_str.center(widths[i])}{Colors.ENDC}")
            else:  # 其他列：默认颜色，居中对齐
                cells.append(cell_str.center(widths[i]))
        
        print(f"|{'|'.join(cells)}|")
        print(separator)

def get_pod_name(pod_pattern, namespace):
    """根据 pod 名称模式获取完整的 pod 名称"""
    try:
        # 构建命令
        if namespace:
            cmd = f"kubectl get pods -n {namespace} -o wide"
            print(f"{Colors.HEADER}在命名空间 {namespace} 中搜索 Pod: {pod_pattern}{Colors.ENDC}")
        else:
            cmd = "kubectl get pods -A -o wide"
            if pod_pattern:
                print(f"{Colors.HEADER}在所有命名空间中搜索 Pod: {pod_pattern}{Colors.ENDC}")
            else:
                print(f"{Colors.HEADER}获取所有命名空间的 Pods:{Colors.ENDC}")

        # 执行命令获取输出
        output = subprocess.check_output(cmd, shell=True).decode('utf-8').splitlines()
        
        if len(output) < 2:
            print(f"{Colors.FAIL}错误: 未找到任何 Pod{Colors.ENDC}")
            sys.exit(1)

        # 解析表头和数据
        headers = output[0].split()
        data_lines = output[1:]

        # 过滤匹配的行
        if pod_pattern:
            pattern = pod_pattern.lower()
            data_lines = [line for line in data_lines if pattern in line.lower()]

        if not data_lines:
            print(f"{Colors.FAIL}错误: 未找到匹配的 Pod{Colors.ENDC}")
            sys.exit(1)

        # 解析每行数据
        pods = []
        for line in data_lines:
            if not line.strip():
                continue
                
            parsed = parse_kubectl_output(line)
            if not parsed:
                continue
                
            pod_data = {
                'NAMESPACE': namespace if namespace else parsed['namespace'],
                'NAME': parsed['name'],
                'READY': parsed['ready'],
                'STATUS': parsed['status'],
                'RESTARTS': parsed['restarts'],
                'AGE': parsed['age'],
                'IP': parsed['ip'],
                'NODE': parsed['node']
            }
            pods.append(pod_data)

        # 准备表格数据
        table_headers = ["序号", "NAMESPACE", "NAME", "READY", "STATUS", "RESTARTS", "AGE", "IP", "NODE"]
        rows = []
        
        for i, pod in enumerate(pods, 1):
            rows.append([
                str(i),
                pod['NAMESPACE'],
                pod['NAME'],
                pod['READY'],
                pod['STATUS'],
                pod['RESTARTS'],
                pod['AGE'],
                pod['IP'],
                pod['NODE']
            ])

        # 打印表格
        print("\n")
        print_table(table_headers, rows)

        if len(pods) > 1:
            choice = input(f"\n{Colors.GREEN}请选择 Pod 序号: {Colors.ENDC}")
            try:
                selected_pod = pods[int(choice)-1]
                return selected_pod['NAME'], selected_pod['NAMESPACE']
            except (ValueError, IndexError):
                print(f"{Colors.FAIL}无效的选择{Colors.ENDC}")
                sys.exit(1)
        else:
            return pods[0]['NAME'], pods[0]['NAMESPACE']

    except subprocess.CalledProcessError as e:
        print(f"{Colors.FAIL}错误: 执行命令失败: {e}{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.FAIL}错误: {str(e)}{Colors.ENDC}")
        sys.exit(1)

def get_container_name(pod_name, namespace):
    """获取 Pod 中的容器名称"""
    try:
        cmd = f"kubectl get pod {pod_name} -n {namespace} -o jsonpath='{{.spec.containers[*].name}}'"
        containers = subprocess.check_output(cmd, shell=True).decode('utf-8').split()
        
        if len(containers) == 0:
            print(f"{Colors.FAIL}错误: Pod {pod_name} 中没有找到容器{Colors.ENDC}")
            sys.exit(1)
        elif len(containers) > 1:
            print(f"\n{Colors.HEADER}在 Pod {pod_name} 中找到多个容器:{Colors.ENDC}")
            for i, container in enumerate(containers, 1):
                print(f"{Colors.BLUE}{i}. {container}{Colors.ENDC}")
            choice = input(f"{Colors.GREEN}请选择容器序号: {Colors.ENDC}")
            try:
                container_name = containers[int(choice)-1]
            except (ValueError, IndexError):
                print(f"{Colors.FAIL}无效的选择{Colors.ENDC}")
                sys.exit(1)
        else:
            container_name = containers[0]
        
        return container_name
    except subprocess.CalledProcessError as e:
        print(f"{Colors.FAIL}错误: 获取容器信息失败: {e}{Colors.ENDC}")
        sys.exit(1)

def login_pod(pod_name, namespace, container_name):
    """登录到指定的 Pod 容器"""
    try:
        # 首先尝试获取容器的入口点和工作目录
        cmd_template = "kubectl get pod {pod} -n {ns} -o jsonpath='{{.spec.containers[?(@.name==\"{container}\")].{field}}}'"
        
        # 获取容器的入口点
        cmd = cmd_template.format(pod=pod_name, ns=namespace, container=container_name, field="command")
        entrypoint = subprocess.check_output(cmd, shell=True).decode('utf-8').strip('[]"\n ')
        
        # 获取容器的工作目录
        cmd = cmd_template.format(pod=pod_name, ns=namespace, container=container_name, field="workingDir")
        workdir = subprocess.check_output(cmd, shell=True).decode('utf-8').strip('[]"\n ')
        
        print(f"{Colors.WARNING}容器信息:{Colors.ENDC}")
        print(f"{Colors.WARNING}• 入口点: {entrypoint}{Colors.ENDC}")
        if workdir:
            print(f"{Colors.WARNING}• 工作目录: {workdir}{Colors.ENDC}")
        
        # 尝试找到可用的 shell
        shell_paths = [
            "/bin/bash",
            "/bin/sh",
            "/usr/bin/bash",
            "/usr/bin/sh",
            "/busybox/sh",
            "/usr/local/bin/sh",
            "/usr/local/bin/bash"
        ]
        
        # 构建检查 shell 的命令
        check_shells_cmd = " || ".join([f"test -x {shell}" for shell in shell_paths])
        shell_cmd = f"{{ {check_shells_cmd}; }} && echo 'shell_exists' || echo 'no_shell'"
        
        # 检查容器中是否有可用的 shell
        cmd = f"kubectl exec {pod_name} -n {namespace}"
        if container_name:
            cmd += f" -c {container_name}"
        cmd += f" -- sh -c '{shell_cmd}' 2>/dev/null"
        
        try:
            shell_check = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
            has_shell = shell_check == 'shell_exists'
        except subprocess.CalledProcessError:
            has_shell = False
        
        if not has_shell:
            print(f"{Colors.WARNING}警: ��是一个精简容器，未找到标准的 shell{Colors.ENDC}")
            print(f"{Colors.WARNING}尝试使用基本命令执行方式...{Colors.ENDC}")
            
            # 对于没有 shell 的容器，直接使用 kubectl exec
            kubectl_args = ['kubectl', 'exec', '-it', pod_name, '-n', namespace]
            if container_name:
                kubectl_args.extend(['-c', container_name])
            kubectl_args.extend(['--'])
            
            # 如果入口点包含 shell 路径，使用它
            if any(shell in entrypoint for shell in ['/bin/sh', '/bin/bash']):
                shell_path = next(shell for shell in ['/bin/sh', '/bin/bash'] if shell in entrypoint)
                kubectl_args.append(shell_path)
            elif entrypoint:
                # 如果有入口点但不是 shell，使用入口点命令
                kubectl_args.extend(entrypoint.split(',')[0].strip('"').split())
            else:
                # 如果没有口点，尝试常见的命令
                common_commands = [
                    '/bin/sh',
                    '/bin/bash',
                    '/busybox/sh',
                    'sh',
                    'bash'
                ]
                print(f"{Colors.WARNING}容器没有指定入口点，尝试常见命令...{Colors.ENDC}")
                
                # 尝试在容器中执行 'true' 命令来测试每个可能的 shell
                for cmd in common_commands:
                    test_cmd = f"kubectl exec {pod_name} -n {namespace}"
                    if container_name:
                        test_cmd += f" -c {container_name}"
                    test_cmd += f" -- {cmd} -c 'true' 2>/dev/null"
                    
                    try:
                        subprocess.check_call(test_cmd, shell=True)
                        print(f"{Colors.GREEN}找到可用命令: {cmd}{Colors.ENDC}")
                        kubectl_args.append(cmd)
                        break
                    except subprocess.CalledProcessError:
                        continue
                
                if len(kubectl_args) == 0 or kubectl_args[-1] == '--':
                    print(f"{Colors.FAIL}错误: 无法找到可用的命令来访问容器{Colors.ENDC}")
                    print(f"{Colors.WARNING}提示: 这个容器可能是一个特殊的系统容器或精简容器{Colors.ENDC}")
                    print(f"{Colors.WARNING}您可以尝试以下方法：{Colors.ENDC}")
                    print(f"{Colors.GREEN}1. 检查容器的 Dockerfile 或配置，确认入口点或可用的 shell{Colors.ENDC}")
                    print(f"{Colors.GREEN}2. 使用 kubectl logs 查看容器日志{Colors.ENDC}")
                    print(f"{Colors.GREEN}3. 使用 kubectl describe 查看容器详细信息{Colors.ENDC}")
                    sys.exit(1)
            
            os.execvp('kubectl', kubectl_args)
            return
        
        # 构建 bash 配置
        bash_prompt = r'\[\e[32m\]\u@{pod}\[\e[0m\]:\[\e[34m\]\w\[\e[0m\]\$ '.format(pod=pod_name)
        welcome_msg = [
            r'echo -e "\e[33m欢迎登录容器！\e[0m"',
            r'echo -e "\e[36m容器信息:\e[0m"',
            r'echo -e "  \e[32m• Pod:\e[0m      {pod}"'.format(pod=pod_name),
            r'echo -e "  \e[32m• 命名空间:\e[0m  {ns}"'.format(ns=namespace),
            r'echo -e "  \e[32m• 容器名:\e[0m    {container}"'.format(container=container_name),
            r'echo -e "\e[35m----------------------------------------\e[0m"'
        ]
        
        bash_config = [
            f"PS1='{bash_prompt}'",
            "export TERM=xterm-256color",
            "export LANG=en_US.UTF-8",
            "export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "alias ll='ls -la'",
            "alias l='ls -l'"
        ] + welcome_msg
        
        # 将配置转换为单行，并理引号
        bash_config_str = ';'.join(bash_config).replace("'", "'\\''")
        
        # 构建 kubectl 命令参数列表
        kubectl_args = ['kubectl', 'exec', '-it', pod_name, '-n', namespace]
        if container_name:
            kubectl_args.extend(['-c', container_name])
        
        # 构建简单的 shell 命令
        shell_cmd = f"sh -c 'if command -v bash >/dev/null 2>&1; then {bash_config_str}; exec bash; else exec sh; fi'"
        
        kubectl_args.extend(['--', 'sh', '-c', shell_cmd])
        
        # 使用 os.execvp 执行命令
        os.execvp('kubectl', kubectl_args)
        
    except Exception as e:
        print(f"{Colors.FAIL}错误: 登录 Pod 失败: {e}{Colors.ENDC}")
        sys.exit(1)

def check_kubectl():
    """检查kubectl是否可用"""
    try:
        subprocess.check_output("which kubectl", shell=True)
        # 检查kubectl是否可以正常连接集群
        subprocess.check_output("kubectl get nodes", shell=True)
        return True
    except subprocess.CalledProcessError:
        print(f"{Colors.FAIL}错误: kubectl 未安装或无法访问集群{Colors.ENDC}")
        print(f"{Colors.WARNING}请确保：{Colors.ENDC}")
        print(f"{Colors.GREEN}1. 已安装 kubectl 命令行工具{Colors.ENDC}")
        print(f"{Colors.GREEN}2. kubectl 已添加到系统 PATH 中{Colors.ENDC}")
        print(f"{Colors.GREEN}3. kubernetes 集群配置正确（~/.kube/config）{Colors.ENDC}")
        return False

def show_operation_menu(pod_name, namespace, container_name):
    """显示运维操作菜单"""
    while True:
        print(f"\n{Colors.HEADER}运维操作菜单:{Colors.ENDC}")
        print(f"{Colors.BLUE}1. 重启容器{Colors.ENDC}")
        print(f"{Colors.BLUE}2. 返回上级菜单{Colors.ENDC}")
        
        choice = input(f"\n{Colors.GREEN}请选择操作 (1-2): {Colors.ENDC}")
        if choice == '1':
            # 执行容器重启
            confirm = input(f"{Colors.WARNING}确认要重启容器 {container_name} 吗？(y/n): {Colors.ENDC}")
            if confirm.lower() == 'y':
                print(f"\n{Colors.BLUE}开始重启容器...{Colors.ENDC}")
                
                # 使用多个命令分别执行，避免复杂的shell脚本
                try:
                    # 1. 获取子进程列表
                    cmd = f"kubectl exec {pod_name} -n {namespace} -c {container_name} -- ps -eo pid,ppid | awk '$2==1 && $1!=1 {{print $1}}'"
                    child_pids = subprocess.check_output(cmd, shell=True).decode().strip().split()
                    
                    # 2. 逐个终止子进程
                    for pid in child_pids:
                        print(f"{Colors.BLUE}终止子进程: {pid}{Colors.ENDC}")
                        cmd = f"kubectl exec {pod_name} -n {namespace} -c {container_name} -- kill -15 {pid}"
                        subprocess.call(cmd, shell=True)
                    
                    # 3. 等待子进程终止
                    print(f"{Colors.BLUE}等待子进程终止...{Colors.ENDC}")
                    subprocess.call(f"sleep 2", shell=True)
                    
                    # 4. 终止1号进程
                    print(f"{Colors.BLUE}终止1号进程...{Colors.ENDC}")
                    cmd = f"kubectl exec {pod_name} -n {namespace} -c {container_name} -- kill -15 1"
                    subprocess.call(cmd, shell=True)
                    
                    print(f"{Colors.GREEN}容器重启命令已执行{Colors.ENDC}")
                except Exception as e:
                    print(f"{Colors.FAIL}容器重启命令执行失败: {e}{Colors.ENDC}")
                    print(f"{Colors.FAIL}请检查容器状态{Colors.ENDC}")
                continue  # 继续显示运维菜单
        elif choice == '2':
            return  # 返回上级菜单
        else:
            print(f"{Colors.FAIL}无效的选择，请重试{Colors.ENDC}")

def show_main_menu(pod_name, namespace, container_name):
    """显示主菜单"""
    while True:
        print(f"\n{Colors.HEADER}请选择操作类型:{Colors.ENDC}")
        print(f"{Colors.BLUE}1. 进入容器{Colors.ENDC}")
        print(f"{Colors.BLUE}2. 运维操作{Colors.ENDC}")
        print(f"{Colors.BLUE}3. 退出{Colors.ENDC}")
        
        choice = input(f"\n{Colors.GREEN}请选择操作 (1-3): {Colors.ENDC}")
        if choice == '1':
            # 进入容器
            login_pod(pod_name, namespace, container_name)
            break
        elif choice == '2':
            # 运维操作
            show_operation_menu(pod_name, namespace, container_name)
            continue  # 返回主菜单
        elif choice == '3':
            print(f"\n{Colors.GREEN}退出程序{Colors.ENDC}")
            sys.exit(0)
        else:
            print(f"{Colors.FAIL}无效的选择，请重试{Colors.ENDC}")

def main():
    """主函数"""
    # 首先检查kubectl
    if not check_kubectl():
        sys.exit(1)
        
    args = setup_arguments()
    
    # 获取完整的 Pod 名称和命名空间
    full_pod_name, namespace = get_pod_name(args.pod_name, args.namespace)
    print(f"\n{Colors.BOLD}选择的 Pod: {Colors.GREEN}{full_pod_name}{Colors.ENDC}")
    print(f"{Colors.BOLD}命名空间: {Colors.GREEN}{namespace}{Colors.ENDC}")
    
    # 获取容器名称
    container_name = get_container_name(full_pod_name, namespace)
    print(f"{Colors.BOLD}选择的容器: {Colors.GREEN}{container_name}{Colors.ENDC}\n")
    
    # 显示主菜单
    show_main_menu(full_pod_name, namespace, container_name)

if __name__ == "__main__":
    main()