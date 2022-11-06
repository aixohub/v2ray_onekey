#!/usr/bin/env bash

#====================================================
#	System Request:Debian 9+/Ubuntu 18.04+/Centos 7+
#	Author:	aixohub
#	Dscription: WireGuard onekey Management
#	email: admin@wulabing.com
#====================================================

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
stty erase ^?

cd "$(
  cd "$(dirname "$0")" || exit
  pwd
)" || exit

# 字体颜色配置
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
Blue="\033[36m"
Font="\033[0m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
OK="${Green}[OK]${Font}"
ERROR="${Red}[ERROR]${Font}"

# 变量
shell_version="1.3.0"
github_branch="main"
wg_conf_dir="/usr/local/etc/wireguard"
website_dir="/www/wireguard_web/"
wireguard_access_log="/var/log/wireguard/access.log"
wireguard_error_log="/var/log/wireguard/error.log"
cert_dir="/usr/local/etc/wireguard"
domain_tmp_dir="/usr/local/etc/wireguard"
cert_group="nobody"
random_num=$((RANDOM % 12 + 4))

VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')
WS_PATH="/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})/"




function is_root() {
  if [[ 0 == "$UID" ]]; then
    print_ok "当前用户是 root 用户，开始安装流程"
  else
    print_error "当前用户不是 root 用户，请切换到 root 用户后重新执行脚本"
    exit 1
  fi
}

function print_ok() {
  echo -e "${OK} ${Blue} $1 ${Font}"
}

function print_error() {
  echo -e "${ERROR} ${RedBG} $1 ${Font}"
}


judge() {
  if [[ 0 -eq $? ]]; then
    print_ok "$1 完成"
    sleep 1
  else
    print_error "$1 失败"
    exit 1
  fi
}

function system_check() {
  source '/etc/os-release'

  if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
    print_ok "当前系统为 Centos ${VERSION_ID} ${VERSION}"
    INS="yum install -y"

  elif [[ "${ID}" == "ol" ]]; then
    print_ok "当前系统为 Oracle Linux ${VERSION_ID} ${VERSION}"
    INS="yum install -y"

  elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 9 ]]; then
    print_ok "当前系统为 Debian ${VERSION_ID} ${VERSION}"
    INS="apt install -y"
    apt update

  elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 18 ]]; then
    print_ok "当前系统为 Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME}"
    INS="apt install -y"
    apt update
  else
    print_error "当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内"
    exit 1
  fi

  if [[ $(grep "nogroup" /etc/group) ]]; then
    cert_group="nogroup"
  fi

  $INS dbus

  # 关闭各类防火墙
  systemctl stop firewalld
  systemctl disable firewalld
  systemctl stop nftables
  systemctl disable nftables
  systemctl stop ufw
  systemctl disable ufw
}


function dependency_install() {
 
  ${INS} wget
  judge "安装 wget"

  ${INS} unzip
  judge "安装 unzip"

  ${INS} curl
  judge "安装 curl"

  # upgrade systemd
  ${INS} systemd
  judge "安装/升级 systemd"
}

function basic_optimization() {
  # 最大文件打开数
  sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
  sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
  echo '* soft nofile 65536' >>/etc/security/limits.conf
  echo '* hard nofile 65536' >>/etc/security/limits.conf

  # RedHat 系发行版关闭 SELinux
  if [[ "${ID}" == "centos" || "${ID}" == "ol" ]]; then
    sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
    setenforce 0
  fi
}


function port_exist_check() {
  if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
    print_ok "$1 端口未被占用"
    sleep 1
  else
    print_error "检测到 $1 端口被占用，以下为 $1 端口占用信息"
    lsof -i:"$1"
    print_error "5s 后将尝试自动 kill 占用进程"
    sleep 5
    lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
    print_ok "kill 完成"
    sleep 1
  fi
}

function update_sh() {
  ol_version=$(curl -L -s https://raw.githubusercontent.com/aixohub/v2ray_onekey/${github_branch}/wg-install.sh | grep "shell_version=" | head -1 | awk -F '=|"' '{print $3}')
  if [[ "$shell_version" != "$(echo -e "$shell_version\n$ol_version" | sort -rV | head -1)" ]]; then
    print_ok "存在新版本，是否更新 [Y/N]?"
    read -r update_confirm
    case $update_confirm in
    [yY][eE][sS] | [yY])
      wget -N --no-check-certificate https://raw.githubusercontent.com/aixohub/v2ray_onekey/${github_branch}/wg-install.sh
      print_ok "更新完成"
      print_ok "您可以通过 bash $0 执行本程序"
      exit 0
      ;;
    *) ;;
    esac
  else
    print_ok "当前版本为最新版本"
    print_ok "您可以通过 bash $0 执行本程序"
  fi
}

function generate_key() {
  mkdir /etc/wireguard
  cd /etc/wireguard
  wg genkey | tee sprivatekey | wg pubkey > spublickey
  wg genkey | tee cprivatekey | wg pubkey > cpublicke
  print_ok "生成密匙对成功"
}

function generate_server_conf() {
   echo "[Interface]
   # 服务器的私匙，对应客户端配置中的公匙（自动读取上面刚刚生成的密匙内容）
   PrivateKey = $(cat sprivatekey)
   # 本机的内网IP地址，一般默认即可，除非和你服务器或客户端设备本地网段冲突
   Address = 10.0.0.1/24 
   # 运行 WireGuard 时要执行的 iptables 防火墙规则，用于打开NAT转发之类的。
   # 如果你的服务器主网卡名称不是 eth0 ，那么请修改下面防火墙规则中最后的 eth0 为你的主网卡名称。
   PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
   # 停止 WireGuard 时要执行的 iptables 防火墙规则，用于关闭NAT转发之类的。
   # 如果你的服务器主网卡名称不是 eth0 ，那么请修改下面防火墙规则中最后的 eth0 为你的主网卡名称。
   PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
   # 服务端监听端口，可以自行修改
   ListenPort = 443
   # 服务端请求域名解析 DNS
   DNS = 8.8.8.8
   # 保持默认
   MTU = 1420
   # [Peer] 代表客户端配置，每增加一段 [Peer] 就是增加一个客户端账号，具体我稍后会写多用户教程。
   [Peer]
   # 该客户端账号的公匙，对应客户端配置中的私匙（自动读取上面刚刚生成的密匙内容）
   PublicKey = $(cat cpublickey)
   # 该客户端账号的内网IP地址
   AllowedIPs = 10.0.0.2/32"|sed '/^#/d;/^\s*$/d' > wg0.conf
   print_ok "生成密匙对成功"
}

function generate_client_conf() {
   echo "[Interface]
   # 客户端的私匙，对应服务器配置中的客户端公匙（自动读取上面刚刚生成的密匙内容）
   PrivateKey = $(cat cprivatekey)
   # 客户端的内网IP地址
   Address = 10.0.0.2/24
   # 解析域名用的DNS
   DNS = 8.8.8.8
   # 保持默认
   MTU = 1420
   [Peer]
   # 服务器的公匙，对应服务器的私匙（自动读取上面刚刚生成的密匙内容）
   PublicKey = $(cat spublickey)
   # 服务器地址和端口，下面的 X.X.X.X 记得更换为你的服务器公网IP，端口请填写服务端配置时的监听端口
   Endpoint = X.X.X.X:443
   # 因为是客户端，所以这个设置为全部IP段即可
   AllowedIPs = 0.0.0.0/0, ::0/0
   # 保持连接，如果客户端或服务端是 NAT 网络(比如国内大多数家庭宽带没有公网IP，都是NAT)，那么就需要添加这个参数定时链接服务端(单位：秒)，如果你的服务器和你本地都不是 NAT 网络，那么建议不使用该参数（设置为0，或客户端配置文件中删除这行）
   PersistentKeepalive = 25"|sed '/^#/d;/^\s*$/d' > client.conf
 
   print_ok "生成密匙对成功"
}

function wireguard_install() {
  print_ok "安装 wireguard"

  if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
    ${INS} epel-release.noarch elrepo-release.noarch -y
    ${INS} 
  elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 9 ]]; then
     apt install linux-headers-$(uname -r) -y
     echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list
     echo -e 'Package: *\nPin: release a=unstable\nPin-Priority: 150' > /etc/apt/preferences.d/limit-unstable
     apt update
     apt install wireguard resolvconf -y 
  elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 18 ]]; then
     apt update
     apt install wireguard resolvconf -y

  else
    print_error "当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内"
    exit 1
  fi
  judge "wireguard 安装"

}

function configure_wireguard() {
  # 赋予配置文件夹权限
  chmod 777 -R /etc/wireguard
 
  # 打开防火墙转发功能
  echo 1 > /proc/sys/net/ipv4/ip_forward
  echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
  sysctl -p
}

function wireguard_uninstall() {
  print_ok "是否卸载 acme.sh [Y/N]?"
  read -r uninstall_acme
  case $uninstall_acme in
  [yY][eE][sS] | [yY])
    "$HOME"/.acme.sh/acme.sh --uninstall
    rm -rf /root/.acme.sh
    rm -rf /ssl/
    ;;
  *) ;;
  esac
  print_ok "卸载完成"
  exit 0
}

function restart_all() {
  systemctl restart wireguard
  judge "wireguard 启动"
}


function show_access_log() {
  [ -f ${wireguard_access_log} ] && tail -f ${wireguard_access_log} || echo -e "${RedBG}log 文件不存在${Font}"
}

function client_conf_information() {
  echo -e "${Red} wireguard 配置信息 ${Font}"
  echo -e "${Red}  $(cat /etc/wireguard/client.conf)  ${Font}  $DOMAIN"
}

function basic_information() {
  systemctl enable wg-quick@wg0
  print_ok "wireguard 安装成功"
  client_conf_information
}

function install_wireguard() {
  is_root
  system_check
  dependency_install
  basic_optimization
  port_exist_check 80
  wireguard_install
  generate_key
  generate_server_conf
  generate_client_conf
  configure_wireguard

  restart_all
  basic_information
}

menu() {
  echo -e "\t  wireguard ${Red}[${shell_version}]${Font}"
  echo -e "\t---authored by aixohub---"
  echo -e "\thttps://github.com/aixohub\n"

  echo -e "—————————————— 安装向导 ——————————————"""
  echo -e "${Green}0.${Font}  升级 脚本"
  echo -e "${Green}1.${Font}  安装 wireguard "
  echo -e "${Green}1.${Font}  卸载 wireguard "
  echo -e "—————————————— 配置变更 ——————————————"
  echo -e "${Green}11.${Font} 启动 WireGuard"
  echo -e "${Green}12.${Font} 停止 WireGuard"
  echo -e "${Green}13.${Font} 查询 WireGuard"
  echo -e "—————————————— 查看信息 ——————————————"
  echo -e "${Green}21.${Font} 查看 实时访问日志"
  echo -e "${Green}22.${Font} 查看 实时错误日志"
  echo -e "${Green}23.${Font} 查看 WireGuard 客户端配置"
  echo -e "—————————————— 其他选项 ——————————————"
  echo -e "${Green}31.${Font} 退出"
  read -rp "请输入数字：" menu_num
  case $menu_num in
  0)
    update_sh
    ;;
  1)
    install_wireguard
    ;;
  2)
    source '/etc/os-release'
    wireguard_uninstall
    ;;
  11)
    wg-quick up wg0
    ;;
  12)
    wg-quick down wg0
    ;;
  13)
    wg
    ;;
  21)
    tail -f $wireguard_access_log
    ;;
  22)
    tail -f $wireguard_error_log
    ;;
  23)
    cat /etc/wireguard/client.conf
    ;;
  31)
    exit 0
    ;;
  *)
    print_error "请输入正确的数字"
    ;;
  esac
}
menu "$@"
