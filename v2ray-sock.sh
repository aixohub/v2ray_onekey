#!/usr/bin/env bash

#====================================================
#	System Request:Debian 9+/Ubuntu 18.04+/Centos 7+
#	Author:	aixohub
#	Dscription: shadowsocks Management
#	email: shadowsocks@aixohub.com
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
shell_version="1.3.11"
github_repo="https://raw.githubusercontent.com/aixohub/v2ray_onekey"
github_branch="main"
shadowsocks_conf_dir="/usr/local/etc/shadowsocks"
website_dir="/www/v2ray_web/"
shadowsocks_access_log="/var/log/shadowsocks/access.log"
shadowsocks_error_log="/var/log/shadowsocks/error.log"
cert_dir="/usr/local/etc/shadowsocks"
domain_tmp_dir="/usr/local/etc/shadowsocks"
cert_group="nobody"
random_num=$((RANDOM % 12 + 4))

VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')
WS_PATH="/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
WS_PATH_WITHOUT_SLASH=$(echo $WS_PATH | tr -d '/')


function print_ok() {
  echo -e "${OK} ${Blue} $1 ${Font}"
}

function print_error() {
  echo -e "${ERROR} ${RedBG} $1 ${Font}"
}

function is_root() {
  if [[ 0 == "$UID" ]]; then
    print_ok "当前用户是 root 用户，开始安装流程"
  else
    print_error "当前用户不是 root 用户，请切换到 root 用户后重新执行脚本"
    exit 1
  fi
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
    ${INS} wget
    wget -N -P /etc/yum.repos.d/ ${github_repo}/${github_branch}/basic/nginx.repo


  elif [[ "${ID}" == "ol" ]]; then
    print_ok "当前系统为 Oracle Linux ${VERSION_ID} ${VERSION}"
    INS="yum install -y"
    wget -N -P /etc/yum.repos.d/ ${github_repo}/${github_branch}/basic/nginx.repo
  elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 9 ]]; then
    print_ok "当前系统为 Debian ${VERSION_ID} ${VERSION}"
    INS="apt install -y"
    # 清除可能的遗留问题
    rm -f /etc/apt/sources.list.d/nginx.list
    # nginx 安装预处理
    $INS curl gnupg2 ca-certificates lsb-release debian-archive-keyring
    curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor \
    | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
    http://nginx.org/packages/debian `lsb_release -cs` nginx" \
    | tee /etc/apt/sources.list.d/nginx.list
    echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" \
    | tee /etc/apt/preferences.d/99nginx

    apt update

  elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 18 ]]; then
    print_ok "当前系统为 Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME}"
    INS="apt install -y"
    # 清除可能的遗留问题
    rm -f /etc/apt/sources.list.d/nginx.list
    # nginx 安装预处理
    $INS curl gnupg2 ca-certificates lsb-release ubuntu-keyring
    curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor \
    | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
    http://nginx.org/packages/ubuntu `lsb_release -cs` nginx" \
    | tee /etc/apt/sources.list.d/nginx.list
    echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" \
    | tee /etc/apt/preferences.d/99nginx

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

function nginx_install() {
  if ! command -v nginx >/dev/null 2>&1; then
    ${INS} nginx
    judge "Nginx 安装"
  else
    print_ok "Nginx 已存在"
  fi
  # 遗留问题处理
  mkdir -p /etc/nginx/conf.d >/dev/null 2>&1
}
function dependency_install() {
  if ! command -v lsof; then
    ${INS} lsof tar
    judge "安装 lsof tar"
  fi

  if ! command -v unzip; then
    ${INS} unzip
    judge "安装 unzip"
  fi

  if ! command -v curl; then
    ${INS} curl
    judge "安装 curl"
  fi

  # upgrade systemd
  if ! command -v systemd; then
    ${INS} systemd
    judge "安装/升级 systemd"
  fi

  # Nginx 后置 无需编译 不再需要
  #  if [[ "${ID}" == "centos" ||  "${ID}" == "ol" ]]; then
  #    yum -y groupinstall "Development tools"
  #  else
  #    ${INS} build-essential
  #  fi
  #  judge "编译工具包 安装"

  if [[ "${ID}" == "centos" ]]; then
    ${INS} pcre pcre-devel zlib-devel epel-release openssl openssl-devel
  elif [[ "${ID}" == "ol" ]]; then
    ${INS} pcre pcre-devel zlib-devel openssl openssl-devel
    # Oracle Linux 不同日期版本的 VERSION_ID 比较乱 直接暴力处理。如出现问题或有更好的方案，请提交 Issue。
    yum-config-manager --enable ol7_developer_EPEL >/dev/null 2>&1
    yum-config-manager --enable ol8_developer_EPEL >/dev/null 2>&1
  else
    ${INS} libpcre3 libpcre3-dev zlib1g-dev openssl libssl-dev
  fi

  ${INS} jq

  if ! command -v jq; then
    wget -P /usr/bin ${github_repo}/${github_branch}/binary/jq && chmod +x /usr/bin/jq
    judge "安装 jq"
  fi

  # 防止部分系统v2ray的默认bin目录缺失
  mkdir /usr/local/bin >/dev/null 2>&1
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

function domain_check() {
  read -rp "请输入你的域名信息(eg: www.aixohub.com):" domain
  domain_ip=$(curl -sm8 ipget.net/?ip="${domain}")
  print_ok "正在获取 IP 地址信息，请耐心等待"
  wgcfv4_status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
  wgcfv6_status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
  if [[ ${wgcfv4_status} =~ "on"|"plus" ]] || [[ ${wgcfv6_status} =~ "on"|"plus" ]]; then
    # 关闭wgcf-warp，以防误判VPS IP情况
    wg-quick down wgcf >/dev/null 2>&1
    print_ok "已关闭 wgcf-warp"
  fi
  local_ipv4=$(curl -s4m8 https://checkip.amazonaws.com)
  local_ipv6=$(curl -s6m8 https://checkip.amazonaws.com)
  if [[ -z ${local_ipv4} && -n ${local_ipv6} ]]; then
    # 纯IPv6 VPS，自动添加DNS64服务器以备acme.sh申请证书使用
    echo -e nameserver 2a01:4f8:c2c:123f::1 > /etc/resolv.conf
    print_ok "识别为 IPv6 Only 的 VPS，自动添加 DNS64 服务器"
  fi
  echo -e "域名通过 DNS 解析的 IP 地址: ${domain_ip}"
  echo -e "本机公网 IPv4 地址:  ${local_ipv4}"
  echo -e "本机公网 IPv6 地址:  ${local_ipv6}"
  sleep 2
  if [[ ${domain_ip} == "${local_ipv4}" ]]; then
    print_ok "域名通过 DNS 解析的 IP 地址与 本机 IPv4 地址匹配"
    sleep 2
  elif [[ ${domain_ip} == "${local_ipv6}" ]]; then
    print_ok "域名通过 DNS 解析的 IP 地址与 本机 IPv6 地址匹配"
    sleep 2
  else
    print_error "请确保域名添加了正确的 A / AAAA 记录，否则将无法正常使用 v2ray"
    print_error "域名通过 DNS 解析的 IP 地址与 本机 IPv4 / IPv6 地址不匹配，是否继续安装？(y/n)" && read -r install
    case $install in
    [yY][eE][sS] | [yY])
      print_ok "继续安装"
      sleep 2
      ;;
    *)
      print_error "安装终止"
      exit 2
      ;;
    esac
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
  ol_version=$(curl -L -s ${github_repo}/${github_branch}/v2ray-sock.sh | grep "shell_version=" | head -1 | awk -F '=|"' '{print $3}')
  if [[ "$shell_version" != "$(echo -e "$shell_version\n$ol_version" | sort -rV | head -1)" ]]; then
    print_ok "存在新版本，是否更新 [Y/N]?"
    read -r update_confirm
    case $update_confirm in
    [yY][eE][sS] | [yY])
      wget -N --no-check-certificate ${github_repo}/${github_branch}/v2ray-sock.sh
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

function v2ray_tmp_config_file_check_and_use() {
  if [[ -s ${shadowsocks_conf_dir}/config_tmp.json ]]; then
    mv -f ${shadowsocks_conf_dir}/config_tmp.json ${shadowsocks_conf_dir}/config.json
  else
    print_error "v2ray 配置文件修改异常"
  fi
}




function configure_nginx() {
  nginx_conf="/etc/nginx/conf.d/${domain}.conf"
  cd /etc/nginx/conf.d/ && rm -f ${domain}.conf 
echo "
server {
  listen 80;
  listen [::]:80;
  server_name  ${domain};
  return 301 https://\$http_host\$request_uri;
  access_log  /dev/null;
  error_log  /dev/null;

}" > ${domain}.conf

  sed -i "s/xxx/${domain}/g" ${nginx_conf}
  judge "Nginx 配置 修改"
  
  systemctl enable nginx
  systemctl restart nginx
}



function configure_nginx_ws() {
  nginx_conf="/etc/nginx/conf.d/${domain}.conf"
  cd /etc/nginx/conf.d/ && rm -f ${domain}.conf 
  
  echo "

map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ''      close;
}

upstream websocket {
    server localhost:${PORT};
}

server {
  listen 80;
  listen [::]:80;
  server_name  ${domain};
  return 301 https://\$http_host\$request_uri;
  access_log  /dev/null;
  error_log  /dev/null;
}

 server {
  listen 443 ssl;
  server_name          ${domain};
  
  ssl_certificate       /ssl/v2ray.crt;
  ssl_certificate_key   /ssl/v2ray.key;
  ssl_session_timeout 1d;
  ssl_session_cache shared:MozSSL:10m;
  ssl_session_tickets off;
  
  ssl_protocols         TLSv1.2 TLSv1.3;
  ssl_ciphers           ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
  ssl_prefer_server_ciphers off;
  

  location / {
        root   html;
        index  index.html index.htm;
  }

  # 与 V2Ray 配置中的 path 保持一致
  location  ${WS_PATH} { 
    if (\$http_upgrade != \"websocket\") { # WebSocket协商失败时返回404
        return 404;
    }
    proxy_redirect off;
    proxy_pass https://websocket${WS_PATH}; 

    proxy_ssl_certificate     /ssl/v2ray.crt;
    proxy_ssl_certificate_key /ssl/v2ray.key;

    proxy_http_version 1.1;
    proxy_read_timeout 300s;
    proxy_connect_timeout 75s;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \"upgrade\";
    proxy_set_header Host \$host;
    # Show real IP in v2ray access.log
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  }
}" > ${domain}.conf

  sed -i "s/xxx/${domain}/g" ${nginx_conf}
  judge "Nginx ws 配置 修改"
  
  systemctl enable nginx
  systemctl restart nginx
}





function v2ray_install() {
  print_ok "安装 v2ray"
  bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
  judge "v2ray 安装"

  if [[ -f ${domain_tmp_dir} ]]; then
    print_ok "${domain_tmp_dir} 已存在"
  else
    mkdir -p ${domain_tmp_dir}
  fi
  # 用于生成 V2ray 的导入链接
  echo $domain >$domain_tmp_dir/domain
  judge "域名记录"
}

function ssl_install() {
  curl -L https://get.acme.sh | bash
  judge "安装 SSL 证书生成脚本"
}


function acme() {
  "$HOME"/.acme.sh/acme.sh --set-default-ca --server letsencrypt
  sed -i "6s/^/#/" "$nginx_conf"
  sed -i "6a\\\troot $website_dir;" "$nginx_conf"
  systemctl restart nginx

  if "$HOME"/.acme.sh/acme.sh --issue --insecure -d "${domain}" --webroot "$website_dir" -k ec-256 --force; then
    print_ok "SSL 证书生成成功"
    sleep 2
    if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /ssl/v2ray.crt --keypath /ssl/v2ray.key --reloadcmd "systemctl restart v2ray" --ecc --force; then
      print_ok "SSL 证书配置成功"
      sleep 2
      if [[ -n $(type -P wgcf) && -n $(type -P wg-quick) ]]; then
        wg-quick up wgcf >/dev/null 2>&1
        print_ok "已启动 wgcf-warp"
      fi
    fi
  elif "$HOME"/.acme.sh/acme.sh --issue --insecure -d "${domain}" --webroot "$website_dir" -k ec-256 --force --listen-v6; then
    print_ok "SSL 证书生成成功"
    sleep 2
    if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /ssl/v2ray.crt --keypath /ssl/v2ray.key --reloadcmd "systemctl restart v2ray" --ecc --force; then
      print_ok "SSL 证书配置成功"
      sleep 2
      if [[ -n $(type -P wgcf) && -n $(type -P wg-quick) ]]; then
        wg-quick up wgcf >/dev/null 2>&1
        print_ok "已启动 wgcf-warp"
      fi
    fi
  else
    print_error "SSL 证书生成失败"
    rm -rf "$HOME/.acme.sh/${domain}_ecc"
    if [[ -n $(type -P wgcf) && -n $(type -P wg-quick) ]]; then
      wg-quick up wgcf >/dev/null 2>&1
      print_ok "已启动 wgcf-warp"
    fi
    exit 1
  fi

  sed -i "7d" "$nginx_conf"
  sed -i "6s/#//" "$nginx_conf"
}


function ssl_judge_and_install() {
  mkdir -p /ssl >/dev/null 2>&1
  if [[ -f "/ssl/v2ray.key" || -f "/ssl/v2ray.crt" ]]; then
    print_ok "/ssl 目录下证书文件已存在"
    print_ok "是否删除 /ssl 目录下的证书文件 [Y/N]?"
    read -r ssl_delete
    case $ssl_delete in
    [yY][eE][sS] | [yY])
      rm -rf /ssl/*
      print_ok "已删除"
      ;;
    *) ;;

    esac
  fi

  if [[ -f "/ssl/v2ray.key" || -f "/ssl/v2ray.crt" ]]; then
    echo "证书文件已存在"
  elif [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
    echo "证书文件已存在"
    "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /ssl/v2ray.crt --keypath /ssl/v2ray.key --ecc
    judge "证书启用"
  else
    mkdir /ssl
    cp -a $cert_dir/self_signed_cert.pem /ssl/v2ray.crt
    cp -a $cert_dir/self_signed_key.pem /ssl/v2ray.key
    ssl_install
    acme
  fi

  # V2ray 默认以 nobody 用户运行，证书权限适配
  chown -R nobody.$cert_group /ssl/*
}

function generate_certificate() {
    if [[ -f ${cert_dir} ]]; then
      print_ok "${cert_dir} 已存在"
    else
      mkdir -p ${cert_dir}
    fi
  if [[ -z ${local_ipv4} && -n ${local_ipv6} ]]; then
    signedcert=$(v2ray tls cert -domain="$local_ipv6" -name="$local_ipv6" -org="$local_ipv6" -expire=87600)
  else
    signedcert=$(v2ray tls cert -domain="$local_ipv4" -name="$local_ipv4" -org="$local_ipv4" -expire=87600)
  fi
  echo $signedcert | jq '.certificate[]' | sed 's/\"//g' | tee $cert_dir/self_signed_cert.pem
  echo $signedcert | jq '.key[]' | sed 's/\"//g' >$cert_dir/self_signed_key.pem
  openssl x509 -in $cert_dir/self_signed_cert.pem -noout || (print_error "生成自签名证书失败" && exit 1)
  print_ok "生成自签名证书成功"
  chown nobody.$cert_group $cert_dir/self_signed_cert.pem
  chown nobody.$cert_group $cert_dir/self_signed_key.pem
}

function configure_web() {
  rm -rf /www/v2ray_web
  mkdir -p /www/v2ray_web
  print_ok "是否配置伪装网页？[Y/N]"
  read -r webpage
  case $webpage in
  [yY][eE][sS] | [yY])
    wget -O web.tar.gz ${github_repo}/main/basic/web.tar.gz
    tar xzf web.tar.gz -C /www/v2ray_web
    judge "站点伪装"
    rm -f web.tar.gz
    ;;
  *) ;;
  esac
}

function v2ray_uninstall() {
  print_ok "是否卸载nginx [Y/N]?"
  read -r uninstall_nginx
  case $uninstall_nginx in
  [yY][eE][sS] | [yY])
    if [[ "${ID}" == "centos" || "${ID}" == "ol" ]]; then
      yum remove nginx -y
    else
      apt purge nginx -y
    fi
    ;;
  *) ;;
  esac
  print_ok "是否卸载acme.sh [Y/N]?"
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

ss_file=0
v2_file=0
get_latest_ver(){
    ss_file=$(wget -qO- https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest | grep name | grep x86_64-unknown-linux-musl.tar.xz | cut -f4 -d\"| head -1)
    v2_file=$(wget -qO- https://api.github.com/repos/shadowsocks/v2ray-plugin/releases/latest | grep linux-amd64 | grep name | cut -f4 -d\")
}


# Installation of shadowsocks-rust
install_ss(){
    if [ -f /usr/local/bin/ssserver ];then
        print_error "Shadowsocks-rust already installed, skip."
    else
        if [ ! -f $ss_file ];then
            ss_url=$(wget -qO- https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest | grep x86_64-unknown-linux-musl.tar.xz | grep browser_download_url | cut -f4 -d\" | head -1)
            wget $ss_url
        fi
        tar xf $ss_file
        mv ss* /usr/local/bin/
        cd ..
        if [ ! -f /usr/local/bin/ssserver ];then
            print_error "Failed to install shadowsocks-rust"
            exit 1
        else
          print_ok "Success install shadowsocks-rust"
        fi
    fi
}

# Installation of v2ray-plugin
install_v2ray_plugin(){
    if [ -f /usr/local/bin/v2ray-plugin ];then
        print_ok "v2ray-plugin already installed, skip."
    else
        if [ ! -f $v2_file ];then
            v2_url=$(wget -qO- https://api.github.com/repos/shadowsocks/v2ray-plugin/releases/latest | grep linux-amd64 | grep browser_download_url | cut -f4 -d\")
            wget $v2_url
        fi
        tar xf $v2_file
        mv v2ray-plugin_linux_amd64 /usr/local/bin/v2ray-plugin
        if [ ! -f /usr/local/bin/v2ray-plugin ];then
            print_error "Failed to install v2ray-plugin"
            exit 1
        else
          print_ok "v2ray-plugin install success"
        fi
    fi
}


function modify_password() {
   [ -z "$UUID" ] && UUID=$(cat /proc/sys/kernel/random/uuid)
  cat ${shadowsocks_conf_dir}/config.json | jq 'setpath(["password"];"'${UUID}'")' >${shadowsocks_conf_dir}/config_tmp.json
  v2ray_tmp_config_file_check_and_use
  judge "password  修改"
}


function modify_port() {
  read -rp "请输入端口号(默认: 443): " PORT
  [ -z "$PORT" ] && PORT="443"
  if [[ $PORT -le 0 ]] || [[ $PORT -gt 65535 ]]; then
    print_error "请输入 0-65535 之间的值"
    exit 1
  fi
  port_exist_check $PORT
  cat ${shadowsocks_conf_dir}/config.json | jq 'setpath(["server_port"];'${PORT}')' >${shadowsocks_conf_dir}/config_tmp.json
  v2ray_tmp_config_file_check_and_use
  judge "shadowsocks 端口 修改"
}

function modify_method() {
  read -rp "请输入 shadowsocks_method: " shadowsocks_method
  cat ${shadowsocks_conf_dir}/config.json | jq 'setpath(["method"];"'${shadowsocks_method}'")' >${shadowsocks_conf_dir}/config_tmp.json
  v2ray_tmp_config_file_check_and_use
  judge "shadowsocks method 修改"
}

function configure_v2ray_ws() {
  cd /usr/local/etc/shadowsocks && rm -f config.json && wget -O config.json ${github_repo}/${github_branch}/config/shadowsocks_conf.json
  modify_password
  modify_port
}

configure_shadowsocks(){
    modify_port
    shadowsocks_pwd="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
    mkdir -p /etc/shadowsocks
    cat >/usr/local/etc/shadowsocks/config.json << EOF
{
    "server":"$local_ipv4",
    "server_port":$PORT,
    "password":"$shadowsocks_pwd",
    "timeout":300,
    "method":"chacha20-ietf-poly1305",
    "plugin":"v2ray-plugin",
    "plugin_opts":"server;host=$domain;loglevel=info"
}
EOF
    cat >/lib/systemd/system/shadowsocks.service << EOF
[Unit]
Description=Shadowsocks-rust Server Service
After=network.target
[Service]
ExecStart=/usr/local/bin/ssserver -c /usr/local/etc/shadowsocks/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
}

function restart_shadowsocks() {
  systemctl restart nginx
  judge "Nginx 启动"
  systemctl restart shadowsocks
  judge "shadowsocks 启动"
}

function restart_all() {
  systemctl restart nginx
  judge "Nginx 启动"
  systemctl restart shadowsocks
  judge "shadowsocks 启动"
}



function ws_information() {
  SERVER=$(cat ${shadowsocks_conf_dir}/config.json | jq .server | tr -d '"')
  SERVER_PORT=$(cat ${shadowsocks_conf_dir}/config.json | jq .server_port)
  NET_WORK=$(cat ${shadowsocks_conf_dir}/config.json | jq .password | tr -d '"')
  SECURITY=$(cat ${shadowsocks_conf_dir}/config.json | jq .method | tr -d '"')
  DOMAIN=$(cat ${domain_tmp_dir}/domain)

  echo -e "${Red} shadowsocks 配置信息 ${Font}"
  echo -e "${Red} 地址(address):${Font}  $SERVER"
  echo -e "${Red} 端口(port): ${Font}  $SERVER_PORT"
  echo -e "${Red} 地址(password):${Font}  $NET_WORK"
  echo -e "${Red} 端口(method): ${Font}  $SECURITY"
}




function basic_ws_information() {
  print_ok "shadowsocks 混合模式 安装成功"
  ws_information
  print_ok "————————————————————————"
}

function basic_ss_information() {
  print_ok "shadowsocks 安装成功"
  cat /etc/shadowsocks-rust/config.json
}

function show_access_log() {
  [ -f ${shadowsocks_access_log} ] && tail -f ${shadowsocks_access_log} || echo -e "${RedBG}log 文件不存在${Font}"
}

function show_error_log() {
  [ -f ${shadowsocks_error_log} ] && tail -f ${shadowsocks_error_log} || echo -e "${RedBG}log 文件不存在${Font}"
}

function bbr_boost_sh() {
  [ -f "tcp.sh" ] && rm -rf ./tcp.sh
  wget -N --no-check-certificate "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
}


function install_ss_v2ray_plugin() {
  is_root
  system_check
  dependency_install
  basic_optimization
  domain_check
  v2ray_install
  port_exist_check 80
  get_latest_ver
  install_ss
  install_v2ray_plugin
  configure_shadowsocks
  nginx_install
  configure_nginx
  configure_web
  generate_certificate
  ssl_judge_and_install
  configure_nginx_ws
  restart_shadowsocks
  basic_ss_information
}


menu() {
  update_sh
  shell_mode_check
  echo -e "\t ss V2ray 安装管理脚本 ${Red}[${shell_version}]${Font}"
  echo -e "\t---authored by aixohub---"
  echo -e "\thttps://github.com/aixohub\n"

  echo -e "当前已安装版本: ${shell_mode}"
  echo -e "—————————————— 安装向导 ——————————————"""
  echo -e "${Green}0.${Font}  升级 脚本"
  echo -e "${Green}1.${Font}  安装 V2ray ws"
  echo -e "—————————————— 配置变更 ——————————————"
  echo -e "${Green}11.${Font} 变更 UUID"
  echo -e "${Green}13.${Font} 变更 连接端口"
  echo -e "${Green}14.${Font} 变更 METHOD"
  echo -e "—————————————— 查看信息 ——————————————"
  echo -e "${Green}21.${Font} 查看 实时访问日志"
  echo -e "${Green}22.${Font} 查看 实时错误日志"
  echo -e "${Green}23.${Font} 查看 V2ray 配置链接"
  #    echo -e "${Green}23.${Font}  查看 V2Ray 配置信息"
  echo -e "—————————————— 其他选项 ——————————————"
  echo -e "${Green}31.${Font} 安装 4 合 1 BBR、锐速安装脚本"
  echo -e "${Green}36.${Font} 手动更新 SSL 证书"
  echo -e "${Green}40.${Font} 退出"
  read -rp "请输入数字: " menu_num
  case $menu_num in
  0)
    update_sh
    ;;
  1)
    install_ss_v2ray_plugin
    ;;
  11)
    read -rp "请输入 UUID:" UUID
    modify_password
    restart_all
    ;;
  13)
    modify_port
    restart_all
    ;;
  14)
    modify_method
    restart_all
    ;;
  21)
    journalctl -u shadowsocks.service
    ;;
  22)
    tail -f $shadowsocks_error_log
    ;;
  23)
    if [[ -f $shadowsocks_conf_dir/config.json ]]; then
      if [[ ${shell_mode} == "tcp" ]]; then
        basic_information
      elif [[ ${shell_mode} == "ws" ]]; then
        basic_ws_information
      fi
    else
      print_error "v2ray 配置文件不存在"
    fi
    ;;
  31)
    bbr_boost_sh
    ;;
  33)
    source '/etc/os-release'
    v2ray_uninstall
    ;;
  36)
    "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh"
    restart_all
    ;;
  40)
    exit 0
    ;;
  *)
    print_error "请输入正确的数字"
    ;;
  esac
}
menu "$@"
