#!/bin/bash
# Module: Install Node Only (nginx, Xray TLS + static ECH on 443)
#
# Design A on a standalone node: Xray owns 443, terminates TLS for the
# direct domain, falls back to a cleartext nginx on the shared unix socket.
# nginx holds no certificate; the cert tree and the static ECH key mount
# into remnanode. The whole compose and nginx.conf are written in one
# heredoc each — conditional content is resolved by shell variables, never
# patched with sed.

install_node_nginx() {
    load_selfsteal_templates_module

    mkdir -p /opt/remnanode && cd /opt/remnanode

    reading "${LANG[SELFSTEAL]}" SELFSTEAL_DOMAIN

    check_domain "$SELFSTEAL_DOMAIN" true false
    local domain_check_result=$?
    if [ $domain_check_result -eq 2 ]; then
        echo -e "${COLOR_RED}${LANG[ABORT_MESSAGE]}${COLOR_RESET}"
        exit 1
    fi

    while true; do
        reading "${LANG[PANEL_IP_PROMPT]}" PANEL_IP
        if echo "$PANEL_IP" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' >/dev/null && \
           [[ $(echo "$PANEL_IP" | tr '.' '\n' | wc -l) -eq 4 ]] && \
           [[ ! $(echo "$PANEL_IP" | tr '.' '\n' | grep -vE '^[0-9]{1,3}$') ]] && \
           [[ ! $(echo "$PANEL_IP" | tr '.' '\n' | grep -E '^(25[6-9]|2[6-9][0-9]|[3-9][0-9]{2})$') ]]; then
            break
        else
            echo -e "${COLOR_RED}${LANG[IP_ERROR]}${COLOR_RESET}"
        fi
    done

    echo -n "$(question "${LANG[CERT_PROMPT]}")"
    CERTIFICATE=""
    while IFS= read -r line; do
        if [ -z "$line" ]; then
            if [ -n "$CERTIFICATE" ]; then break; fi
        else
            CERTIFICATE="$CERTIFICATE$line\n"
        fi
    done

    echo -e "${COLOR_YELLOW}${LANG[CERT_CONFIRM]}${COLOR_RESET}"
    read_yn confirm || { echo -e "${COLOR_RED}${LANG[ABORT_MESSAGE]}${COLOR_RESET}"; exit 1; }

    SELFSTEAL_BASE_DOMAIN=$(extract_domain "$SELFSTEAL_DOMAIN")
    unique_domains["$SELFSTEAL_BASE_DOMAIN"]=1

    # ECH key: generate once, before the compose is written, so the
    # remnanode volume list can carry (or omit) the mount at heredoc time.
    if ! docker image inspect remnawave/node:latest >/dev/null 2>&1; then
        step_do "${LANG[ECH_IMAGE_PULL]}"
        docker pull remnawave/node:latest >/dev/null 2>&1 || true
    fi

    CP_ECH_KEY_PATH=""
    CP_ECH_PUBLIC_CONFIG=""
    ensure_ech_server_keys "/opt/remnanode" "$SELFSTEAL_DOMAIN" || true

    local ech_mount_line=""
    if [ -n "$CP_ECH_KEY_PATH" ]; then
        ech_mount_line="      - ./ech:/etc/xray/ech:ro"
    fi

    cat > docker-compose.yml <<EOL
x-common: &common
  ulimits:
    nofile:
      soft: 1048576
      hard: 1048576
  restart: always

x-logging: &logging
  logging:
    driver: json-file
    options:
      max-size: 100m
      max-file: 5

services:
  # Cleartext reverse proxy behind Xray. Listens on the shared unix socket
  # with proxy_protocol. No certificate, no SSL directives.
  remnawave-nginx:
    image: nginx:1.30
    container_name: remnawave-nginx
    hostname: remnawave-nginx
    <<: [*common, *logging]
    network_mode: host
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - /dev/shm:/dev/shm:rw
      - /var/www/html:/var/www/html:ro
    command: sh -c 'rm -f /dev/shm/nginx.sock && exec nginx -g "daemon off;"'

  # Xray owns 443 (TLS). Certificates and the static ECH key mount here,
  # never into nginx.
  remnanode:
    image: remnawave/node:latest
    container_name: remnanode
    hostname: remnanode
    <<: [*common, *logging]
    network_mode: host
    cap_add:
      - NET_ADMIN
    environment:
      - NODE_PORT=2222
      - SECRET_KEY=$(echo -e "$CERTIFICATE")
    volumes:
      - /dev/shm:/dev/shm:rw
      - /var/log/remnanode:/var/log/remnanode
      - /etc/letsencrypt:/etc/letsencrypt:ro
$ech_mount_line
EOL

    # Cleartext server block on the socket: no ssl_certificate, no ssl_*
    # tuning. Xray already terminated TLS; the camouflage site lives here.
    cat > /opt/remnanode/nginx.conf <<EOL
server_names_hash_bucket_size 64;

server {
    server_name $SELFSTEAL_DOMAIN;
    listen unix:/dev/shm/nginx.sock proxy_protocol;
    http2 on;

    root /var/www/html;
    index index.html;
    add_header X-Robots-Tag "noindex, nofollow, noarchive, nosnippet, noimageindex" always;
}

server {
    listen unix:/dev/shm/nginx.sock proxy_protocol default_server;
    server_name _;
    add_header X-Robots-Tag "noindex, nofollow, noarchive, nosnippet, noimageindex" always;
    return 444;
}
EOL
}

installation_node() {
    check_node_not_running
    check_port_443_free
    load_certificates_module
    echo -e "${COLOR_YELLOW}${LANG[INSTALLING_NODE]}${COLOR_RESET}"
    sleep 1

    declare -A unique_domains
    install_node_nginx

    declare -A domains_to_check
    domains_to_check["$SELFSTEAL_DOMAIN"]=1

    handle_certificates domains_to_check "$CERT_METHOD" "$LETSENCRYPT_EMAIL" "/opt/remnanode" || return 1

    NODE_CERT_DOMAIN=$(resolve_certificate_domain "$SELFSTEAL_DOMAIN") || return 1

    # Certbot deploy hook restarts remnanode: Xray holds the certs and
    # keeps serving the old inode through its bind mounts until restarted.
    local renew_conf="/etc/letsencrypt/renewal/$NODE_CERT_DOMAIN.conf"
    if [ -f "$renew_conf" ]; then
        sed -i -E 's|^deploy_hook = .*|deploy_hook = /usr/bin/docker restart remnanode 2>/dev/null \|\| true|' "$renew_conf"
    fi

    ufw allow from $PANEL_IP to any port 2222 > /dev/null 2>&1
    ufw reload > /dev/null 2>&1

    echo -e "${COLOR_YELLOW}${LANG[STARTING_NODE]}${COLOR_RESET}"
    sleep 3
    cd /opt/remnanode
    docker compose up -d > /dev/null 2>&1 &

    spinner $! "${LANG[WAITING]}"

    randomhtml || exit 1

    printf "${COLOR_YELLOW}${LANG[NODE_CHECK]}${COLOR_RESET}\n" "$SELFSTEAL_DOMAIN"
    local max_attempts=5
    local attempt=1
    local delay=15

    while [ $attempt -le $max_attempts ]; do
        printf "${COLOR_YELLOW}${LANG[NODE_ATTEMPT]}${COLOR_RESET}\n" "$attempt" "$max_attempts"
        if curl -s --fail --max-time 10 "https://$SELFSTEAL_DOMAIN" | grep -q "html"; then
            step_ok "${LANG[NODE_LAUNCHED]}"
            break
        else
            printf "${COLOR_RED}${LANG[NODE_UNAVAILABLE]}${COLOR_RESET}\n" "$attempt"
            if [ $attempt -eq $max_attempts ]; then
                printf "${COLOR_RED}${LANG[NODE_NOT_CONNECTED]}${COLOR_RESET}\n" "$max_attempts"
                echo -e "${COLOR_YELLOW}${LANG[CHECK_CONFIG]}${COLOR_RESET}"
                exit 1
            fi
            sleep $delay
        fi
        ((attempt++))
    done

    if [ -n "$CP_ECH_PUBLIC_CONFIG" ]; then
        echo -e ""
        echo -e "${COLOR_GREEN}${LANG[ECH_PUBLISH_NOTICE]}${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}${LANG[ECH_PUBLIC_LABEL]}${COLOR_RESET}"
        echo -e "${COLOR_WHITE}${CP_ECH_PUBLIC_CONFIG}${COLOR_RESET}"
        echo -e ""
        echo -e "${COLOR_YELLOW}${LANG[ECH_DNS_LABEL]}${COLOR_RESET}"
        echo -e "${COLOR_WHITE}  _https.${SELFSTEAL_DOMAIN}  IN  HTTPS  1 .  ech=${CP_ECH_PUBLIC_CONFIG}${COLOR_RESET}"
    fi
}