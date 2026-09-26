#!/bin/bash
# Module: Install Panel + Node (nginx, Xray TLS + static ECH on 443)
#
# Design A: Xray (inside remnanode) terminates TLS on 443 for every SNI and
# holds every certificate plus the static ECH key. nginx sits on a cleartext
# unix socket behind Xray and holds no certificate — its server blocks are
# HTTP only, listening on /dev/shm/nginx.sock with proxy_protocol to receive
# the real client IP from Xray's PROXY v2 header.
#
# Domain layout:
#   default (bonded): 2 domains — CDN (panel + /sub) and Direct (proxy).
#   optional split:   3 domains — panel, sub, direct.
#
# The whole compose is written in one heredoc — conditional content is
# resolved by shell variables, never patched with sed.

install_panel_node_nginx() {
    load_selfsteal_templates_module

    mkdir -p /opt/remnawave && cd /opt/remnawave

    reading "${LANG[ENTER_PANEL_DOMAIN]}" PANEL_DOMAIN
    check_domain "$PANEL_DOMAIN" true true
    local panel_check_result=$?
    if [ $panel_check_result -eq 2 ]; then
        echo -e "${COLOR_RED}${LANG[ABORT_MESSAGE]}${COLOR_RESET}"
        exit 1
    fi

    # Bonded default; split restores the old three-domain layout.
    local split_sub="n"
    printf ' %s' "$(question "${LANG[SUB_ON_PANEL_PATH_ASK]}")"
    read_yn split_sub || true
    echo

    if [ "$split_sub" = "y" ]; then
        SUB_ON_PANEL_PATH=false
        reading "${LANG[ENTER_SUB_DOMAIN]}" SUB_DOMAIN
        check_domain "$SUB_DOMAIN" true true
        local sub_check_result=$?
        if [ $sub_check_result -eq 2 ]; then
            echo -e "${COLOR_RED}${LANG[ABORT_MESSAGE]}${COLOR_RESET}"
            exit 1
        fi
    else
        SUB_ON_PANEL_PATH=true
        SUB_DOMAIN="$PANEL_DOMAIN"
    fi

    reading "${LANG[ENTER_NODE_DOMAIN]}" SELFSTEAL_DOMAIN
    check_domain "$SELFSTEAL_DOMAIN" true false
    local node_check_result=$?
    if [ $node_check_result -eq 2 ]; then
        echo -e "${COLOR_RED}${LANG[ABORT_MESSAGE]}${COLOR_RESET}"
        exit 1
    fi

    if [ "$PANEL_DOMAIN" = "$SELFSTEAL_DOMAIN" ] || [ "$SUB_DOMAIN" = "$SELFSTEAL_DOMAIN" ]; then
        echo -e "${COLOR_RED}${LANG[DOMAINS_MUST_BE_UNIQUE]}${COLOR_RESET}"
        exit 1
    fi

    PANEL_BASE_DOMAIN=$(extract_domain "$PANEL_DOMAIN")
    SELFSTEAL_BASE_DOMAIN=$(extract_domain "$SELFSTEAL_DOMAIN")

    unique_domains["$PANEL_BASE_DOMAIN"]=1
    unique_domains["$SELFSTEAL_BASE_DOMAIN"]=1
    if [ "$SUB_ON_PANEL_PATH" = false ]; then
        SUB_BASE_DOMAIN=$(extract_domain "$SUB_DOMAIN")
        unique_domains["$SUB_BASE_DOMAIN"]=1
    fi

    # nginx auth: cookie (magic query param) or TinyAuth (extra subdomain +
    # cert, own container). The caddy portal is not available on nginx.
    PANEL_AUTH_MODE=cookie
    while true; do
        echo -e ""
        echo -e "${COLOR_GREEN}${LANG[PANEL_AUTH_PROMPT]}${COLOR_RESET}"
        echo -e ""
        echo -e "${COLOR_YELLOW}1. ${LANG[PANEL_AUTH_OPT_COOKIE]}${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}2. ${LANG[PANEL_AUTH_OPT_TINYAUTH]}${COLOR_RESET}"
        echo -e ""
        reading "${LANG[PANEL_AUTH_PROMPT_CHOOSE]}" auth_choice
        case "$auth_choice" in
            1) break ;;
            2) PANEL_AUTH_MODE=tinyauth; break ;;
            *) echo -e "${COLOR_RED}${LANG[CERT_INVALID_CHOICE]}${COLOR_RESET}" ;;
        esac
    done

    SUPERADMIN_USERNAME=$(generate_user)
    SUPERADMIN_PASSWORD=$(generate_password)

    cookies_random1=$(generate_user)
    cookies_random2=$(generate_user)

    METRICS_USER=$(generate_user)
    METRICS_PASS=$(generate_user)

    APP_SECRET=$(openssl rand -hex 64)

    if [ "$PANEL_AUTH_MODE" = "tinyauth" ]; then
        load_tinyauth_module
        tinyauth_setup "$PANEL_BASE_DOMAIN" "$PANEL_DOMAIN" "$SUB_DOMAIN" "$SELFSTEAL_DOMAIN"
    fi

    # SUB_PUBLIC_DOMAIN carries the /sub suffix when bonded. The sub-page
    # container is given CUSTOM_SUB_PREFIX=/sub so it expects the same path.
    local sub_public_domain sub_custom_prefix
    if [ "$SUB_ON_PANEL_PATH" = true ]; then
        sub_public_domain="${PANEL_DOMAIN}/sub"
        sub_custom_prefix="/sub"
    else
        sub_public_domain="$SUB_DOMAIN"
        sub_custom_prefix=""
    fi

    # ---- ECH key --------------------------------------------------------
    if ! docker image inspect remnawave/node:latest >/dev/null 2>&1; then
        step_do "${LANG[ECH_IMAGE_PULL]}"
        docker pull remnawave/node:latest >/dev/null 2>&1 || true
    fi

    CP_ECH_KEY_PATH=""
    CP_ECH_PUBLIC_CONFIG=""
    ensure_ech_server_keys "/opt/remnawave" "$SELFSTEAL_DOMAIN" || true

    local ech_mount_line=""
    if [ -n "$CP_ECH_KEY_PATH" ]; then
        ech_mount_line="      - ./ech:/etc/xray/ech:ro"
    fi

    # ---- .env -----------------------------------------------------------
    cat > .env <<EOL
### APP ###
APP_PORT=3000
METRICS_PORT=3001

### API ###
API_INSTANCES=1

### DATABASE ###
DATABASE_URL="postgresql://postgres:postgres@remnawave-db:5432/postgres"

### REDIS ###
REDIS_SOCKET=/var/run/valkey/valkey.sock

### SECRETS ###
APP_SECRET=$APP_SECRET

JWT_AUTH_LIFETIME=168

### TELEGRAM NOTIFICATIONS ###
IS_TELEGRAM_NOTIFICATIONS_ENABLED=false
TELEGRAM_BOT_TOKEN=change_me

TELEGRAM_NOTIFY_USERS=change_me
TELEGRAM_NOTIFY_NODES=change_me
TELEGRAM_NOTIFY_CRM=change_me
TELEGRAM_NOTIFY_SERVICE=change_me
TELEGRAM_NOTIFY_TBLOCKER=change_me

### PANEL DOMAIN ###
PANEL_DOMAIN=$PANEL_DOMAIN

### FRONT_END ###
FRONT_END_DOMAIN=$PANEL_DOMAIN

### SUBSCRIPTION PUBLIC DOMAIN ###
SUB_PUBLIC_DOMAIN=$sub_public_domain

### PROMETHEUS ###
METRICS_USER=$METRICS_USER
METRICS_PASS=$METRICS_PASS

### Webhook configuration
WEBHOOK_ENABLED=false
WEBHOOK_URL=https://your-webhook-url.com/endpoint
WEBHOOK_SECRET_HEADER=vsmu67Kmg6R8FjIOF1WUY8LWBHie4scdEqrfsKmyf4IAf8dY3nFS0wwYHkhh6ZvQ

### Bandwidth usage reached notifications
BANDWIDTH_USAGE_NOTIFICATIONS_ENABLED=false
BANDWIDTH_USAGE_NOTIFICATIONS_THRESHOLD=[60, 80]

### Not connected users notification
NOT_CONNECTED_USERS_NOTIFICATIONS_ENABLED=false
NOT_CONNECTED_USERS_NOTIFICATIONS_AFTER_HOURS=[6, 24, 48]

### Database ###
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=postgres
EOL

    # ---- docker-compose.yml ---------------------------------------------
    cat > docker-compose.yml <<EOL
x-common: &common
  ulimits:
    nofile:
      soft: 1048576
      hard: 1048576
  restart: always

x-networks: &networks
  networks:
    - remnawave-network

x-logging: &logging
  logging:
    driver: json-file
    options:
      max-size: 100m
      max-file: 5

x-env: &env
  env_file: .env

services:
  remnawave-db:
    image: postgres:18.6
    container_name: 'remnawave-db'
    hostname: remnawave-db
    shm_size: 512mb
    <<: [*common, *logging, *env, *networks]
    environment:
      - POSTGRES_USER=\${POSTGRES_USER}
      - POSTGRES_PASSWORD=\${POSTGRES_PASSWORD}
      - POSTGRES_DB=\${POSTGRES_DB}
      - TZ=UTC
    ports:
      - '127.0.0.1:6767:5432'
    volumes:
      - remnawave-db-data:/var/lib/postgresql
    healthcheck:
      test: ['CMD-SHELL', 'pg_isready -U \$\${POSTGRES_USER} -d \$\${POSTGRES_DB}']
      interval: 3s
      timeout: 10s
      retries: 3

  remnawave:
    image: remnawave/backend:3
    container_name: remnawave
    hostname: remnawave
    <<: [*common, *logging, *env, *networks]
    volumes:
      - valkey-socket:/var/run/valkey
    ports:
      - '127.0.0.1:3000:\${APP_PORT:-3000}'
      - '127.0.0.1:3001:\${METRICS_PORT:-3001}'
    healthcheck:
      test: ['CMD-SHELL', 'curl -f http://localhost:\${METRICS_PORT:-3001}/health']
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 30s
    depends_on:
      remnawave-db:
        condition: service_healthy
      remnawave-redis:
        condition: service_healthy

  remnawave-redis:
    image: valkey/valkey:9.1.2-alpine
    container_name: remnawave-redis
    hostname: remnawave-redis
    <<: [*common, *logging, *networks]
    volumes:
      - valkey-socket:/var/run/valkey
    command: >
      valkey-server
      --save ""
      --appendonly no
      --maxmemory-policy noeviction
      --loglevel warning
      --unixsocket /var/run/valkey/valkey.sock
      --unixsocketperm 777
      --port 0
    healthcheck:
      test: ['CMD', 'valkey-cli', '-s', '/var/run/valkey/valkey.sock', 'ping']
      interval: 3s
      timeout: 10s
      retries: 3

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

  remnawave-subscription-page:
    image: remnawave/subscription-page:latest
    container_name: remnawave-subscription-page
    hostname: remnawave-subscription-page
    <<: [*common, *logging, *networks]
    environment:
      - REMNAWAVE_PANEL_URL=http://remnawave:3000
      - APP_PORT=3010
      - REMNAWAVE_API_TOKEN=\$api_token
      - CUSTOM_SUB_PREFIX=${sub_custom_prefix}
    ports:
      - '127.0.0.1:3010:3010'
    depends_on:
      remnawave:
        condition: service_healthy

  # Xray owns 443 (TLS). Certificates and the static ECH key mount here,
  # never into nginx.
  remnanode:
    image: remnawave/node:latest
    container_name: remnanode
    hostname: remnanode
    <<: [*common, *logging]
    depends_on:
      remnawave:
        condition: service_healthy
    network_mode: host
    cap_add:
      - NET_ADMIN
    environment:
      - NODE_PORT=2222
      - SECRET_KEY="PUBLIC KEY FROM REMNAWAVE-PANEL"
    volumes:
      - /dev/shm:/dev/shm:rw
      - /var/log/remnanode:/var/log/remnanode
      - /etc/letsencrypt:/etc/letsencrypt:ro
$ech_mount_line
EOL

    if [ "$PANEL_AUTH_MODE" = "tinyauth" ]; then
        tinyauth_compose_service /opt/remnawave
    fi

    cat >> /opt/remnawave/docker-compose.yml <<EOL

networks:
  remnawave-network:
    name: remnawave-network
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/16
    external: false

volumes:
  remnawave-db-data:
    driver: local
    external: false
    name: remnawave-db-data
  valkey-socket:
    name: valkey-socket
    driver: local
    external: false
EOL
}

installation() {
    check_panel_not_running
    check_port_443_free
    check_node_not_running
    load_certificates_module
    echo -e "${COLOR_YELLOW}${LANG[INSTALLING]}${COLOR_RESET}"
    sleep 1

    declare -A unique_domains
    install_panel_node_nginx

    declare -A domains_to_check
    domains_to_check["$PANEL_DOMAIN"]=1
    if [ "$SUB_ON_PANEL_PATH" = false ]; then
        domains_to_check["$SUB_DOMAIN"]=1
    fi
    domains_to_check["$SELFSTEAL_DOMAIN"]=1
    if [ "$PANEL_AUTH_MODE" = "tinyauth" ]; then
        domains_to_check["$TINYAUTH_DOMAIN"]=1
    fi

    handle_certificates domains_to_check "$CERT_METHOD" "$LETSENCRYPT_EMAIL" || return 1

    PANEL_CERT_DOMAIN=$(resolve_certificate_domain "$PANEL_DOMAIN") || return 1
    if [ "$SUB_ON_PANEL_PATH" = false ]; then
        SUB_CERT_DOMAIN=$(resolve_certificate_domain "$SUB_DOMAIN") || return 1
    fi
    NODE_CERT_DOMAIN=$(resolve_certificate_domain "$SELFSTEAL_DOMAIN") || return 1
    if [ "$PANEL_AUTH_MODE" = "tinyauth" ]; then
        TINYAUTH_CERT_DOMAIN=$(resolve_certificate_domain "$TINYAUTH_DOMAIN") || return 1
    fi

    # Certbot deploy hook restarts remnanode (Xray holds the certs, no hot
    # reload through bind mounts). nginx holds no cert.
    for domain in "${!domains_to_check[@]}"; do
        local lineage conf
        lineage=$(resolve_certificate_domain "$domain" 2>/dev/null) || continue
        conf="/etc/letsencrypt/renewal/$lineage.conf"
        [ -f "$conf" ] || continue
        sed -i -E 's|^deploy_hook = .*|deploy_hook = /usr/bin/docker restart remnanode 2>/dev/null \|\| true|' "$conf"
    done

    # ---- nginx.conf -----------------------------------------------------
    # Cleartext socket listener, proxy_protocol to receive the real client
    # IP from Xray. No ssl_certificate directives anywhere — Xray terminated
    # TLS on 443.
    cat > /opt/remnawave/nginx.conf <<EOL
server_names_hash_bucket_size 64;

gzip_vary on;
gzip_proxied any;
gzip_comp_level 6;
gzip_min_length 1024;
gzip_types
    application/javascript
    application/json
    application/manifest+json
    application/xml
    application/wasm
    font/opentype
    font/eot
    font/otf
    font/ttf
    image/svg+xml
    text/css
    text/javascript
    text/plain
    text/xml;

upstream remnawave {
    server 127.0.0.1:3000;
}

upstream json {
    server 127.0.0.1:3010;
}

map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ""      close;
}
EOL

    if [ "$PANEL_AUTH_MODE" = "tinyauth" ]; then
        tinyauth_nginx_sites "unix:/dev/shm/nginx.sock proxy_protocol" "$PANEL_DOMAIN" "$PANEL_CERT_DOMAIN" "$TINYAUTH_CERT_DOMAIN" "remnawave" >> /opt/remnawave/nginx.conf
    else
        cat >> /opt/remnawave/nginx.conf <<EOL

map \$http_cookie \$auth_cookie {
    default 0;
    "~*${cookies_random1}=${cookies_random2}" 1;
}

map \$arg_${cookies_random1} \$auth_query {
    default 0;
    "${cookies_random2}" 1;
}

map "\$auth_cookie\$auth_query" \$authorized {
    "~1" 1;
    default 0;
}

map \$arg_${cookies_random1} \$set_cookie_header {
    "${cookies_random2}" "${cookies_random1}=${cookies_random2}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=31536000";
    default "";
}

# Panel domain — sub path served by the subscription page (no cookie).
server {
    server_name $PANEL_DOMAIN;
    listen unix:/dev/shm/nginx.sock proxy_protocol;
    http2 on;
    gzip on;

    add_header Set-Cookie \$set_cookie_header;

    location ^~ /sub/ {
        proxy_http_version 1.1;
        proxy_pass http://json;
        proxy_set_header Host \$host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header X-Real-IP \$proxy_protocol_addr;
        proxy_set_header X-Forwarded-For \$proxy_protocol_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port 443;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        proxy_intercept_errors on;
        error_page 400 404 500 502 @redirect;
    }

    location @redirect {
        return 444;
    }

    location / {
        if (\$authorized = 0) {
            return 418;
        }
        error_page 418 = @unauthorized;
        recursive_error_pages on;

        proxy_http_version 1.1;
        proxy_pass http://remnawave;
        proxy_set_header Host \$host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header X-Real-IP \$proxy_protocol_addr;
        proxy_set_header X-Forwarded-For \$proxy_protocol_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port 443;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    location @unauthorized {
        root /var/www/html;
        index index.html;
    }

    # OAuth2 callbacks land on /oauth2/callback/:provider from every
    # provider's redirect (GitHub, Yandex, Pocket ID, Telegram) without
    # the access cookie. Only a request carrying code+state gets through.
    location ^~ /oauth2/ {
        if (\$arg_code = "") { return 444; }
        if (\$arg_state = "") { return 444; }
        proxy_http_version 1.1;
        proxy_pass http://remnawave;
        proxy_set_header Host \$host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header X-Real-IP \$proxy_protocol_addr;
        proxy_set_header X-Forwarded-For \$proxy_protocol_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port 443;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
EOL
    fi

    if [ "$SUB_ON_PANEL_PATH" = false ]; then
        cat >> /opt/remnawave/nginx.conf <<EOL

# Separate-sub-domain layout: its own server block.
server {
    server_name $SUB_DOMAIN;
    listen unix:/dev/shm/nginx.sock proxy_protocol;
    http2 on;
    gzip on;

    location / {
        proxy_http_version 1.1;
        proxy_pass http://json;
        proxy_set_header Host \$host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header X-Real-IP \$proxy_protocol_addr;
        proxy_set_header X-Forwarded-For \$proxy_protocol_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port 443;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        proxy_intercept_errors on;
        error_page 400 404 500 502 @redirect;
    }

    location @redirect {
        return 444;
    }
}
EOL
    fi

    cat >> /opt/remnawave/nginx.conf <<EOL

# Direct domain — camouflage site behind Xray.
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

    # ---- Start stack ----------------------------------------------------
    echo -e "${COLOR_YELLOW}${LANG[STARTING_PANEL_NODE]}${COLOR_RESET}"
    sleep 1
    cd /opt/remnawave
    docker compose up -d > /dev/null 2>&1 &
    spinner $! "${LANG[WAITING]}"

    ufw allow from "172.30.0.0/16" to any port 2222 proto tcp > /dev/null 2>&1

    local domain_url="127.0.0.1:3000"
    local target_dir="/opt/remnawave"

    sleep 20

    step_do "${LANG[CHECK_CONTAINERS]}"
    local attempts=0 max_attempts=5
    until curl -s -f --max-time 30 "http://$domain_url/api/auth/status" \
        --header 'X-Forwarded-For: 127.0.0.1' \
        --header 'X-Forwarded-Proto: https' > /dev/null; do
        attempts=$((attempts + 1))
        if [ "$attempts" -ge "$max_attempts" ]; then
            error "$(printf "${LANG[CONTAINERS_TIMEOUT]}" $max_attempts)"
        fi
        echo -e "${COLOR_RED}$(printf "${LANG[CONTAINERS_NOT_READY_ATTEMPT]}" $attempts $max_attempts)${COLOR_RESET}"
        sleep 60
    done

    local token
    token=$(register_remnawave "$domain_url" "$SUPERADMIN_USERNAME" "$SUPERADMIN_PASSWORD")
    case "$token" in
        ey*) ;;
        *) abort_with_credentials "${LANG[ERROR_REGISTER]}: $token" ;;
    esac

    sleep 1
    get_public_key "$domain_url" "$token" "$target_dir" || abort_with_credentials "${LANG[ERROR_EXTRACT_PUBLIC_KEY]}"

    delete_config_profile "$domain_url" "$token"

    CP_PROFILE_NAME="StealConfig"
    CP_INBOUND_TAG="Steal"
    CP_DIRECT_DOMAIN="$SELFSTEAL_DOMAIN"
    CP_DIRECT_CERT="$NODE_CERT_DOMAIN"
    CP_PANEL_DOMAIN="$PANEL_DOMAIN"
    CP_PANEL_CERT="$PANEL_CERT_DOMAIN"
    CP_TINYAUTH_DOMAIN=""
    CP_TINYAUTH_CERT=""
    if [ "$PANEL_AUTH_MODE" = "tinyauth" ]; then
        CP_TINYAUTH_DOMAIN="$TINYAUTH_DOMAIN"
        CP_TINYAUTH_CERT="$TINYAUTH_CERT_DOMAIN"
    fi

    local profile_output
    profile_output=$(create_config_profile "$domain_url" "$token") || abort_with_credentials "${LANG[ERROR_CREATE_CONFIG_PROFILE]}"
    read -r config_profile_uuid inbound_uuid <<< "$profile_output"

    create_node "$domain_url" "$token" "$config_profile_uuid" "$inbound_uuid" || abort_with_credentials "${LANG[ERROR_CREATE_NODE]}"
    create_host "$domain_url" "$token" "$inbound_uuid" "$SELFSTEAL_DOMAIN" "$config_profile_uuid" || abort_with_credentials "${LANG[ERROR_CREATE_HOST]}"

    local squad_uuid
    squad_uuid=$(get_default_squad "$domain_url" "$token")
    update_squad "$domain_url" "$token" "$squad_uuid" "$inbound_uuid"

    persist_script_api_token "$domain_url" "$token"
    create_api_token "$domain_url" "$token" "$target_dir"

    if [ -n "$CP_ECH_PUBLIC_CONFIG" ]; then
        ensure_ech_subscription_templates "$domain_url" "$token" "$CP_ECH_PUBLIC_CONFIG" || true
    fi

    step_do "${LANG[STOPPING_REMNAWAVE]}"
    sleep 1
    docker compose down > /dev/null 2>&1

    step_do "${LANG[STARTING_PANEL_NODE]}"
    sleep 1
    if ! docker compose up -d > /dev/null 2>&1; then
        echo -e "${COLOR_RED}$(printf "${LANG[COMPOSE_UP_FAIL]}" "/opt/remnawave" "/opt/remnawave")${COLOR_RESET}"
        return 1
    fi

    clear

    echo -e "${COLOR_YELLOW}=================================================${COLOR_RESET}"
    echo -e "${COLOR_GREEN}${LANG[INSTALL_COMPLETE]}${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}=================================================${COLOR_RESET}"
    if [ "$PANEL_AUTH_MODE" = "tinyauth" ]; then
        tinyauth_banner "$PANEL_DOMAIN"
        echo -e "${COLOR_YELLOW}-------------------------------------------------${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}${LANG[ADMIN_CREDS]}${COLOR_RESET}"
    else
        echo -e "${COLOR_YELLOW}${LANG[PANEL_ACCESS]}${COLOR_RESET}"
        echo -e "${COLOR_WHITE}https://${PANEL_DOMAIN}/auth/login?${cookies_random1}=${cookies_random2}${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}-------------------------------------------------${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}${LANG[ADMIN_CREDS]}${COLOR_RESET}"
    fi
    echo -e "${COLOR_YELLOW}${LANG[USERNAME]} ${COLOR_WHITE}$SUPERADMIN_USERNAME${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}${LANG[PASSWORD]} ${COLOR_WHITE}$SUPERADMIN_PASSWORD${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}-------------------------------------------------${COLOR_RESET}"
    if [ "$SUB_ON_PANEL_PATH" = true ]; then
        echo -e "${COLOR_YELLOW}${LANG[SUB_ACCESS]} https://${PANEL_DOMAIN}/sub${COLOR_RESET}"
    else
        echo -e "${COLOR_YELLOW}${LANG[SUB_ACCESS]} https://${SUB_DOMAIN}${COLOR_RESET}"
    fi
    echo -e "${COLOR_YELLOW}-------------------------------------------------${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}${LANG[RELAUNCH_CMD]}${COLOR_RESET}"
    echo -e "${COLOR_GREEN}remnawave_reverse${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}=================================================${COLOR_RESET}"

    if [ -n "$CP_ECH_PUBLIC_CONFIG" ]; then
        echo -e ""
        echo -e "${COLOR_GREEN}${LANG[ECH_PUBLISH_NOTICE]}${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}${LANG[ECH_PUBLIC_LABEL]}${COLOR_RESET}"
        echo -e "${COLOR_WHITE}${CP_ECH_PUBLIC_CONFIG}${COLOR_RESET}"
        echo -e ""
        echo -e "${COLOR_YELLOW}${LANG[ECH_DNS_LABEL]}${COLOR_RESET}"
        echo -e "${COLOR_WHITE}  _https.${SELFSTEAL_DOMAIN}  IN  HTTPS  1 .  ech=${CP_ECH_PUBLIC_CONFIG}${COLOR_RESET}"
        echo -e ""
        echo -e "${COLOR_YELLOW}${LANG[ECH_SUB_INJECTED]}${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}=================================================${COLOR_RESET}"
    fi

    randomhtml || exit 1
}