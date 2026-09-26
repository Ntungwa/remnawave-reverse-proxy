#!/bin/bash
# Module: Install Panel Only (nginx)
#
# No Xray on this box, so nginx terminates TLS on 443 with its own
# certificates. This is the one nginx installer under Design A where nginx
# holds the certs. The direct domain is asked for anyway: it is the ECH
# serverName that the panel will hand downstream to every node it manages,
# and `xray tls ech` binds to it without needing the domain's cert here.
#
# Domain layout:
#   default (bonded): 2 domains — CDN (panel + /sub) and Direct.
#   optional split:   3 domains — panel, sub, direct.
#
# The whole compose and nginx.conf are written in one heredoc each —
# conditional content is resolved by shell variables, never patched with sed.

install_panel_nginx() {
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

    # The direct domain is asked here even though nothing on this box serves
    # it: the ECH keypair binds to this hostname, and downstream nodes will
    # present it as their SNI later.
    reading "${LANG[ENTER_NODE_DOMAIN]}" SELFSTEAL_DOMAIN
    if ! [[ "$SELFSTEAL_DOMAIN" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        echo -e "${COLOR_RED}${LANG[CERT_MANUAL_BAD_DOMAIN]}${COLOR_RESET}"
        exit 1
    fi

    if [ "$PANEL_DOMAIN" = "$SELFSTEAL_DOMAIN" ] || [ "$SUB_DOMAIN" = "$SELFSTEAL_DOMAIN" ]; then
        echo -e "${COLOR_RED}${LANG[DOMAINS_MUST_BE_UNIQUE]}${COLOR_RESET}"
        exit 1
    fi

    PANEL_BASE_DOMAIN=$(extract_domain "$PANEL_DOMAIN")

    unique_domains["$PANEL_BASE_DOMAIN"]=1
    if [ "$SUB_ON_PANEL_PATH" = false ]; then
        SUB_BASE_DOMAIN=$(extract_domain "$SUB_DOMAIN")
        unique_domains["$SUB_BASE_DOMAIN"]=1
    fi

    # nginx auth: cookie (magic query param) or TinyAuth (extra subdomain +
    # cert, own container).
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
        tinyauth_setup "$PANEL_BASE_DOMAIN" "$PANEL_DOMAIN" "$SUB_DOMAIN"
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
    # Generated before the compose is written. On panel-only there is no
    # local Xray to serve it — the key is what the panel injects into every
    # XRAY_JSON subscription template for its remote nodes. Requires the
    # node image on disk; pulled once here.
    if ! docker image inspect remnawave/node:latest >/dev/null 2>&1; then
        step_do "${LANG[ECH_IMAGE_PULL]}"
        docker pull remnawave/node:latest >/dev/null 2>&1 || true
    fi

    CP_ECH_KEY_PATH=""
    CP_ECH_PUBLIC_CONFIG=""
    ensure_ech_server_keys "/opt/remnawave" "$SELFSTEAL_DOMAIN" || true

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

  # No Xray on this box: nginx owns 443 and terminates TLS itself with the
  # panel and sub certificates. This is the one nginx installer where nginx
  # holds the certs.
  remnawave-nginx:
    image: nginx:1.30
    container_name: remnawave-nginx
    hostname: remnawave-nginx
    <<: [*common, *logging]
    network_mode: host
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
      - /var/www/html:/var/www/html:ro
EOL

    cat >> docker-compose.yml <<EOL

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
EOL

    if [ "$PANEL_AUTH_MODE" = "tinyauth" ]; then
        tinyauth_compose_service /opt/remnawave
    fi

    cat >> /opt/remnawave/docker-compose.yml <<EOL

networks:
  remnawave-network:
    name: remnawave-network
    driver: bridge
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

installation_panel() {
    check_panel_not_running
    check_port_443_free
    load_certificates_module
    echo -e "${COLOR_YELLOW}${LANG[INSTALLING_PANEL]}${COLOR_RESET}"
    sleep 1

    declare -A unique_domains
    install_panel_nginx

    declare -A domains_to_check
    domains_to_check["$PANEL_DOMAIN"]=1
    if [ "$SUB_ON_PANEL_PATH" = false ]; then
        domains_to_check["$SUB_DOMAIN"]=1
    fi
    if [ "$PANEL_AUTH_MODE" = "tinyauth" ]; then
        domains_to_check["$TINYAUTH_DOMAIN"]=1
    fi

    handle_certificates domains_to_check "$CERT_METHOD" "$LETSENCRYPT_EMAIL" "/opt/remnawave" || return 1

    PANEL_CERT_DOMAIN=$(resolve_certificate_domain "$PANEL_DOMAIN") || return 1
    if [ "$SUB_ON_PANEL_PATH" = false ]; then
        SUB_CERT_DOMAIN=$(resolve_certificate_domain "$SUB_DOMAIN") || return 1
    fi
    if [ "$PANEL_AUTH_MODE" = "tinyauth" ]; then
        TINYAUTH_CERT_DOMAIN=$(resolve_certificate_domain "$TINYAUTH_DOMAIN") || return 1
    fi

    # Certbot deploy hook restarts remnawave-nginx: the container reads its
    # certs from the bind-mounted /etc/letsencrypt tree and keeps serving
    # the old inode until restarted.
    for domain in "${!domains_to_check[@]}"; do
        local lineage conf
        lineage=$(resolve_certificate_domain "$domain" 2>/dev/null) || continue
        conf="/etc/letsencrypt/renewal/$lineage.conf"
        [ -f "$conf" ] || continue
        sed -i -E 's|^deploy_hook = .*|deploy_hook = /usr/bin/docker restart remnawave-nginx 2>/dev/null \|\| true|' "$conf"
    done

    # ---- nginx.conf -----------------------------------------------------
    # nginx terminates TLS on 443. Certificates come from the bind-mounted
    # certbot tree. No proxy_protocol on the listener — nginx reads the
    # client IP directly from the TCP socket.
    cat > /opt/remnawave/nginx.conf <<EOL
server_names_hash_bucket_size 64;

# Gzip Compression
# Remnawave 3.x does not compress response bodies itself, so the reverse proxy
# has to. https://f.docs.rw/t/topic/354/3
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

ssl_protocols TLSv1.2 TLSv1.3;
ssl_ecdh_curve X25519:prime256v1:secp384r1;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305';
ssl_prefer_server_ciphers on;
ssl_session_timeout 1d;
ssl_session_cache shared:MozSSL:10m;
EOL

    if [ "$PANEL_AUTH_MODE" = "tinyauth" ]; then
        tinyauth_nginx_sites "443 ssl" "$PANEL_DOMAIN" "$PANEL_CERT_DOMAIN" "$TINYAUTH_CERT_DOMAIN" "remnawave" >> /opt/remnawave/nginx.conf
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
    listen 443 ssl;
    http2 on;
    gzip on;

    ssl_certificate "/etc/letsencrypt/live/$PANEL_CERT_DOMAIN/fullchain.pem";
    ssl_certificate_key "/etc/letsencrypt/live/$PANEL_CERT_DOMAIN/privkey.pem";
    ssl_trusted_certificate "/etc/letsencrypt/live/$PANEL_CERT_DOMAIN/fullchain.pem";

    add_header Set-Cookie \$set_cookie_header;

    location ^~ /sub/ {
        proxy_http_version 1.1;
        proxy_pass http://json;
        proxy_set_header Host \$host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
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
            return 444;
        }
        proxy_http_version 1.1;
        proxy_pass http://remnawave;
        proxy_set_header Host \$host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # OAuth2 callbacks: only a request carrying code+state gets through.
    location ^~ /oauth2/ {
        if (\$arg_code = "") { return 444; }
        if (\$arg_state = "") { return 444; }
        proxy_http_version 1.1;
        proxy_pass http://remnawave;
        proxy_set_header Host \$host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
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
    listen 443 ssl;
    http2 on;
    gzip on;

    ssl_certificate "/etc/letsencrypt/live/$SUB_CERT_DOMAIN/fullchain.pem";
    ssl_certificate_key "/etc/letsencrypt/live/$SUB_CERT_DOMAIN/privkey.pem";
    ssl_trusted_certificate "/etc/letsencrypt/live/$SUB_CERT_DOMAIN/fullchain.pem";

    location / {
        proxy_http_version 1.1;
        proxy_pass http://json;
        proxy_set_header Host \$host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
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

server {
    listen 443 ssl default_server;
    server_name _;
    ssl_reject_handshake on;
}
EOL

    echo -e "${COLOR_YELLOW}${LANG[STARTING_PANEL]}${COLOR_RESET}"
    sleep 1
    cd /opt/remnawave
    docker compose up -d > /dev/null 2>&1 &
    spinner $! "${LANG[WAITING]}"

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

    # No config profile on panel-only: no local node to bind. The
    # subscription page token still gets created for the sub-page container.
    persist_script_api_token "$domain_url" "$token"
    create_api_token "$domain_url" "$token" "$target_dir"

    if [ -n "$CP_ECH_PUBLIC_CONFIG" ]; then
        ensure_ech_subscription_templates "$domain_url" "$token" "$CP_ECH_PUBLIC_CONFIG" || true
    fi

    step_do "${LANG[STOPPING_REMNAWAVE_SUBSCRIPTION_PAGE]}"
    sleep 1
    docker compose down remnawave-subscription-page > /dev/null 2>&1 &
    spinner $! "${LANG[WAITING]}"

    step_do "${LANG[STARTING_REMNAWAVE_SUBSCRIPTION_PAGE]}"
    sleep 1
    docker compose up -d remnawave-subscription-page > /dev/null 2>&1 &
    spinner $! "${LANG[WAITING]}"

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
    echo -e "${COLOR_RED}${LANG[PANEL_ONLY_NEXT_STEP]}${COLOR_RESET}"

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
}