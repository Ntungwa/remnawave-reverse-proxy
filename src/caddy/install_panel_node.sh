#!/bin/bash
# Module: Install Panel + Node (Caddy, Xray TLS + static ECH on 443)
#
# Design A: Xray (inside remnanode) terminates TLS on 443 for every SNI and
# holds every certificate plus the static ECH key. Caddy sits on a cleartext
# unix socket behind Xray and holds no certificate at all — auto_https is
# off globally, TLS is dropped from the listener wrapper.
#
# Domain layout:
#   default (bonded): 2 domains — CDN (panel + /sub) and Direct (proxy).
#   optional split:   3 domains — panel, sub, direct.
#
# The whole compose is written in one heredoc — conditional content is
# resolved by shell variables, never patched with sed.

install_panel_node_caddy() {
    load_selfsteal_templates_module

    mkdir -p /opt/remnawave && cd /opt/remnawave

    reading "${LANG[ENTER_PANEL_DOMAIN]}" PANEL_DOMAIN
    check_domain "$PANEL_DOMAIN" true true
    local panel_check_result=$?
    if [ $panel_check_result -eq 2 ]; then
        echo -e "${COLOR_RED}${LANG[ABORT_MESSAGE]}${COLOR_RESET}"
        exit 1
    fi

    # Bonded is the default: the sub page lives on the CDN domain at /sub.
    # Split restores the old three-domain layout and asks for a separate
    # subscription hostname.
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

    PANEL_AUTH_MODE=cookie
    CADDY_IMAGE="caddy:2.11.4"
    AUTHP_ENV=""
    while true; do
        echo -e ""
        echo -e "${COLOR_GREEN}${LANG[PANEL_AUTH_PROMPT]}${COLOR_RESET}"
        echo -e ""
        echo -e "${COLOR_YELLOW}1. ${LANG[PANEL_AUTH_OPT_COOKIE]}${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}2. ${LANG[PANEL_AUTH_OPT_PORTAL]}${COLOR_RESET}"
        echo -e ""
        reading "${LANG[PANEL_AUTH_PROMPT_CHOOSE]}" auth_choice
        case "$auth_choice" in
            1) break ;;
            2)
                PANEL_AUTH_MODE=portal
                CADDY_IMAGE="remnawave/caddy-with-auth:latest"
                break
                ;;
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

    if [ "$PANEL_AUTH_MODE" = "portal" ]; then
        AUTHP_ADMIN_USER="$SUPERADMIN_USERNAME"
        AUTHP_ADMIN_EMAIL="${SUPERADMIN_USERNAME}@${PANEL_DOMAIN}"
        AUTHP_ADMIN_SECRET=$(generate_password)
        AUTHP_ENV=$(printf '\n          - AUTHP_ADMIN_USER=%s\n          - AUTHP_ADMIN_EMAIL=%s\n          - AUTHP_ADMIN_SECRET=%s\n          - AUTH_TOKEN_LIFETIME=604800' \
            "$AUTHP_ADMIN_USER" "$AUTHP_ADMIN_EMAIL" "$AUTHP_ADMIN_SECRET")
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
    # Generated before the compose is written so the remnanode volume list
    # can carry (or omit) the mount at heredoc time. Requires the node
    # image on disk for `xray tls ech`; pulled once here.
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

  # Cleartext reverse proxy behind Xray. No certificate, no auto_https.
  remnawave-caddy:
      image: ${CADDY_IMAGE}
      container_name: remnawave-caddy
      hostname: remnawave-caddy
      <<: [*common, *logging]
      network_mode: host
      volumes:
          - ./Caddyfile:/etc/caddy/Caddyfile
          - /var/www/html:/var/www/html:ro
          - /dev/shm:/dev/shm:rw
          - caddy_data:/data
      command: sh -c 'rm -f /dev/shm/nginx.sock && caddy run --config /etc/caddy/Caddyfile --adapter caddyfile'
      environment:
          - CADDY_SOCKET_PATH=/dev/shm/nginx.sock
          - SELF_STEAL_DOMAIN=${SELFSTEAL_DOMAIN}
          - PANEL_DOMAIN=${PANEL_DOMAIN}
          - SUB_DOMAIN=${SUB_DOMAIN}
          - SUB_ON_PANEL_PATH=${SUB_ON_PANEL_PATH}
          - BACKEND_URL=127.0.0.1:3000
          - SUB_BACKEND_URL=127.0.0.1:3010${AUTHP_ENV}
      healthcheck:
          test: ["CMD", "test", "-S", "/dev/shm/nginx.sock"]
          interval: 2s
          timeout: 5s
          retries: 15
          start_period: 5s

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
  # never into caddy.
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
  caddy_data:
    name: caddy_data
    driver: local
    external: false
EOL

    # ---- Caddyfile ------------------------------------------------------
    # Global options: no admin API, auto_https off (Xray terminated TLS),
    # proxy_protocol on the socket listener. No certificates are referenced
    # anywhere — Caddy is a cleartext reverse proxy on the shared socket.
    if [ "$PANEL_AUTH_MODE" = "portal" ]; then
        cat > /opt/remnawave/Caddyfile <<EOL
{
    admin off
    auto_https off
    order authenticate before respond
    order authorize before respond
    servers {
        listener_wrappers {
            proxy_protocol
        }
    }

    security {
        local identity store localdb {
            realm local
            path /data/.local/caddy/users.json
        }

        authentication portal remnawaveportal {
            crypto default token lifetime {\$AUTH_TOKEN_LIFETIME}
            enable identity store localdb
            cookie domain {\$PANEL_DOMAIN}
            ui {
                links {
                    "Remnawave" "/dashboard/home" icon "las la-tachometer-alt"
                    "My Identity" "/r/whoami" icon "las la-user"
                    "API Keys" "/r/settings/apikeys" icon "las la-key"
                    "MFA" "/r/settings/mfa" icon "lab la-keycdn"
                }
            }
            transform user {
                match origin local
                action add role authp/admin
                require mfa
            }
        }

        authorization policy panelpolicy {
            set auth url /r
            allow roles authp/admin
            with api key auth portal remnawaveportal realm local
            acl rule {
                comment "Accept"
                match role authp/admin
                allow stop log info
            }
            acl rule {
                comment "Deny"
                match any
                deny log warn
            }
        }
    }
}

http://{\$SELF_STEAL_DOMAIN} {
    bind unix/{\$CADDY_SOCKET_PATH}
    root * /var/www/html
    try_files {path} /index.html
    file_server
}
EOL
    else
        cat > /opt/remnawave/Caddyfile <<EOL
{
    admin off
    auto_https off
    servers {
        listener_wrappers {
            proxy_protocol
        }
    }
}

http://{\$SELF_STEAL_DOMAIN} {
    bind unix/{\$CADDY_SOCKET_PATH}
    root * /var/www/html
    try_files {path} /index.html
    file_server
}
EOL
    fi

    if [ "$PANEL_AUTH_MODE" = "portal" ]; then
        cat >> /opt/remnawave/Caddyfile <<EOL

http://{\$PANEL_DOMAIN} {
    bind unix/{\$CADDY_SOCKET_PATH}
    encode

    # Subscription: public by design, no portal auth.
    route /sub/* {
        reverse_proxy {\$SUB_BACKEND_URL} {
            header_up X-Real-IP {remote}
            header_up Host {host}
        }
    }

    # Panel API carries its own Bearer-token auth; OAuth2 callbacks must
    # reach the backend untouched.
    route /api/* {
        reverse_proxy {\$BACKEND_URL} {
            header_up X-Real-IP {remote}
            header_up Host {host}
        }
    }
    route /oauth2/* {
        reverse_proxy {\$BACKEND_URL} {
            header_up Host {host}
        }
    }

    handle /r {
        rewrite * /auth
        request_header +X-Forwarded-Prefix /r
        authenticate with remnawaveportal
    }
    route /r* {
        authenticate with remnawaveportal
    }
    route /* {
        authorize with panelpolicy
        reverse_proxy {\$BACKEND_URL} {
            header_up X-Real-IP {remote}
            header_up Host {host}
        }
    }
}
EOL
    else
        cat >> /opt/remnawave/Caddyfile <<EOL

http://{\$PANEL_DOMAIN} {
    bind unix/{\$CADDY_SOCKET_PATH}
    encode

    # Subscription: public, no cookie required.
    route /sub/* {
        reverse_proxy {\$SUB_BACKEND_URL} {
            header_up X-Real-IP {remote}
            header_up Host {host}
        }
    }

    @has_token_param {
        query $cookies_random1=$cookies_random2
    }
    handle @has_token_param {
        header +Set-Cookie "$cookies_random1=$cookies_random2; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000"
    }

    @unauthorized {
        not path /oauth2/*
        not header Cookie *$cookies_random1=$cookies_random2*
        not query $cookies_random1=$cookies_random2
    }
    handle @unauthorized {
        root * /var/www/html
        try_files {path} /index.html
        file_server
    }

    @oauth2_callback {
        path /oauth2/*
        query code=* state=*
    }
    handle @oauth2_callback {
        reverse_proxy {\$BACKEND_URL} {
            header_up Host {host}
        }
    }

    reverse_proxy {\$BACKEND_URL} {
        header_up X-Real-IP {remote}
        header_up Host {host}
    }
}
EOL
    fi

    # Separate-sub-domain layout gets its own site block.
    if [ "$SUB_ON_PANEL_PATH" = false ]; then
        cat >> /opt/remnawave/Caddyfile <<EOL

http://{\$SUB_DOMAIN} {
    bind unix/{\$CADDY_SOCKET_PATH}
    encode
    handle {
        reverse_proxy {\$SUB_BACKEND_URL} {
            header_up X-Real-IP {remote}
            header_up Host {host}
        }
    }
}
EOL
    fi
}

installation_panel_node_caddy() {
    check_panel_not_running
    check_port_443_free
    check_node_not_running
    load_certificates_module
    echo -e "${COLOR_YELLOW}${LANG[INSTALLING]}${COLOR_RESET}"
    sleep 1

    declare -A unique_domains
    install_panel_node_caddy

    declare -A domains_to_check
    domains_to_check["$PANEL_DOMAIN"]=1
    if [ "$SUB_ON_PANEL_PATH" = false ]; then
        domains_to_check["$SUB_DOMAIN"]=1
    fi
    domains_to_check["$SELFSTEAL_DOMAIN"]=1

    handle_certificates domains_to_check "$CERT_METHOD" "$LETSENCRYPT_EMAIL" "/opt/remnawave" || return 1

    PANEL_CERT_DOMAIN=$(resolve_certificate_domain "$PANEL_DOMAIN") || return 1
    if [ "$SUB_ON_PANEL_PATH" = false ]; then
        SUB_CERT_DOMAIN=$(resolve_certificate_domain "$SUB_DOMAIN") || return 1
    fi
    NODE_CERT_DOMAIN=$(resolve_certificate_domain "$SELFSTEAL_DOMAIN") || return 1

    # Certbot deploy hook must restart remnanode: Xray holds the certs and
    # keeps serving the old inode through its bind mounts until restarted.
    for domain in "${!domains_to_check[@]}"; do
        local lineage conf
        lineage=$(resolve_certificate_domain "$domain" 2>/dev/null) || continue
        conf="/etc/letsencrypt/renewal/$lineage.conf"
        [ -f "$conf" ] || continue
        sed -i -E 's|^deploy_hook = .*|deploy_hook = /usr/bin/docker restart remnanode 2>/dev/null \|\| true|' "$conf"
    done

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

    # Config profile: Xray TLS on 443 for direct + panel. ECH serverName is
    # the direct domain. Bonded layout uses the panel cert for both panel
    # and sub SNIs; split adds the sub cert separately (not wired here —
    # this installer's panel+node layout is bonded by design when a sub
    # domain is not asked for).
    CP_PROFILE_NAME="StealConfig"
    CP_INBOUND_TAG="Steal"
    CP_DIRECT_DOMAIN="$SELFSTEAL_DOMAIN"
    CP_DIRECT_CERT="$NODE_CERT_DOMAIN"
    CP_PANEL_DOMAIN="$PANEL_DOMAIN"
    CP_PANEL_CERT="$PANEL_CERT_DOMAIN"
    CP_TINYAUTH_DOMAIN=""
    CP_TINYAUTH_CERT=""

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
    if [ "$PANEL_AUTH_MODE" = "portal" ]; then
        echo -e "${COLOR_YELLOW}${LANG[PORTAL_ACCESS]}${COLOR_RESET}"
        echo -e "${COLOR_WHITE}https://${PANEL_DOMAIN}/r${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}${LANG[PORTAL_CREDS]}${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}${LANG[USERNAME]} ${COLOR_WHITE}$AUTHP_ADMIN_USER${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}${LANG[PASSWORD]} ${COLOR_WHITE}$AUTHP_ADMIN_SECRET${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}${LANG[PORTAL_MFA_NOTE]} https://${PANEL_DOMAIN}/r/settings/mfa${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}-------------------------------------------------${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}${LANG[ADMIN_CREDS]}${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}${LANG[USERNAME]} ${COLOR_WHITE}$SUPERADMIN_USERNAME${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}${LANG[PASSWORD]} ${COLOR_WHITE}$SUPERADMIN_PASSWORD${COLOR_RESET}"
    else
        echo -e "${COLOR_YELLOW}${LANG[PANEL_ACCESS]}${COLOR_RESET}"
        echo -e "${COLOR_WHITE}https://${PANEL_DOMAIN}/auth/login?${cookies_random1}=${cookies_random2}${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}-------------------------------------------------${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}${LANG[ADMIN_CREDS]}${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}${LANG[USERNAME]} ${COLOR_WHITE}$SUPERADMIN_USERNAME${COLOR_RESET}"
        echo -e "${COLOR_YELLOW}${LANG[PASSWORD]} ${COLOR_WHITE}$SUPERADMIN_PASSWORD${COLOR_RESET}"
    fi
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