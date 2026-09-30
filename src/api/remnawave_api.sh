cat > /usr/local/remnawave_reverse/api/remnawave_api.sh <<'ENDOFFILE'
#!/bin/bash
# Module: Remnawave API Functions
#
# Design A: Xray owns 443 and holds every certificate plus the static ECH
# key. The webserver is a cleartext reverse proxy on a unix socket behind it.
#
# ECH: server-key base64 blob passed INLINE as echServerKeys — the field is
# decoded by base64.StdEncoding.DecodeString and a file path is not base64.
# The on-disk file is a reference copy only.
#
# TLS ALPN is ["h2","http/1.1"]. Xray fallback docs: baseline needs
# alpn:['http/1.1'], h2 access needs alpn:['h2','http/1.1']. XHTTP is
# HTTP/2 and requires h2. Path matching does not work for h2 (HPACK-
# encoded), so the XHTTP fallback matches ALPN "h2" and is first in the
# table.
#
# Fallback hosts: one visible host per inbound. All ten are isHidden:false
# so the subscription lists ten proxies. Each fallback host carries its
# transport path. remnawave.injectHosts is NOT used.
#
# Host tags sanitized to /^[A-Z0-9_:]+$/.

err_msg() { echo -e "${COLOR_RED}$*${COLOR_RESET}" >&2; }

make_api_request() {
    local method=$1 url=$2 token=$3 data=$4
    local headers=(
        -H "Authorization: Bearer $token"
        -H "Content-Type: application/json"
        -H "X-Forwarded-For: 127.0.0.1"
        -H "X-Forwarded-Proto: https"
        -H "X-Remnawave-Client-Type: browser"
    )
    if [ -n "$data" ]; then
        curl -s --connect-timeout 10 --max-time 60 -X "$method" "$url" "${headers[@]}" -d "$data"
    else
        curl -s --connect-timeout 10 --max-time 60 -X "$method" "$url" "${headers[@]}"
    fi
}

rw_token_is_api() {
    local tok="$1"; [ -n "$tok" ] || return 1
    local p; p=$(printf '%s' "$tok" | cut -d. -f2)
    p="${p//-/+}"; p="${p//_/\/}"
    case $(( ${#p} % 4 )) in 2) p="${p}==";; 3) p="${p}=";; esac
    [ "$(printf '%s' "$p" | base64 -d 2>/dev/null | jq -r '.role // empty' 2>/dev/null)" = "API" ]
}

mint_script_api_token() {
    local domain_url="$1" token="$2"
    local list uuid body resp
    list=$(make_api_request "GET" "http://$domain_url/api/tokens" "$token")
    uuid=$(echo "$list" | jq -r '.response.tokens[]? | select(.name=="remnawave-reverse-proxy") | .uuid' 2>/dev/null | head -n1)
    [ -n "$uuid" ] && [ "$uuid" != "null" ] && make_api_request "DELETE" "http://$domain_url/api/tokens/$uuid" "$token" >/dev/null
    body=$(jq -n '{name:"remnawave-reverse-proxy",expiresInDays:3650,scopes:["*"]}')
    resp=$(make_api_request "POST" "http://$domain_url/api/tokens" "$token" "$body")
    echo "$resp" | jq -r '.response.token // empty'
}

persist_script_api_token() {
    local tok="${!#}"
    [ -n "$tok" ] || return 1
    case "$tok" in http*) return 1 ;; esac
    local file="${TOKEN_FILE:-${DIR_REMNAWAVE}/token}"
    mkdir -p "$(dirname "$file")" 2>/dev/null
    printf '%s' "$tok" > "$file"
    chmod 600 "$file" 2>/dev/null
}

register_remnawave() {
    local domain_url=$1 username=$2 password=$3 token=$4
    local d
    d=$(jq -n --arg u "$username" --arg p "$password" '{username:$u,password:$p}')
    step_do "${LANG[REGISTERING_REMNAWAVE]}" >&2
    local r
    r=$(make_api_request "POST" "http://$domain_url/api/auth/register" "$token" "$d")
    if [ -z "$r" ]; then err_msg "${LANG[ERROR_EMPTY_RESPONSE_REGISTER]}"; return 1
    elif [[ "$r" == *"accessToken"* ]]; then
        step_ok "${LANG[REGISTRATION_SUCCESS]}" >&2
        echo "$r" | jq -r '.response.accessToken'; return 0
    else err_msg "${LANG[ERROR_REGISTER]}: $r"; return 1; fi
}

panel_login_url() {
    local dir="${1:-/opt/remnawave}"
    local domain="${PANEL_DOMAIN:-}"
    if [ -z "$domain" ]; then
        domain=$(grep -h '^PANEL_DOMAIN=' "$dir/.env" "$dir/docker-compose.yml" 2>/dev/null | head -n1 \
            | sed -e 's/^PANEL_DOMAIN=//' -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'\$//" -e 's/[[:space:]]*$//')
    fi
    [ -n "$domain" ] || return 1
    local url="https://${domain}" line c1 c2
    if [ -f "$dir/nginx.conf" ] && ! grep -q "auth_request /tinyauth_check" "$dir/nginx.conf"; then
        line=$(grep -A 2 "map \$http_cookie \$auth_cookie" "$dir/nginx.conf" | grep "~*\w\+.*=" | head -n1)
        c1=$(echo "$line" | grep -oP '~*\K\w+(?==)'); c2=$(echo "$line" | grep -oP '=\K\w+(?=")')
        [ -n "$c1" ] && [ -n "$c2" ] && url="https://${domain}/auth/login?${c1}=${c2}"
    elif [ -f "$dir/Caddyfile" ] && ! grep -q "authentication portal" "$dir/Caddyfile"; then
        line=$(grep 'header +Set-Cookie' "$dir/Caddyfile" | head -n 1)
        c1=$(echo "$line" | grep -oP 'Set-Cookie "\K[^=]+')
        c2=$(echo "$line" | grep -oP 'Set-Cookie "[^=]+=\K[^;]+')
        [ -n "$c1" ] && [ -n "$c2" ] && url="https://${domain}/auth/login?${c1}=${c2}"
    fi
    echo "$url"
}

get_panel_token() {
    TOKEN_FILE="${DIR_REMNAWAVE}/token"
    local domain_url="127.0.0.1:3000"
    local ast; ast=$(make_api_request "GET" "http://${domain_url}/api/auth/status" "")
    local oauth=false prov=""
    if [ -n "$ast" ]; then
        local g y p t
        g=$(echo "$ast" | jq -r '.response.authentication.oauth2.providers.github // false' 2>/dev/null)
        y=$(echo "$ast" | jq -r '.response.authentication.oauth2.providers.yandex // false' 2>/dev/null)
        p=$(echo "$ast" | jq -r '.response.authentication.oauth2.providers.pocketid // false' 2>/dev/null)
        t=$(echo "$ast" | jq -r '.response.authentication.oauth2.providers.telegram // .response.authentication.tgAuth.enabled // false' 2>/dev/null)
        [ "$g" = "true" ] && prov+="GitHub, "
        [ "$y" = "true" ] && prov+="Yandex, "
        [ "$p" = "true" ] && prov+="Pocket ID, "
        [ "$t" = "true" ] && prov+="Telegram, "
        if [ -n "$prov" ]; then oauth=true; prov="${prov%, }"; fi
    fi
    if [ -f "$TOKEN_FILE" ]; then
        token=$(cat "$TOKEN_FILE")
        echo -e "${COLOR_YELLOW}${LANG[USING_SAVED_TOKEN]}${COLOR_RESET}"
        local tr; tr=$(make_api_request "GET" "http://${domain_url}/api/config-profiles" "$token")
        if [ -z "$tr" ] || ! echo "$tr" | jq -e '.response.configProfiles' >/dev/null 2>&1; then
            echo -e "${COLOR_RED}${LANG[INVALID_SAVED_TOKEN]}${COLOR_RESET}"
            token=""
        fi
    fi
    if [ -z "$token" ]; then
        if [ "$oauth" = true ]; then
            echo -e ""; echo -e "${COLOR_RED}${LANG[WARNING_LABEL]}${COLOR_RESET}"
            printf "${COLOR_YELLOW}${LANG[OAUTH_ENABLED_WARNING]}${COLOR_RESET}\n" "$prov"
            printf "${COLOR_YELLOW}${LANG[CREATE_API_TOKEN_INSTRUCTION]}${COLOR_RESET}\n" "$(panel_login_url)"
            reading "${LANG[ENTER_API_TOKEN]}" token
            [ -n "$token" ] || { echo -e "${COLOR_RED}${LANG[EMPTY_TOKEN_ERROR]}${COLOR_RESET}"; return 1; }
        else
            reading "${LANG[ENTER_PANEL_USERNAME]}" username
            reading "${LANG[ENTER_PANEL_PASSWORD]}" password
            local ld lr
            ld=$(jq -n --arg u "$username" --arg p "$password" '{username:$u,password:$p}')
            lr=$(make_api_request "POST" "http://${domain_url}/api/auth/login" "" "$ld")
            token=$(echo "$lr" | jq -r '.response.accessToken // .accessToken // ""')
            if [ -z "$token" ] || [ "$token" = "null" ]; then
                echo -e "${COLOR_RED}${LANG[ERROR_TOKEN]}: $lr${COLOR_RESET}"; return 1
            fi
        fi
        if ! rw_token_is_api "$token"; then
            local at; at=$(mint_script_api_token "$domain_url" "$token")
            [ -n "$at" ] && [ "$at" != "null" ] && token="$at"
        fi
        persist_script_api_token "$token"
        echo -e "${COLOR_GREEN}${LANG[TOKEN_RECEIVED_AND_SAVED]}${COLOR_RESET}"
    else
        echo -e "${COLOR_GREEN}${LANG[TOKEN_USED_SUCCESSFULLY]}${COLOR_RESET}"
    fi
    local ftr; ftr=$(make_api_request "GET" "http://${domain_url}/api/config-profiles" "$token")
    if [ -z "$ftr" ] || ! echo "$ftr" | jq -e '.response.configProfiles' >/dev/null 2>&1; then
        echo -e "${COLOR_RED}${LANG[INVALID_SAVED_TOKEN]}: $ftr${COLOR_RESET}"; return 1
    fi
}

get_public_key() {
    local domain_url=$1 token=$2 target_dir=$3
    step_do "${LANG[GET_PUBLIC_KEY]}"
    local r; r=$(make_api_request "GET" "http://$domain_url/api/keygen" "$token")
    [ -z "$r" ] && { echo -e "${COLOR_RED}${LANG[ERROR_PUBLIC_KEY]}${COLOR_RESET}"; return 1; }
    local pk; pk=$(echo "$r" | jq -r '.response.secretKey // .response.pubKey // empty')
    if [ -z "$pk" ] || [ "$pk" = "null" ]; then
        echo -e "${COLOR_RED}${LANG[ERROR_EXTRACT_PUBLIC_KEY]}: $r${COLOR_RESET}"; return 1
    fi
    local compose="$target_dir/docker-compose.yml"
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$compose" "$pk" <<'PY'
import io, re, sys
path, value = sys.argv[1], sys.argv[2]
with io.open(path, 'r', encoding='utf-8') as f: src = f.read()
pattern = re.compile(r'^(\s*-\s*SECRET_KEY=).*$', re.MULTILINE)
replacement = r'\1' + "'" + value.replace("'", "''") + "'"
new, n = pattern.subn(replacement, src)
if n == 0: sys.exit("SECRET_KEY line not found in " + path)
with io.open(path, 'w', encoding='utf-8') as f: f.write(new)
PY
    else
        local esc; esc=$(printf '%s' "$pk" | sed "s/'/''/g")
        sed -i "s|SECRET_KEY=.*|SECRET_KEY='${esc}'|" "$compose"
    fi
    step_ok "${LANG[PUBLIC_KEY_SUCCESS]}"
}

ensure_ech_server_keys() {
    local target_dir="$1" selfsteal_domain="$2"
    local ech_dir="$target_dir/ech"
    local server_file="$ech_dir/server-keys.txt"
    local client_file="$ech_dir/client-config.txt"
    local client_json="$ech_dir/client-config.json"

    CP_ECH_KEY_PATH=""; CP_ECH_SERVER_KEYS_B64=""; CP_ECH_PUBLIC_CONFIG=""
    mkdir -p "$ech_dir"; chmod 750 "$ech_dir"

    if [ -s "$server_file" ] && ! LC_ALL=C grep -qE '[^A-Za-z0-9+/=]' "$server_file"; then
        CP_ECH_KEY_PATH="/etc/xray/ech/server-keys.txt"
        CP_ECH_SERVER_KEYS_B64=$(cat "$server_file")
        [ -s "$client_file" ] && CP_ECH_PUBLIC_CONFIG=$(cat "$client_file")
        step_ok "${LANG[ECH_KEYGEN_REUSED]}"; return 0
    fi

    step_do "${LANG[ECH_KEYGEN]}"
    if ! docker image inspect remnawave/node:latest >/dev/null 2>&1; then
        docker pull remnawave/node:latest >/dev/null 2>&1 || true
    fi
    if ! docker image inspect remnawave/node:latest >/dev/null 2>&1; then
        echo -e "${COLOR_YELLOW}${LANG[ECH_KEYGEN_IMG_MISSING]}${COLOR_RESET}"; return 1
    fi

    local raw
    raw=$(docker run --rm --entrypoint /usr/local/bin/xray \
        remnawave/node:latest tls ech --serverName "$selfsteal_domain" 2>/dev/null)
    [ -z "$raw" ] && { echo -e "${COLOR_YELLOW}${LANG[ECH_KEYGEN_FAIL]}${COLOR_RESET}"; return 1; }

    local kb
    kb=$(printf '%s\n' "$raw" | sed -n '/ECH server keys:/,$p' | tail -n +2 | tr -d '[:space:]:')
    [ -z "$kb" ] && kb=$(printf '%s\n' "$raw" | sed -n 's/.*ECH server keys:[[:space:]]*//p' | tr -d '[:space:]:')
    [ -z "$kb" ] && kb=$(printf '%s\n' "$raw" | grep -oE '[A-Za-z0-9+/=]{40,}' | sort -u | awk '{print length,$0}' | sort -rn | head -n1 | cut -d' ' -f2-)
    [ -z "$kb" ] && { echo -e "${COLOR_YELLOW}${LANG[ECH_KEYGEN_FAIL]}${COLOR_RESET}"; return 1; }

    printf '%s' "$kb" > "$server_file"; chmod 640 "$server_file"
    CP_ECH_SERVER_KEYS_B64="$kb"

    local pc
    pc=$(printf '%s\n' "$raw" | sed -n '/ECH config list:/,/ECH server keys:/p' | sed '1d;$d' | tr -d '[:space:]:')
    [ -z "$pc" ] && pc=$(printf '%s\n' "$raw" | sed -n 's/.*ECH config list:[[:space:]]*//p' | tr -d '[:space:]:')
    [ -z "$pc" ] && pc=$(printf '%s\n' "$raw" | sed -n '/ECH server keys:/q;p' | grep -oE '[A-Za-z0-9+/=]{40,}' | tail -n1)

    if [ -n "$pc" ]; then
        printf '%s' "$pc" > "$client_file"; chmod 644 "$client_file"
        jq -n --arg e "$pc" '{echConfigList:$e}' > "$client_json"; chmod 644 "$client_json"
        CP_ECH_PUBLIC_CONFIG="$pc"
    fi

    CP_ECH_KEY_PATH="/etc/xray/ech/server-keys.txt"
    step_ok "${LANG[ECH_KEYGEN_OK]}"; return 0
}

ensure_ech_subscription_templates() {
    local domain_url=$1 token=$2 ech_b64="$3"
    [ -z "$ech_b64" ] && { echo -e "${COLOR_YELLOW}${LANG[ECH_TEMPLATE_NO_KEY]}${COLOR_RESET}"; return 1; }
    step_do "${LANG[ECH_TEMPLATE_SETUP]}"
    local list
    list=$(make_api_request "GET" "http://$domain_url/api/subscription-templates" "$token")
    if [ -z "$list" ] || ! echo "$list" | jq -e '.response.templates' >/dev/null 2>&1; then
        echo -e "${COLOR_YELLOW}${LANG[ECH_TEMPLATE_FETCH_FAIL]}${COLOR_RESET}"; return 1
    fi
    local uuids
    uuids=$(echo "$list" | jq -r '.response.templates[]? | select(.templateType=="XRAY_JSON") | .uuid')
    [ -z "$uuids" ] && { echo -e "${COLOR_YELLOW}${LANG[ECH_TEMPLATE_NONE_XRAYJSON]}${COLOR_RESET}"; return 1; }
    local uuid tpl name body patched ub resp
    local updated=0 skipped=0 failed=0
    for uuid in $uuids; do
        tpl=$(make_api_request "GET" "http://$domain_url/api/subscription-templates/$uuid" "$token")
        [ -z "$tpl" ] && { failed=$((failed+1)); continue; }
        name=$(echo "$tpl" | jq -r '.response.name // empty')
        body=$(echo "$tpl" | jq -c '.response.templateJson // empty')
        if [ -z "$body" ] || [ "$body" = "null" ]; then failed=$((failed+1)); continue; fi
        if printf '%s' "$body" | jq -e '[.. | objects | select(has("echConfigList"))] | length > 0' >/dev/null 2>&1; then
            skipped=$((skipped+1)); continue
        fi
        patched=$(printf '%s' "$body" | jq -c --arg e "$ech_b64" \
            '(.. | objects | select(has("serverName") and (has("echConfigList") | not))) |= . + {echConfigList: $e}' 2>/dev/null)
        if [ -z "$patched" ] || [ "$patched" = "$body" ]; then skipped=$((skipped+1)); continue; fi
        ub=$(jq -n --arg u "$uuid" --argjson b "$patched" '{uuid:$u, templateJson:$b}')
        resp=$(make_api_request "PATCH" "http://$domain_url/api/subscription-templates" "$token" "$ub")
        if echo "$resp" | jq -e '.response.uuid' >/dev/null 2>&1; then
            step_ok "$(printf "${LANG[ECH_TEMPLATE_UPDATED]}" "$name")"; updated=$((updated+1))
        else
            echo -e "${COLOR_YELLOW}$(printf "${LANG[ECH_TEMPLATE_UPDATE_FAIL]}" "$name")${COLOR_RESET}"; failed=$((failed+1))
        fi
    done
    printf "${COLOR_GRAY}${LANG[ECH_TEMPLATE_SUMMARY]}${COLOR_RESET}\n" "$updated" "$skipped" "$failed"
    [ "$failed" -eq 0 ]
}

check_node_domain() {
    local domain_url="$1" token="$2" domain="$3"
    local r
    r=$(make_api_request "GET" "http://$domain_url/api/nodes" "$token")
    if [ -z "$r" ]; then echo -e "${COLOR_RED}${LANG[ERROR_CHECK_DOMAIN]}${COLOR_RESET}"; return 1; fi
    if echo "$r" | jq -e '.response' >/dev/null 2>&1; then
        local ex
        ex=$(echo "$r" | jq -r --arg a "$domain" '.response[] | select(.address==$a) | .address' 2>/dev/null)
        if [ -n "$ex" ]; then echo -e "${COLOR_RED}${LANG[DOMAIN_ALREADY_EXISTS]}: $domain${COLOR_RESET}"; return 1; fi
        return 0
    fi
    local msg; msg=$(echo "$r" | jq -r '.message // "Unknown error"')
    echo -e "${COLOR_RED}${LANG[ERROR_CHECK_DOMAIN]}: $msg${COLOR_RESET}"
    return 1
}

create_node() {
    local domain_url=$1 token=$2 cp=$3 ib=$4 addr="${5:-172.30.0.1}" name="${6:-Steal}" plug="${7:-}"
    step_do "${LANG[CREATING_NODE]}"
    local pf=""; [ -n "$plug" ] && pf="\"activePluginUuid\": \"$plug\","
    local nd
    nd=$(cat <<EOF
{"name":"$name","address":"$addr","port":2222,
"configProfile":{"activeConfigProfileUuid":"$cp","activeInbounds":["$ib"]},
$pf
"isTrafficTrackingActive":false,"trafficLimitBytes":0,"notifyPercent":0,
"trafficResetDay":31,"countryCode":"XX","consumptionMultiplier":1.0}
EOF
)
    local r; r=$(make_api_request "POST" "http://$domain_url/api/nodes" "$token" "$nd")
    if echo "$r" | jq -e '.response.uuid' >/dev/null 2>&1; then step_ok "${LANG[NODE_CREATED]}"; return 0; fi
    [ -z "$r" ] && echo -e "${COLOR_RED}${LANG[ERROR_EMPTY_RESPONSE_NODE]}${COLOR_RESET}" || echo -e "${COLOR_RED}${LANG[ERROR_CREATE_NODE]}: $r${COLOR_RESET}"
    return 1
}

get_config_profiles() {
    local domain_url="$1" token="$2"
    local r; r=$(make_api_request "GET" "http://$domain_url/api/config-profiles" "$token")
    if [ -z "$r" ] || ! echo "$r" | jq -e '.' >/dev/null 2>&1; then err_msg "${LANG[ERROR_NO_CONFIGS]}"; return 1; fi
    local u
    u=$(echo "$r" | jq -r '.response.configProfiles[] | select(.name=="Default-Profile") | .uuid' 2>/dev/null)
    [ -z "$u" ] && { echo -e "${COLOR_YELLOW}${LANG[NO_DEFAULT_PROFILE]}${COLOR_RESET}" >&2; return 0; }
    echo "$u"; return 0
}

delete_config_profile() {
    local domain_url="$1" token="$2" uuid="$3"
    if [ -z "$uuid" ]; then
        uuid=$(get_config_profiles "$domain_url" "$token")
        if [ $? -ne 0 ] || [ -z "$uuid" ]; then return 0; fi
    fi
    local r
    r=$(make_api_request "DELETE" "http://$domain_url/api/config-profiles/$uuid" "$token")
    [ -z "$r" ] && return 0
    echo "$r" | jq -e '.' >/dev/null 2>&1 || { echo -e "${COLOR_RED}${LANG[ERROR_DELETE_PROFILE]}${COLOR_RESET}"; return 1; }
    return 0
}

create_config_profile() {
    local domain_url=$1 token=$2
    local name="$CP_PROFILE_NAME" tag="$CP_INBOUND_TAG"
    local dd="$CP_DIRECT_DOMAIN" dc="$CP_DIRECT_CERT"
    local pc="${CP_PANEL_CERT:-}"
    local tc="${CP_TINYAUTH_CERT:-}"
    local ech_path="${CP_ECH_KEY_PATH:-}" ech_b64="${CP_ECH_SERVER_KEYS_B64:-}"

    step_do "${LANG[CREATING_CONFIG_PROFILE]}" >&2
    if [ -z "$name" ] || [ -z "$dd" ] || [ -z "$dc" ]; then
        err_msg "${LANG[ERROR_CREATE_CONFIG_PROFILE]}: missing CP_* globals"; return 1
    fi
    if [ -z "$tag" ]; then err_msg "${LANG[ERROR_CREATE_CONFIG_PROFILE]}: CP_INBOUND_TAG empty"; return 1; fi
    case "$tag" in *,*) err_msg "${LANG[ERROR_CREATE_CONFIG_PROFILE]}: CP_INBOUND_TAG has comma"; return 1;; esac

    local certs_json
    certs_json=$(jq -n --arg dc "$dc" --arg pc "$pc" --arg tc "$tc" '
        ([{certificateFile:("/etc/letsencrypt/live/"+$dc+"/fullchain.pem"),keyFile:("/etc/letsencrypt/live/"+$dc+"/privkey.pem"),ocspStapling:3600}]
         + (if $pc!="" then [{certificateFile:("/etc/letsencrypt/live/"+$pc+"/fullchain.pem"),keyFile:("/etc/letsencrypt/live/"+$pc+"/privkey.pem"),ocspStapling:3600}] else [] end)
         + (if $tc!="" then [{certificateFile:("/etc/letsencrypt/live/"+$tc+"/fullchain.pem"),keyFile:("/etc/letsencrypt/live/"+$tc+"/privkey.pem"),ocspStapling:3600}] else [] end))
        | unique_by(.certificateFile)')

    local tls_json
    local tls_base='{minVersion:"1.2",cipherSuites:"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",alpn:["h2","http/1.1"]}'
    if [ -n "$ech_b64" ]; then
        tls_json=$(jq -n --argjson c "$certs_json" --arg e "$ech_b64" --argjson b "$tls_base" '$b + {certificates:$c,echServerKeys:$e}')
    elif [ -n "$ech_path" ]; then
        echo -e "${COLOR_YELLOW}${LANG[ECH_KEYGEN_FAIL]}: server keys b64 missing, using TLS without ECH${COLOR_RESET}" >&2
        tls_json=$(jq -n --argjson c "$certs_json" --argjson b "$tls_base" '$b + {certificates:$c}')
    else
        tls_json=$(jq -n --argjson c "$certs_json" --argjson b "$tls_base" '$b + {certificates:$c}')
    fi

    local fbs
    fbs=$(jq -n --arg sn "$dd" '[
        {name:$sn,alpn:"h2",dest:"@vless-xhttp"},
        {name:$sn,path:"/vlws",dest:"@vless-ws",xver:2},
        {name:$sn,path:"/vhu",dest:"@vless-hu",xver:2},
        {name:$sn,path:"/vxh",dest:"@vless-xhttp"},
        {name:$sn,path:"/vltc",dest:"@vless-tcp-obfs",xver:2},
        {name:$sn,path:"/trws",dest:"@trojan-ws",xver:2},
        {name:$sn,path:"/thu",dest:"@trojan-hu",xver:2},
        {name:$sn,path:"/trtc",dest:"@trojan-tcp-obfs",xver:2},
        {name:$sn,path:"/ssws",dest:4001},
        {name:$sn,path:"/sstc",dest:4002},
        {dest:"/dev/shm/nginx.sock",xver:2}]')

    local body
    body=$(jq -n --arg name "$name" --arg tag "$tag" --argjson fbs "$fbs" --argjson tls "$tls_json" '
    {name:$name,config:{
        log:{loglevel:"warning"},
        dns:{queryStrategy:"UseIPv4",servers:[{address:"https://dns.google/dns-query",skipFallback:false}]},
        inbounds:[
            {tag:$tag,port:443,protocol:"vless",
             settings:{clients:[],decryption:"none",fallbacks:$fbs},
             sniffing:{enabled:true,destOverride:["http","tls","quic"]},
             streamSettings:{network:"tcp",security:"tls",tlsSettings:$tls}},
            {tag:($tag+"-vless-ws"),listen:"@vless-ws",protocol:"vless",
             settings:{clients:[],decryption:"none"},
             streamSettings:{network:"ws",security:"none",wsSettings:{acceptProxyProtocol:true,path:"/vlws"}},
             sniffing:{enabled:true,destOverride:["http","tls"]}},
            {tag:($tag+"-vless-hu"),listen:"@vless-hu",protocol:"vless",
             settings:{clients:[],decryption:"none"},
             streamSettings:{network:"httpupgrade",security:"none",httpupgradeSettings:{acceptProxyProtocol:true,path:"/vhu"}},
             sniffing:{enabled:true,destOverride:["http","tls"]}},
            {tag:($tag+"-vless-xhttp"),listen:"@vless-xhttp",protocol:"vless",
             settings:{clients:[],decryption:"none"},
             streamSettings:{network:"xhttp",security:"none",xhttpSettings:{path:"/vxh",mode:"auto"}},
             sniffing:{enabled:true,destOverride:["http","tls"]}},
            {tag:($tag+"-vless-tcp-obfs"),listen:"@vless-tcp-obfs",protocol:"vless",
             settings:{clients:[],decryption:"none"},
             streamSettings:{network:"tcp",security:"none",tcpSettings:{acceptProxyProtocol:true,header:{type:"http",request:{path:["/vltc"]}}}},
             sniffing:{enabled:true,destOverride:["http","tls"]}},
            {tag:($tag+"-trojan-ws"),listen:"@trojan-ws",protocol:"trojan",
             settings:{clients:[]},
             streamSettings:{network:"ws",security:"none",wsSettings:{acceptProxyProtocol:true,path:"/trws"}},
             sniffing:{enabled:true,destOverride:["http","tls"]}},
            {tag:($tag+"-trojan-hu"),listen:"@trojan-hu",protocol:"trojan",
             settings:{clients:[]},
             streamSettings:{network:"httpupgrade",security:"none",httpupgradeSettings:{acceptProxyProtocol:true,path:"/thu"}},
             sniffing:{enabled:true,destOverride:["http","tls"]}},
            {tag:($tag+"-trojan-tcp-obfs"),listen:"@trojan-tcp-obfs",protocol:"trojan",
             settings:{clients:[]},
             streamSettings:{network:"tcp",security:"none",tcpSettings:{acceptProxyProtocol:true,header:{type:"http",request:{path:["/trtc"]}}}},
             sniffing:{enabled:true,destOverride:["http","tls"]}},
            {tag:($tag+"-ss-ws"),listen:"127.0.0.1",port:4001,protocol:"shadowsocks",
             settings:{method:"chacha20-ietf-poly1305",clients:[]},
             streamSettings:{network:"ws",security:"none",wsSettings:{path:"/ssws"}},
             sniffing:{enabled:true,destOverride:["http","tls"]}},
            {tag:($tag+"-ss-tcp-obfs"),listen:"127.0.0.1",port:4002,protocol:"shadowsocks",
             settings:{method:"chacha20-ietf-poly1305",clients:[]},
             streamSettings:{network:"tcp",security:"none",tcpSettings:{header:{type:"http",request:{path:["/sstc"]}}}},
             sniffing:{enabled:true,destOverride:["http","tls"]}}
        ],
        outbounds:[{tag:"DIRECT",protocol:"freedom"},{tag:"BLOCK",protocol:"blackhole"}],
        routing:{rules:[{ip:["geoip:private"],outboundTag:"BLOCK"},{protocol:["bittorrent"],outboundTag:"BLOCK"}]}
    }}')

    local r
    r=$(make_api_request "POST" "http://$domain_url/api/config-profiles" "$token" "$body")
    if [ -z "$r" ] || ! echo "$r" | jq -e '.response.uuid' >/dev/null 2>&1; then
        err_msg "${LANG[ERROR_CREATE_CONFIG_PROFILE]}: $r"; return 1
    fi
    local cu
    cu=$(echo "$r" | jq -r '.response.uuid')
    if [ -z "$cu" ] || [ "$cu" = "null" ]; then
        err_msg "${LANG[ERROR_CREATE_CONFIG_PROFILE]}: missing config uuid"; return 1
    fi
    echo "$cu"
    echo "$r" | jq -r '.response.inbounds[]? | select(.tag and .uuid) | "\(.tag):\(.uuid)"'
    step_ok "${LANG[CONFIG_PROFILE_CREATED]}" >&2
    return 0
}

create_host() {
    local domain_url=$1 token=$2 iu=$3 addr=$4 cu=$5
    local remark="${6:-Steal}" host_tag="${7:-}" is_hidden="${8:-false}"
    local hpath="${9:-}"
    step_do "${LANG[CREATE_HOST]}"

    if [ -n "$host_tag" ]; then
        host_tag=$(printf '%s' "$host_tag" | tr '[:lower:]' '[:upper:]' | sed 's/[^A-Z0-9_:]/_/g' | sed 's/__*/_/g' | sed 's/^_//;s/_$//')
    fi

    local tags_json="[]"
    [ -n "$host_tag" ] && tags_json=$(jq -n --arg t "$host_tag" '[$t]')

    local body
    body=$(jq -n --arg cu "$cu" --arg iu "$iu" --arg r "$remark" --arg a "$addr" --arg p "$hpath" \
                  --argjson tags "$tags_json" --argjson hid "$is_hidden" \
        '{inbound:{configProfileUuid:$cu,configProfileInboundUuid:$iu},remark:$r,
          address:$a,port:443,path:$p,sni:$a,host:$a,alpn:null,fingerprint:"firefox",
          isDisabled:false,securityLayer:"DEFAULT",tags:$tags,isHidden:$hid}')

    local r
    r=$(make_api_request "POST" "http://$domain_url/api/hosts" "$token" "$body")
    if echo "$r" | jq -e '.response.uuid' >/dev/null 2>&1; then step_ok "${LANG[HOST_CREATED]}"; return 0; fi
    [ -z "$r" ] && echo -e "${COLOR_RED}${LANG[ERROR_EMPTY_RESPONSE_HOST]}${COLOR_RESET}" || echo -e "${COLOR_RED}${LANG[ERROR_CREATE_HOST]}: $r${COLOR_RESET}"
    return 1
}

get_default_squad() {
    local domain_url=$1 token=$2
    step_do "${LANG[GET_DEFAULT_SQUAD]}" >&2
    local r; r=$(make_api_request "GET" "http://$domain_url/api/internal-squads" "$token")
    if [ -z "$r" ] || ! echo "$r" | jq -e '.response.internalSquads' >/dev/null 2>&1; then
        err_msg "${LANG[ERROR_GET_SQUAD]}: $r"; return 1
    fi
    local sq; sq=$(echo "$r" | jq -r '.response.internalSquads[].uuid' 2>/dev/null)
    [ -z "$sq" ] && return 0
    local valid=""
    while IFS= read -r uuid; do
        [ -z "$uuid" ] && continue
        if [[ $uuid =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
            valid+="$uuid\n"
        fi
    done <<< "$sq"
    [ -z "$valid" ] && return 0
    echo -e "$valid" | sed '/^$/d'; return 0
}

update_squad() {
    local domain_url=$1 token=$2 su=$3 iu=$4
    if [[ ! $su =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
        echo -e "${COLOR_RED}${LANG[INVALID_SQUAD_UUID]}: $su${COLOR_RESET}"; return 1
    fi
    if [[ ! $iu =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
        echo -e "${COLOR_RED}${LANG[INVALID_INBOUND_UUID]}: $iu${COLOR_RESET}"; return 1
    fi
    local sr; sr=$(make_api_request "GET" "http://$domain_url/api/internal-squads" "$token")
    if [ -z "$sr" ] || ! echo "$sr" | jq -e '.response.internalSquads' >/dev/null 2>&1; then
        echo -e "${COLOR_RED}${LANG[ERROR_GET_SQUAD]}: $sr${COLOR_RESET}"; return 1
    fi
    local ei
    ei=$(echo "$sr" | jq -r --arg u "$su" '.response.internalSquads[] | select(.uuid==$u) | .inbounds[].uuid' 2>/dev/null)
    if [ -z "$ei" ]; then ei="[]"; else ei=$(echo "$ei" | jq -R . | jq -s .); fi
    local arr body r
    arr=$(jq -n --argjson e "$ei" --arg n "$iu" '$e + [$n] | unique')
    body=$(jq -n --arg u "$su" --argjson i "$arr" '{uuid:$u,inbounds:$i}')
    r=$(make_api_request "PATCH" "http://$domain_url/api/internal-squads" "$token" "$body")
    if [ -z "$r" ] || ! echo "$r" | jq -e '.response.uuid' >/dev/null 2>&1; then
        echo -e "${COLOR_RED}${LANG[ERROR_UPDATE_SQUAD]}: $r${COLOR_RESET}"; return 1
    fi
    step_ok "${LANG[UPDATE_SQUAD]}"; return 0
}

create_api_token() {
    local domain_url=$1 token=$2 target_dir=$3 token_name="${4:-subscription-page}"
    step_do "${LANG[CREATING_API_TOKEN]}" >&2
    local td r at
    td='{"name":"'"$token_name"'","expiresInDays":3650,"scopes":["subscription-page-configs:list","subscription-page-configs:get","subscriptions:subpage-config","system:metadata","users:by-username"]}'
    r=$(make_api_request "POST" "http://$domain_url/api/tokens" "$token" "$td")
    at=$(echo "$r" | jq -r '.response.token // ""')
    if [ -z "$at" ] || [ "$at" = "null" ]; then
        td='{"name":"'"$token_name"'","expiresInDays":3650,"scopes":["*"]}'
        r=$(make_api_request "POST" "http://$domain_url/api/tokens" "$token" "$td")
        at=$(echo "$r" | jq -r '.response.token // ""')
    fi
    if [ -z "$at" ] || [ "$at" = "null" ]; then
        echo -e "${COLOR_RED}${LANG[ERROR_CREATE_API_TOKEN]}: $(echo "$r" | jq -r '.message // "Unknown error"')" >&2
        return 1
    fi
    local ef="$target_dir/.env"
    if [ -f "$ef" ]; then
        if grep -q '^api_token=' "$ef"; then
            sed -i "s|^api_token=.*|api_token=$at|" "$ef"
        else
            [ -n "$(tail -c1 "$ef" 2>/dev/null)" ] && printf '\n' >> "$ef"
            printf 'api_token=%s\n' "$at" >> "$ef"
        fi
        chmod 600 "$ef" 2>/dev/null
    fi
    if grep -qE 'REMNAWAVE_API_TOKEN=[^$[:space:]]' "$target_dir/docker-compose.yml" 2>/dev/null; then
        sed -i "s|REMNAWAVE_API_TOKEN=.*|REMNAWAVE_API_TOKEN=$at|" "$target_dir/docker-compose.yml"
    fi
    sleep 1
    step_ok "${LANG[API_TOKEN_ADDED]}" >&2
    return 0
}
ENDOFFILE

bash -n /usr/local/remnawave_reverse/api/remnawave_api.sh && echo "SYNTAX OK"