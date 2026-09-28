#!/bin/bash
# Module: Remnawave API Functions
#
# Design A:
#   Xray terminates TLS on 443 for every SNI and holds every certificate plus
#   the static ECH key. The webserver (nginx or caddy) sits on a cleartext
#   unix socket behind Xray and holds no certificate at all.
#
# ECH:
#   One static server keypair is generated once and persisted under
#   <install_dir>/ech/. It is never rotated. The public ECHConfigList is
#   injected into every XRAY_JSON subscription template so clients receive it
#   automatically, and published as an HTTPS DNS record for the direct
#   hostname.
#
# All-in-one fallbacks on 443 (VLESS primary inbound):
#   /vlws  → VLESS WS
#   /vhu   → VLESS HTTPUpgrade
#   /vxh   → VLESS XHTTP
#   /vltc  → VLESS TCP + HTTP obfs
#   /trws  → Trojan WS
#   /thu   → Trojan HTTPUpgrade
#   /trtc  → Trojan TCP + HTTP obfs
#   /ssws  → Shadowsocks WS        (loopback 4001)
#   /sstc  → Shadowsocks TCP obfs  (loopback 4002)
#   *      → /dev/shm/nginx.sock   (cleartext webserver behind Xray)
#
# Every inbound declared in create_config_profile carries a unique tag
# derived from the primary inbound tag. Remnawave's ConfigProfileInbounds
# table has a GLOBAL unique constraint on tag (@@unique([tag])), so
# hardcoded fallback tags would make the second profile (a second node added
# via add_node.sh) fail with A113. Deriving "Steal-vless-ws" from "Steal"
# keeps the whole set unique per profile and globally unique across profiles.

err_msg() {
    echo -e "${COLOR_RED}$*${COLOR_RESET}" >&2
}

make_api_request() {
    local method=$1
    local url=$2
    local token=$3
    local data=$4

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

# ---------------------------------------------------------------------------
# Token introspection and minting
# ---------------------------------------------------------------------------

rw_token_is_api() {
    local tok="$1"
    [ -n "$tok" ] || return 1
    local payload
    payload=$(printf '%s' "$tok" | cut -d. -f2)
    payload="${payload//-/+}"
    payload="${payload//_/\/}"
    case $(( ${#payload} % 4 )) in
        2) payload="${payload}==" ;;
        3) payload="${payload}=" ;;
    esac
    local role
    role=$(printf '%s' "$payload" | base64 -d 2>/dev/null | jq -r '.role // empty' 2>/dev/null)
    [ "$role" = "API" ]
}

mint_script_api_token() {
    local domain_url="$1" token="$2"
    local list uuid body resp
    list=$(make_api_request "GET" "http://$domain_url/api/tokens" "$token")
    uuid=$(echo "$list" | jq -r '.response.tokens[]? | select(.name == "remnawave-reverse-proxy") | .uuid' 2>/dev/null | head -n1)
    if [ -n "$uuid" ] && [ "$uuid" != "null" ]; then
        make_api_request "DELETE" "http://$domain_url/api/tokens/$uuid" "$token" >/dev/null
    fi
    body=$(jq -n '{name:"remnawave-reverse-proxy", expiresInDays:3650, scopes:["*"]}')
    resp=$(make_api_request "POST" "http://$domain_url/api/tokens" "$token" "$body")
    echo "$resp" | jq -r '.response.token // empty'
}

# Persist the panel token to <install_dir>/token. Self-contained: does not
# depend on TOKEN_FILE being set by the caller; takes the token, not a URL.
persist_script_api_token() {
    local tok="${!#}"
    [ -n "$tok" ] || return 1
    case "$tok" in
        http*) return 1 ;;   # caller still passing a URL as the last arg
    esac
    local file="${TOKEN_FILE:-${DIR_REMNAWAVE}/token}"
    mkdir -p "$(dirname "$file")" 2>/dev/null
    printf '%s' "$tok" > "$file"
    chmod 600 "$file" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Panel registration, login, key retrieval
# ---------------------------------------------------------------------------

register_remnawave() {
    local domain_url=$1
    local username=$2
    local password=$3
    local token=$4

    local register_data
    register_data=$(jq -n --arg u "$username" --arg p "$password" '{username:$u,password:$p}')
    step_do "${LANG[REGISTERING_REMNAWAVE]}" >&2
    local register_response
    register_response=$(make_api_request "POST" "http://$domain_url/api/auth/register" "$token" "$register_data")

    if [ -z "$register_response" ]; then
        err_msg "${LANG[ERROR_EMPTY_RESPONSE_REGISTER]}"
        return 1
    elif [[ "$register_response" == *"accessToken"* ]]; then
        step_ok "${LANG[REGISTRATION_SUCCESS]}" >&2
        echo "$register_response" | jq -r '.response.accessToken'
        return 0
    else
        err_msg "${LANG[ERROR_REGISTER]}: $register_response"
        return 1
    fi
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
        c1=$(echo "$line" | grep -oP '~*\K\w+(?==)')
        c2=$(echo "$line" | grep -oP '=\K\w+(?=")')
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

    local auth_status
    auth_status=$(make_api_request "GET" "http://${domain_url}/api/auth/status" "")
    local oauth_enabled=false
    local oauth_providers=""

    if [ -n "$auth_status" ]; then
        local github_enabled yandex_enabled pocketid_enabled telegram_enabled
        github_enabled=$(echo "$auth_status" | jq -r '.response.authentication.oauth2.providers.github // false' 2>/dev/null)
        yandex_enabled=$(echo "$auth_status" | jq -r '.response.authentication.oauth2.providers.yandex // false' 2>/dev/null)
        pocketid_enabled=$(echo "$auth_status" | jq -r '.response.authentication.oauth2.providers.pocketid // false' 2>/dev/null)
        telegram_enabled=$(echo "$auth_status" | jq -r '.response.authentication.oauth2.providers.telegram // .response.authentication.tgAuth.enabled // false' 2>/dev/null)

        [ "$github_enabled" = "true" ] && oauth_providers+="GitHub, "
        [ "$yandex_enabled" = "true" ] && oauth_providers+="Yandex, "
        [ "$pocketid_enabled" = "true" ] && oauth_providers+="Pocket ID, "
        [ "$telegram_enabled" = "true" ] && oauth_providers+="Telegram, "
        if [ -n "$oauth_providers" ]; then
            oauth_enabled=true
            oauth_providers="${oauth_providers%, }"
        fi
    fi

    if [ -f "$TOKEN_FILE" ]; then
        token=$(cat "$TOKEN_FILE")
        echo -e "${COLOR_YELLOW}${LANG[USING_SAVED_TOKEN]}${COLOR_RESET}"
        local test_response
        test_response=$(make_api_request "GET" "http://${domain_url}/api/config-profiles" "$token")

        if [ -z "$test_response" ] || ! echo "$test_response" | jq -e '.response.configProfiles' > /dev/null 2>&1; then
            if echo "$test_response" | grep -q '"statusCode":401' || \
               echo "$test_response" | jq -e '.message | test("Unauthorized")' > /dev/null 2>&1; then
                echo -e "${COLOR_RED}${LANG[INVALID_SAVED_TOKEN]}${COLOR_RESET}"
            else
                echo -e "${COLOR_RED}${LANG[INVALID_SAVED_TOKEN]}: $test_response${COLOR_RESET}"
            fi
            token=""
        fi
    fi

    if [ -z "$token" ]; then
        if [ "$oauth_enabled" = true ]; then
            echo -e ""
            echo -e "${COLOR_RED}${LANG[WARNING_LABEL]}${COLOR_RESET}"
            printf "${COLOR_YELLOW}${LANG[OAUTH_ENABLED_WARNING]}${COLOR_RESET}\n" "$oauth_providers"
            printf "${COLOR_YELLOW}${LANG[CREATE_API_TOKEN_INSTRUCTION]}${COLOR_RESET}\n" "$(panel_login_url)"
            reading "${LANG[ENTER_API_TOKEN]}" token
            if [ -z "$token" ]; then
                echo -e "${COLOR_RED}${LANG[EMPTY_TOKEN_ERROR]}${COLOR_RESET}"
                return 1
            fi

            local test_response
            test_response=$(make_api_request "GET" "http://${domain_url}/api/config-profiles" "$token")
            if [ -z "$test_response" ] || ! echo "$test_response" | jq -e '.response.configProfiles' > /dev/null 2>&1; then
                echo -e "${COLOR_RED}${LANG[INVALID_SAVED_TOKEN]}: $test_response${COLOR_RESET}"
                return 1
            fi
        else
            reading "${LANG[ENTER_PANEL_USERNAME]}" username
            reading "${LANG[ENTER_PANEL_PASSWORD]}" password

            local login_data login_response
            login_data=$(jq -n --arg u "$username" --arg p "$password" '{username:$u,password:$p}')
            login_response=$(make_api_request "POST" "http://${domain_url}/api/auth/login" "" "$login_data")
            token=$(echo "$login_response" | jq -r '.response.accessToken // .accessToken // ""')
            if [ -z "$token" ] || [ "$token" == "null" ]; then
                echo -e "${COLOR_RED}${LANG[ERROR_TOKEN]}: $login_response${COLOR_RESET}"
                return 1
            fi
        fi

        if ! rw_token_is_api "$token"; then
            local api_tok
            api_tok=$(mint_script_api_token "$domain_url" "$token")
            if [ -n "$api_tok" ] && [ "$api_tok" != "null" ]; then
                token="$api_tok"
            fi
        fi

        persist_script_api_token "$token"
        echo -e "${COLOR_GREEN}${LANG[TOKEN_RECEIVED_AND_SAVED]}${COLOR_RESET}"
    else
        echo -e "${COLOR_GREEN}${LANG[TOKEN_USED_SUCCESSFULLY]}${COLOR_RESET}"
    fi

    local final_test_response
    final_test_response=$(make_api_request "GET" "http://${domain_url}/api/config-profiles" "$token")
    if [ -z "$final_test_response" ] || ! echo "$final_test_response" | jq -e '.response.configProfiles' > /dev/null 2>&1; then
        echo -e "${COLOR_RED}${LANG[INVALID_SAVED_TOKEN]}: $final_test_response${COLOR_RESET}"
        return 1
    fi
}

get_public_key() {
    local domain_url=$1
    local token=$2
    local target_dir=$3

    step_do "${LANG[GET_PUBLIC_KEY]}"
    local api_response
    api_response=$(make_api_request "GET" "http://$domain_url/api/keygen" "$token")

    if [ -z "$api_response" ]; then
        echo -e "${COLOR_RED}${LANG[ERROR_PUBLIC_KEY]}${COLOR_RESET}"
        return 1
    fi

    local pubkey
    pubkey=$(echo "$api_response" | jq -r '.response.secretKey // .response.pubKey // empty')
    if [ -z "$pubkey" ] || [ "$pubkey" = "null" ]; then
        echo -e "${COLOR_RED}${LANG[ERROR_EXTRACT_PUBLIC_KEY]}: $api_response${COLOR_RESET}"
        return 1
    fi

    # The secretKey is itself a JSON document. sed-ing it into a
    # double-quoted YAML scalar produces `SECRET_KEY="{"..."}"`, which
    # docker compose cannot parse. Go through a real YAML-safe single-quoted
    # scalar instead: single quotes around the value keep the inner double
    # quotes literal, and any literal single quote in the JSON is doubled.
    local compose="$target_dir/docker-compose.yml"
    local escaped
    escaped=$(printf '%s' "$pubkey" | sed "s/'/''/g")

    if command -v python3 >/dev/null 2>&1; then
        python3 - "$compose" "$pubkey" <<'PY'
import io, re, sys
path, value = sys.argv[1], sys.argv[2]
with io.open(path, 'r', encoding='utf-8') as f:
    src = f.read()
pattern = re.compile(r'^(\s*-\s*SECRET_KEY=).*$', re.MULTILINE)
replacement = r'\1' + "'" + value.replace("'", "''") + "'"
new, n = pattern.subn(replacement, src)
if n == 0:
    sys.exit("SECRET_KEY line not found in " + path)
with io.open(path, 'w', encoding='utf-8') as f:
    f.write(new)
PY
    else
        # No python3: the sed path emits a single-quoted scalar with the
        # same escaping rules. Same end result, less robust against exotic
        # JSON, but the secretKey is machine-generated base64/JSON and
        # contains no single quotes in practice.
        sed -i "s|SECRET_KEY=.*|SECRET_KEY='${escaped}'|" "$compose"
    fi

    step_ok "${LANG[PUBLIC_KEY_SUCCESS]}"
}

# Kept for backward compatibility with callers that still expect it.
generate_xray_keys() {
    local domain_url=$1
    local token=$2

    step_do "${LANG[GENERATE_KEYS]}" >&2
    local api_response
    api_response=$(make_api_request "GET" "http://$domain_url/api/system/tools/x25519/generate" "$token")

    if [ -z "$api_response" ]; then
        err_msg "${LANG[ERROR_GENERATE_KEYS]}"
        return 1
    fi

    if echo "$api_response" | jq -e '.errorCode' > /dev/null 2>&1; then
        local error_message
        error_message=$(echo "$api_response" | jq -r '.message')
        err_msg "${LANG[ERROR_GENERATE_KEYS]}: $error_message"
        return 1
    fi

    local private_key
    private_key=$(echo "$api_response" | jq -r '.response.keypairs[0].privateKey')
    if [ -z "$private_key" ] || [ "$private_key" = "null" ]; then
        err_msg "${LANG[ERROR_EXTRACT_PRIVATE_KEY]}"
        return 1
    fi

    step_ok "${LANG[GENERATE_KEYS_SUCCESS]}" >&2
    echo "$private_key"
    return 0
}

# ---------------------------------------------------------------------------
# Static ECH key management
#
# `xray tls ech --serverName <name>` prints a human-readable report:
#
#     ECH Config:
#     AEX+DQBB...
#     ECH server keys:
#     ACATwY30o/RKgD6hgeQxwrSiApLaCgU+HKh7B6SUrAHaDwBD/g0APwAAIAAgHjzK...
#
# Xray's echServerKeys field wants the base64 key blob VERBATIM — no labels,
# no "ECH server keys:" prefix, no blank lines, no embedded newlines.
# Writing the whole CLI output to the file makes Xray's base64 decoder choke
# and the core refuses to start with:
#     Failed to build TLS config. > infra/conf: invalid ECH Config...
#
# The public ECHConfigList is the other base64 blob, extracted separately and
# injected into XRAY_JSON subscription templates. It too must be the raw
# base64 with nothing prepended.
#
# Host layout (target_dir is /opt/remnawave or /opt/remnanode):
#   ech/server-keys.txt     base64 key blob only, bind-mounted into Xray
#   ech/client-config.txt   base64 ECHConfigList
#   ech/client-config.json  public config as a small JSON object
#
# Sets on success:
#   CP_ECH_KEY_PATH        container path of the private key file, or ""
#   CP_ECH_PUBLIC_CONFIG   base64 ECHConfigList, or ""
# ---------------------------------------------------------------------------
ensure_ech_server_keys() {
    local target_dir="$1"
    local selfsteal_domain="$2"
    local ech_dir="$target_dir/ech"
    local server_file="$ech_dir/server-keys.txt"
    local client_file="$ech_dir/client-config.txt"
    local client_json="$ech_dir/client-config.json"

    CP_ECH_KEY_PATH=""
    CP_ECH_PUBLIC_CONFIG=""

    mkdir -p "$ech_dir"
    chmod 750 "$ech_dir"

    # A previously-generated key is reused as-is. If the file is present but
    # obviously malformed (contains whitespace or a colon, i.e. a label or a
    # newline), it is treated as stale and regenerated — that path repairs an
    # install broken by the old writer without a manual rm.
    if [ -s "$server_file" ] && ! LC_ALL=C grep -qE '[^A-Za-z0-9+/=]' "$server_file"; then
        CP_ECH_KEY_PATH="/etc/xray/ech/server-keys.txt"
        [ -s "$client_file" ] && CP_ECH_PUBLIC_CONFIG=$(cat "$client_file")
        step_ok "${LANG[ECH_KEYGEN_REUSED]}"
        return 0
    fi

    step_do "${LANG[ECH_KEYGEN]}"

    if ! docker image inspect remnawave/node:latest >/dev/null 2>&1; then
        docker pull remnawave/node:latest >/dev/null 2>&1 || true
    fi

    if ! docker image inspect remnawave/node:latest >/dev/null 2>&1; then
        echo -e "${COLOR_YELLOW}${LANG[ECH_KEYGEN_IMG_MISSING]}${COLOR_RESET}"
        return 1
    fi

    local raw_output
    raw_output=$(docker run --rm --entrypoint /usr/local/bin/xray \
        remnawave/node:latest tls ech --serverName "$selfsteal_domain" 2>/dev/null)

    if [ -z "$raw_output" ]; then
        echo -e "${COLOR_YELLOW}${LANG[ECH_KEYGEN_FAIL]}${COLOR_RESET}"
        return 1
    fi

    # --- server key blob -------------------------------------------------
    # Take whatever follows "ECH server keys:" and strip ALL whitespace and
    # any stray label characters. What remains must be pure base64.
    local key_b64
    key_b64=$(printf '%s\n' "$raw_output" \
        | sed -n '/ECH server keys:/,$p' \
        | tail -n +2 \
        | tr -d '[:space:]:')
    # If the label sits on the same line as the blob (output format varies
    # between Xray tags), fall back to stripping the label prefix in place.
    if [ -z "$key_b64" ]; then
        key_b64=$(printf '%s\n' "$raw_output" \
            | sed -n 's/.*ECH server keys:[[:space:]]*//p' \
            | tr -d '[:space:]:')
    fi
    # Last resort: the longest base64-looking run in the output. This is the
    # key blob; the config blob is shorter and appears earlier.
    if [ -z "$key_b64" ]; then
        key_b64=$(printf '%s\n' "$raw_output" \
            | grep -oE '[A-Za-z0-9+/=]{40,}' \
            | sort -u | awk '{ print length, $0 }' | sort -rn | head -n1 | cut -d' ' -f2-)
    fi

    if [ -z "$key_b64" ]; then
        echo -e "${COLOR_YELLOW}${LANG[ECH_KEYGEN_FAIL]}${COLOR_RESET}"
        return 1
    fi

    # No trailing newline: Xray's decoder is fed the file byte-for-byte, and
    # a newline is not part of base64.StdEncoding's alphabet.
    printf '%s' "$key_b64" > "$server_file"
    chmod 640 "$server_file"

    # --- public ECHConfigList --------------------------------------------
    local public_cfg
    public_cfg=$(printf '%s\n' "$raw_output" \
        | sed -n '/ECH Config:/,/ECH server keys:/p' \
        | sed '1d;$d' \
        | tr -d '[:space:]:')
    if [ -z "$public_cfg" ]; then
        public_cfg=$(printf '%s\n' "$raw_output" \
            | sed -n 's/.*ECH Config:[[:space:]]*//p' \
            | tr -d '[:space:]:')
    fi
    if [ -z "$public_cfg" ]; then
        public_cfg=$(printf '%s\n' "$raw_output" \
            | grep -oE 'AEX[A-Za-z0-9+/=_-]+' | head -n1)
    fi

    if [ -n "$public_cfg" ]; then
        printf '%s' "$public_cfg" > "$client_file"
        chmod 644 "$client_file"
        jq -n --arg ech "$public_cfg" '{ echConfigList: $ech }' > "$client_json"
        chmod 644 "$client_json"
        CP_ECH_PUBLIC_CONFIG="$public_cfg"
    fi

    CP_ECH_KEY_PATH="/etc/xray/ech/server-keys.txt"
    step_ok "${LANG[ECH_KEYGEN_OK]}"
    return 0
}

# ---------------------------------------------------------------------------
# Subscription template injection
#
# Every XRAY_JSON subscription template body is patched to carry the static
# ECHConfigList inside its tlsSettings blocks. The anchor is any object that
# has a "serverName" but no "echConfigList"; injection adds a sibling
# "echConfigList" key. Idempotent: templates that already carry the key are
# skipped.
#
# Done in jq, not sed: the ECHConfigList is base64, which contains '/' and
# '+' and '=' — the previous `sed -e "s/…/…$ech_base64…/"` used '/' as its
# delimiter and silently corrupted (or emptied) any template whenever the
# key happened to contain a slash.
# ---------------------------------------------------------------------------
ensure_ech_subscription_templates() {
    local domain_url=$1
    local token=$2
    local ech_base64="$3"

    if [ -z "$ech_base64" ]; then
        echo -e "${COLOR_YELLOW}${LANG[ECH_TEMPLATE_NO_KEY]}${COLOR_RESET}"
        return 1
    fi

    step_do "${LANG[ECH_TEMPLATE_SETUP]}"

    local list
    list=$(make_api_request "GET" "http://$domain_url/api/subscription-templates" "$token")
    if [ -z "$list" ] || ! echo "$list" | jq -e '.response.subscriptionTemplates' >/dev/null 2>&1; then
        echo -e "${COLOR_YELLOW}${LANG[ECH_TEMPLATE_FETCH_FAIL]}${COLOR_RESET}"
        return 1
    fi

    local uuids
    uuids=$(echo "$list" | jq -r '
        .response.subscriptionTemplates[]?
        | select(.templateType == "XRAY_JSON")
        | .uuid')

    if [ -z "$uuids" ]; then
        echo -e "${COLOR_YELLOW}${LANG[ECH_TEMPLATE_NONE_XRAYJSON]}${COLOR_RESET}"
        return 1
    fi

    local uuid tpl name tt body patched update_body resp
    local updated=0 skipped=0 failed=0

    for uuid in $uuids; do
        tpl=$(make_api_request "GET" "http://$domain_url/api/subscription-templates/$uuid" "$token")
        [ -z "$tpl" ] && { failed=$((failed+1)); continue; }

        name=$(echo "$tpl" | jq -r '.response.name // empty')
        tt=$(echo "$tpl" | jq -r '.response.templateType // "XRAY_JSON"')
        body=$(echo "$tpl" | jq -r '.response.templateJson // empty')
        [ -z "$body" ] && { failed=$((failed+1)); continue; }

        # Already carries echConfigList somewhere → nothing to do.
        if printf '%s' "$body" | jq -e '[.. | objects | select(has("echConfigList"))] | length > 0' >/dev/null 2>&1; then
            skipped=$((skipped+1))
            continue
        fi

        # Inject echConfigList as a sibling of every serverName that does
        # not already carry one. Recursive-descent update assignment.
        patched=$(printf '%s' "$body" | jq -c --arg ech "$ech_base64" '
            (.. | objects | select(has("serverName") and (has("echConfigList") | not)))
            |= . + {echConfigList: $ech}
        ' 2>/dev/null)

        if [ -z "$patched" ] || [ "$patched" = "$body" ]; then
            skipped=$((skipped+1))
            continue
        fi

        update_body=$(jq -n \
            --arg uuid "$uuid" \
            --arg name "$name" \
            --arg tt "$tt" \
            --arg body "$patched" \
            '{uuid: $uuid, name: $name, templateType: $tt, templateJson: $body}')

        resp=$(make_api_request "PATCH" "http://$domain_url/api/subscription-templates" "$token" "$update_body")
        if echo "$resp" | jq -e '.response.uuid' >/dev/null 2>&1; then
            step_ok "$(printf "${LANG[ECH_TEMPLATE_UPDATED]}" "$name")"
            updated=$((updated+1))
        else
            echo -e "${COLOR_YELLOW}$(printf "${LANG[ECH_TEMPLATE_UPDATE_FAIL]}" "$name")${COLOR_RESET}"
            failed=$((failed+1))
        fi
    done

    printf "${COLOR_GRAY}${LANG[ECH_TEMPLATE_SUMMARY]}${COLOR_RESET}\n" "$updated" "$skipped" "$failed"
    [ "$failed" -eq 0 ]
}

# ---------------------------------------------------------------------------
# Node / host / squad operations
# ---------------------------------------------------------------------------

check_node_domain() {
    local domain_url="$1"
    local token="$2"
    local domain="$3"

    local response
    response=$(make_api_request "GET" "http://$domain_url/api/nodes" "$token")
    if [ -z "$response" ]; then
        echo -e "${COLOR_RED}${LANG[ERROR_CHECK_DOMAIN]}${COLOR_RESET}"
        return 1
    fi

    if echo "$response" | jq -e '.response' > /dev/null 2>&1; then
        local existing_domain
        existing_domain=$(echo "$response" | jq -r --arg addr "$domain" '.response[] | select(.address == $addr) | .address' 2>/dev/null)
        if [ -n "$existing_domain" ]; then
            echo -e "${COLOR_RED}${LANG[DOMAIN_ALREADY_EXISTS]}: $domain${COLOR_RESET}"
            return 1
        fi
        return 0
    else
        local error_message
        error_message=$(echo "$response" | jq -r '.message // "Unknown error"')
        echo -e "${COLOR_RED}${LANG[ERROR_CHECK_DOMAIN]}: $error_message${COLOR_RESET}"
        return 1
    fi
}

create_node() {
    local domain_url=$1
    local token=$2
    local config_profile_uuid=$3
    local inbound_uuid=$4
    local node_address="${5:-172.30.0.1}"
    local node_name="${6:-Steal}"
    local plugin_uuid="${7:-}"

    step_do "${LANG[CREATING_NODE]}"
    local plugin_field=""
    [ -n "$plugin_uuid" ] && plugin_field="\"activePluginUuid\": \"$plugin_uuid\","
    local node_data
    node_data=$(cat <<EOF
{
    "name": "$node_name",
    "address": "$node_address",
    "port": 2222,
    "configProfile": {
        "activeConfigProfileUuid": "$config_profile_uuid",
        "activeInbounds": ["$inbound_uuid"]
    },
    $plugin_field
    "isTrafficTrackingActive": false,
    "trafficLimitBytes": 0,
    "notifyPercent": 0,
    "trafficResetDay": 31,
    "countryCode": "XX",
    "consumptionMultiplier": 1.0
}
EOF
)

    local node_response
    node_response=$(make_api_request "POST" "http://$domain_url/api/nodes" "$token" "$node_data")

    if echo "$node_response" | jq -e '.response.uuid' > /dev/null 2>&1; then
        step_ok "${LANG[NODE_CREATED]}"
        return 0
    fi

    if [ -z "$node_response" ]; then
        echo -e "${COLOR_RED}${LANG[ERROR_EMPTY_RESPONSE_NODE]}${COLOR_RESET}"
    else
        echo -e "${COLOR_RED}${LANG[ERROR_CREATE_NODE]}: $node_response${COLOR_RESET}"
    fi
    return 1
}

get_config_profiles() {
    local domain_url="$1"
    local token="$2"

    local config_response
    config_response=$(make_api_request "GET" "http://$domain_url/api/config-profiles" "$token")
    if [ -z "$config_response" ] || ! echo "$config_response" | jq -e '.' > /dev/null 2>&1; then
        err_msg "${LANG[ERROR_NO_CONFIGS]}"
        return 1
    fi

    local profile_uuid
    profile_uuid=$(echo "$config_response" | jq -r '.response.configProfiles[] | select(.name == "Default-Profile") | .uuid' 2>/dev/null)
    if [ -z "$profile_uuid" ]; then
        echo -e "${COLOR_YELLOW}${LANG[NO_DEFAULT_PROFILE]}${COLOR_RESET}" >&2
        return 0
    fi

    echo "$profile_uuid"
    return 0
}

delete_config_profile() {
    local domain_url="$1"
    local token="$2"
    local profile_uuid="$3"

    if [ -z "$profile_uuid" ]; then
        profile_uuid=$(get_config_profiles "$domain_url" "$token")
        if [ $? -ne 0 ] || [ -z "$profile_uuid" ]; then
            return 0
        fi
    fi

    local delete_response
    delete_response=$(make_api_request "DELETE" "http://$domain_url/api/config-profiles/$profile_uuid" "$token")
    [ -z "$delete_response" ] && return 0
    if ! echo "$delete_response" | jq -e '.' > /dev/null 2>&1; then
        echo -e "${COLOR_RED}${LANG[ERROR_DELETE_PROFILE]}${COLOR_RESET}"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Config profile creation — TLS on 443, all-in-one fallbacks, static ECH
#
# Caller-set globals:
#   CP_PROFILE_NAME         Panel-visible profile name
#   CP_INBOUND_TAG          Tag of the primary TLS inbound on 443
#   CP_DIRECT_DOMAIN        Direct hostname — also the ECH serverName
#   CP_DIRECT_CERT          Certbot lineage covering the direct domain
#   CP_PANEL_DOMAIN         CDN hostname for panel + subscription (optional)
#   CP_PANEL_CERT           Certbot lineage covering the CDN hostname
#   CP_TINYAUTH_DOMAIN      TinyAuth subdomain, NGINX variant (optional)
#   CP_TINYAUTH_CERT        Certbot lineage covering the TinyAuth subdomain
#   CP_ECH_KEY_PATH         Container path of the ECH private key file
#
# Emits:  "<config_uuid> <primary_inbound_uuid>"
#
# Every inbound carries a tag. Remnawave's XRayConfig validator rejects any
# inbound without one ("All inbounds must have a unique tag."), and the
# ConfigProfileInbounds table enforces @@unique([tag]) panel-wide — so the
# fallback tags are derived from the primary tag: "Steal" → "Steal-vless-ws",
# "Steal-trojan-ws", "Steal-ss-ws" etc. Hardcoded fallback tags would pass the
# first install and then collide with A113 the moment a second profile is
# created (add_node.sh).
# ---------------------------------------------------------------------------
create_config_profile() {
    local domain_url=$1
    local token=$2

    local name="$CP_PROFILE_NAME"
    local inbound_tag="$CP_INBOUND_TAG"
    local direct_domain="$CP_DIRECT_DOMAIN"
    local direct_cert="$CP_DIRECT_CERT"
    local panel_domain="${CP_PANEL_DOMAIN:-}"
    local panel_cert="${CP_PANEL_CERT:-}"
    local tinyauth_domain="${CP_TINYAUTH_DOMAIN:-}"
    local tinyauth_cert="${CP_TINYAUTH_CERT:-}"
    local ech_key_path="${CP_ECH_KEY_PATH:-}"

    step_do "${LANG[CREATING_CONFIG_PROFILE]}" >&2

    if [ -z "$name" ] || [ -z "$direct_domain" ] || [ -z "$direct_cert" ]; then
        err_msg "${LANG[ERROR_CREATE_CONFIG_PROFILE]}: missing CP_* globals"
        return 1
    fi

    # The primary inbound tag drives every fallback tag. Without it the
    # validator rejects the first tagless inbound and the panel answers A112.
    if [ -z "$inbound_tag" ]; then
        err_msg "${LANG[ERROR_CREATE_CONFIG_PROFILE]}: CP_INBOUND_TAG is empty"
        return 1
    fi
    case "$inbound_tag" in
        *,*)
            err_msg "${LANG[ERROR_CREATE_CONFIG_PROFILE]}: CP_INBOUND_TAG must not contain a comma"
            return 1
            ;;
    esac

    # Certificate array, deduplicated by fullchain path: in the bonded
    # two-domain layout PANEL_CERT and DIRECT_CERT often resolve to the
    # same wildcard lineage, and two identical entries are pointless
    # noise the panel may or may not tolerate.
    local certs_json
    certs_json=$(jq -n \
        --arg d_cert "$direct_cert" \
        --arg p_cert "$panel_cert" \
        --arg t_cert "$tinyauth_cert" '
        ( [ { certificateFile: ("/etc/letsencrypt/live/" + $d_cert + "/fullchain.pem"),
              keyFile:         ("/etc/letsencrypt/live/" + $d_cert + "/privkey.pem"),
              ocspStapling: 3600 } ] )
        + (if $p_cert != "" then [ { certificateFile: ("/etc/letsencrypt/live/" + $p_cert + "/fullchain.pem"),
                                     keyFile:         ("/etc/letsencrypt/live/" + $p_cert + "/privkey.pem"),
                                     ocspStapling: 3600 } ] else [] end)
        + (if $t_cert != "" then [ { certificateFile: ("/etc/letsencrypt/live/" + $t_cert + "/fullchain.pem"),
                                     keyFile:         ("/etc/letsencrypt/live/" + $t_cert + "/privkey.pem"),
                                     ocspStapling: 3600 } ] else [] end)
        | unique_by(.certificateFile)
    ')

    local tls_json
    if [ -n "$ech_key_path" ]; then
        tls_json=$(jq -n --argjson certs "$certs_json" --arg ech "$ech_key_path" '
            {
                certificates: $certs,
                minVersion: "1.2",
                cipherSuites: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                alpn: ["h2", "http/1.1"],
                echServerKeys: $ech
            }')
    else
        tls_json=$(jq -n --argjson certs "$certs_json" '
            {
                certificates: $certs,
                minVersion: "1.2",
                cipherSuites: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                alpn: ["h2", "http/1.1"]
            }')
    fi

    local fallbacks_json
    fallbacks_json=$(jq -n --arg sn "$direct_domain" '[
        { name: $sn, path: "/vlws", dest: "@vless-ws",  xver: 2 },
        { name: $sn, path: "/vhu",  dest: "@vless-hu",  xver: 2 },
        { name: $sn, path: "/vxh",  dest: "@vless-xhttp" },
        { name: $sn, path: "/vltc", dest: "@vless-tcp-obfs", xver: 2 },
        { name: $sn, path: "/trws", dest: "@trojan-ws", xver: 2 },
        { name: $sn, path: "/thu",  dest: "@trojan-hu", xver: 2 },
        { name: $sn, path: "/trtc", dest: "@trojan-tcp-obfs", xver: 2 },
        { name: $sn, path: "/ssws", dest: 4001 },
        { name: $sn, path: "/sstc", dest: 4002 },
        { dest: "/dev/shm/nginx.sock", xver: 2 }
    ]')

    local request_body
    request_body=$(jq -n \
        --arg name "$name" \
        --arg tag "$inbound_tag" \
        --argjson fallbacks "$fallbacks_json" \
        --argjson tls "$tls_json" '
    {
        name: $name,
        config: {
            log: { loglevel: "warning" },
            dns: {
                queryStrategy: "UseIPv4",
                servers: [{ address: "https://dns.google/dns-query", skipFallback: false }]
            },
            inbounds: [
                {
                    tag: $tag,
                    port: 443,
                    protocol: "vless",
                    settings: { clients: [], decryption: "none", fallbacks: $fallbacks },
                    sniffing: { enabled: true, destOverride: ["http", "tls", "quic"] },
                    streamSettings: { network: "tcp", security: "tls", tlsSettings: $tls }
                },
                {
                    tag: ($tag + "-vless-ws"),
                    listen: "@vless-ws",
                    protocol: "vless",
                    settings: { clients: [], decryption: "none" },
                    streamSettings: {
                        network: "ws",
                        security: "none",
                        wsSettings: { acceptProxyProtocol: true, path: "/vlws" }
                    },
                    sniffing: { enabled: true, destOverride: ["http", "tls"] }
                },
                {
                    tag: ($tag + "-vless-hu"),
                    listen: "@vless-hu",
                    protocol: "vless",
                    settings: { clients: [], decryption: "none" },
                    streamSettings: {
                        network: "httpupgrade",
                        security: "none",
                        httpupgradeSettings: { acceptProxyProtocol: true, path: "/vhu" }
                    },
                    sniffing: { enabled: true, destOverride: ["http", "tls"] }
                },
                {
                    tag: ($tag + "-vless-xhttp"),
                    listen: "@vless-xhttp",
                    protocol: "vless",
                    settings: { clients: [], decryption: "none" },
                    streamSettings: {
                        network: "xhttp",
                        security: "none",
                        xhttpSettings: { path: "/vxh", mode: "auto" }
                    },
                    sniffing: { enabled: true, destOverride: ["http", "tls"] }
                },
                {
                    tag: ($tag + "-vless-tcp-obfs"),
                    listen: "@vless-tcp-obfs",
                    protocol: "vless",
                    settings: { clients: [], decryption: "none" },
                    streamSettings: {
                        network: "tcp",
                        security: "none",
                        tcpSettings: {
                            acceptProxyProtocol: true,
                            header: { type: "http", request: { path: ["/vltc"] } }
                        }
                    },
                    sniffing: { enabled: true, destOverride: ["http", "tls"] }
                },
                {
                    tag: ($tag + "-trojan-ws"),
                    listen: "@trojan-ws",
                    protocol: "trojan",
                    settings: { clients: [] },
                    streamSettings: {
                        network: "ws",
                        security: "none",
                        wsSettings: { acceptProxyProtocol: true, path: "/trws" }
                    },
                    sniffing: { enabled: true, destOverride: ["http", "tls"] }
                },
                {
                    tag: ($tag + "-trojan-hu"),
                    listen: "@trojan-hu",
                    protocol: "trojan",
                    settings: { clients: [] },
                    streamSettings: {
                        network: "httpupgrade",
                        security: "none",
                        httpupgradeSettings: { acceptProxyProtocol: true, path: "/thu" }
                    },
                    sniffing: { enabled: true, destOverride: ["http", "tls"] }
                },
                {
                    tag: ($tag + "-trojan-tcp-obfs"),
                    listen: "@trojan-tcp-obfs",
                    protocol: "trojan",
                    settings: { clients: [] },
                    streamSettings: {
                        network: "tcp",
                        security: "none",
                        tcpSettings: {
                            acceptProxyProtocol: true,
                            header: { type: "http", request: { path: ["/trtc"] } }
                        }
                    },
                    sniffing: { enabled: true, destOverride: ["http", "tls"] }
                },
                {
                    tag: ($tag + "-ss-ws"),
                    listen: "127.0.0.1",
                    port: 4001,
                    protocol: "shadowsocks",
                    settings: { method: "chacha20-ietf-poly1305", clients: [] },
                    streamSettings: { network: "ws", security: "none", wsSettings: { path: "/ssws" } },
                    sniffing: { enabled: true, destOverride: ["http", "tls"] }
                },
                {
                    tag: ($tag + "-ss-tcp-obfs"),
                    listen: "127.0.0.1",
                    port: 4002,
                    protocol: "shadowsocks",
                    settings: { method: "chacha20-ietf-poly1305", clients: [] },
                    streamSettings: {
                        network: "tcp",
                        security: "none",
                        tcpSettings: { header: { type: "http", request: { path: ["/sstc"] } } }
                    },
                    sniffing: { enabled: true, destOverride: ["http", "tls"] }
                }
            ],
            outbounds: [
                { tag: "DIRECT", protocol: "freedom" },
                { tag: "BLOCK",  protocol: "blackhole" }
            ],
            routing: {
                rules: [
                    { ip: ["geoip:private"], outboundTag: "BLOCK" },
                    { protocol: ["bittorrent"], outboundTag: "BLOCK" }
                ]
            }
        }
    }')

    local response
    response=$(make_api_request "POST" "http://$domain_url/api/config-profiles" "$token" "$request_body")

    if [ -z "$response" ] || ! echo "$response" | jq -e '.response.uuid' > /dev/null 2>&1; then
        err_msg "${LANG[ERROR_CREATE_CONFIG_PROFILE]}: $response"
        # A112 is the panel's generic catch-all for any failure inside
        # XRayConfig construction (see config-profile.service.ts). The
        # response body names the code, never the reason — the reason is
        # only in the panel log. Point the operator at it.
        if echo "$response" | grep -q 'A112'; then
            echo -e "${COLOR_YELLOW}Panel reported A112 (Create config profile error).${COLOR_RESET}" >&2
            echo -e "${COLOR_YELLOW}The reason is in the panel log:${COLOR_RESET}" >&2
            echo -e "${COLOR_GRAY}  cd /opt/remnawave && docker compose logs --tail=60 remnawave | grep -i 'inbound\\|tag\\|config'${COLOR_RESET}" >&2
        fi
        return 1
    fi

    local config_uuid primary_inbound_uuid
    config_uuid=$(echo "$response" | jq -r '.response.uuid')
    primary_inbound_uuid=$(echo "$response" | jq -r --arg tag "$inbound_tag" \
        '.response.inbounds[] | select(.tag == $tag) | .uuid' | head -n1)

    # Positional fallback: the primary TLS inbound is always first in the
    # array this function just wrote, so `[0]` matches the pre-fork
    # behaviour even on panel builds whose inbound metadata omits `tag`.
    if [ -z "$primary_inbound_uuid" ] || [ "$primary_inbound_uuid" = "null" ]; then
        primary_inbound_uuid=$(echo "$response" | jq -r '.response.inbounds[0].uuid // empty')
    fi

    if [ -z "$config_uuid" ] || [ "$config_uuid" = "null" ] \
       || [ -z "$primary_inbound_uuid" ] || [ "$primary_inbound_uuid" = "null" ]; then
        err_msg "${LANG[ERROR_CREATE_CONFIG_PROFILE]}: Invalid UUIDs in response: $response"
        return 1
    fi

    step_ok "${LANG[CONFIG_PROFILE_CREATED]}" >&2
    echo "$config_uuid $primary_inbound_uuid"
    return 0
}

create_host() {
    local domain_url=$1
    local token=$2
    local inbound_uuid=$3
    local address=$4
    local config_uuid=$5
    local host_remark="${6:-Steal}"

    step_do "${LANG[CREATE_HOST]}"
    local request_body
    request_body=$(jq -n \
        --arg config_uuid "$config_uuid" \
        --arg inbound_uuid "$inbound_uuid" \
        --arg remark "$host_remark" \
        --arg address "$address" '{
        inbound: {
            configProfileUuid: $config_uuid,
            configProfileInboundUuid: $inbound_uuid
        },
        remark: $remark,
        address: $address,
        port: 443,
        path: "",
        sni: $address,
        host: "",
        alpn: null,
        fingerprint: "firefox",
        isDisabled: false,
        securityLayer: "DEFAULT"
    }')

    local response
    response=$(make_api_request "POST" "http://$domain_url/api/hosts" "$token" "$request_body")

    if echo "$response" | jq -e '.response.uuid' > /dev/null 2>&1; then
        step_ok "${LANG[HOST_CREATED]}"
        return 0
    fi

    if [ -z "$response" ]; then
        echo -e "${COLOR_RED}${LANG[ERROR_EMPTY_RESPONSE_HOST]}${COLOR_RESET}"
    else
        echo -e "${COLOR_RED}${LANG[ERROR_CREATE_HOST]}: $response${COLOR_RESET}"
    fi
    return 1
}

get_default_squad() {
    local domain_url=$1
    local token=$2

    step_do "${LANG[GET_DEFAULT_SQUAD]}" >&2
    local response
    response=$(make_api_request "GET" "http://$domain_url/api/internal-squads" "$token")
    if [ -z "$response" ] || ! echo "$response" | jq -e '.response.internalSquads' > /dev/null 2>&1; then
        err_msg "${LANG[ERROR_GET_SQUAD]}: $response"
        return 1
    fi

    local squad_uuids
    squad_uuids=$(echo "$response" | jq -r '.response.internalSquads[].uuid' 2>/dev/null)
    if [ -z "$squad_uuids" ]; then
        echo -e "${COLOR_YELLOW}${LANG[NO_SQUADS_FOUND]}${COLOR_RESET}" >&2
        return 0
    fi

    local valid_uuids=""
    while IFS= read -r uuid; do
        [ -z "$uuid" ] && continue
        if [[ $uuid =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
            valid_uuids+="$uuid\n"
        else
            err_msg "${LANG[INVALID_UUID_FORMAT]}: $uuid"
        fi
    done <<< "$squad_uuids"

    if [ -z "$valid_uuids" ]; then
        echo -e "${COLOR_YELLOW}${LANG[NO_VALID_SQUADS_FOUND]}${COLOR_RESET}" >&2
        return 0
    fi

    echo -e "$valid_uuids" | sed '/^$/d'
    return 0
}

update_squad() {
    local domain_url=$1
    local token=$2
    local squad_uuid=$3
    local inbound_uuid=$4

    if [[ ! $squad_uuid =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
        echo -e "${COLOR_RED}${LANG[INVALID_SQUAD_UUID]}: $squad_uuid${COLOR_RESET}"
        return 1
    fi

    if [[ ! $inbound_uuid =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
        echo -e "${COLOR_RED}${LANG[INVALID_INBOUND_UUID]}: $inbound_uuid${COLOR_RESET}"
        return 1
    fi

    local squad_response
    squad_response=$(make_api_request "GET" "http://$domain_url/api/internal-squads" "$token")
    if [ -z "$squad_response" ] || ! echo "$squad_response" | jq -e '.response.internalSquads' > /dev/null 2>&1; then
        echo -e "${COLOR_RED}${LANG[ERROR_GET_SQUAD]}: $squad_response${COLOR_RESET}"
        return 1
    fi

    local existing_inbounds
    existing_inbounds=$(echo "$squad_response" | jq -r --arg uuid "$squad_uuid" '.response.internalSquads[] | select(.uuid == $uuid) | .inbounds[].uuid' 2>/dev/null)
    if [ -z "$existing_inbounds" ]; then
        existing_inbounds="[]"
    else
        existing_inbounds=$(echo "$existing_inbounds" | jq -R . | jq -s .)
    fi

    local inbounds_array request_body response
    inbounds_array=$(jq -n --argjson existing "$existing_inbounds" --arg new "$inbound_uuid" '$existing + [$new] | unique')
    request_body=$(jq -n --arg uuid "$squad_uuid" --argjson inbounds "$inbounds_array" '{uuid: $uuid, inbounds: $inbounds}')

    response=$(make_api_request "PATCH" "http://$domain_url/api/internal-squads" "$token" "$request_body")
    if [ -z "$response" ] || ! echo "$response" | jq -e '.response.uuid' > /dev/null 2>&1; then
        echo -e "${COLOR_RED}${LANG[ERROR_UPDATE_SQUAD]}: $response${COLOR_RESET}"
        return 1
    fi

    step_ok "${LANG[UPDATE_SQUAD]}"
    return 0
}

create_api_token() {
    local domain_url=$1
    local token=$2
    local target_dir=$3
    local token_name="${4:-subscription-page}"

    step_do "${LANG[CREATING_API_TOKEN]}" >&2

    local token_data api_response api_token
    token_data='{"name":"'"$token_name"'","expiresInDays":3650,"scopes":["subscription-page-configs:list","subscription-page-configs:get","subscriptions:subpage-config","system:metadata","users:by-username"]}'

    api_response=$(make_api_request "POST" "http://$domain_url/api/tokens" "$token" "$token_data")
    api_token=$(echo "$api_response" | jq -r '.response.token // ""')

    if [ -z "$api_token" ] || [ "$api_token" = "null" ]; then
        token_data='{"name":"'"$token_name"'","expiresInDays":3650,"scopes":["*"]}'
        api_response=$(make_api_request "POST" "http://$domain_url/api/tokens" "$token" "$token_data")
        api_token=$(echo "$api_response" | jq -r '.response.token // ""')
    fi

    if [ -z "$api_token" ] || [ "$api_token" = "null" ]; then
        echo -e "${COLOR_RED}${LANG[ERROR_CREATE_API_TOKEN]}: $(echo "$api_response" | jq -r '.message // "Unknown error"')" >&2
        return 1
    fi

    # The compose file references REMNAWAVE_API_TOKEN=${api_token} — the
    # substitution source is .env, so that is where the value must land.
    # (Writing it straight into the compose used to work only because the
    # old template had a literal placeholder; today's has none, and the
    # sed hit nothing while Compose kept printing
    #   WARN[0000] The "api_token" variable is not set.
    # on every invocation.)
    local env_file="$target_dir/.env"
    if [ -f "$env_file" ]; then
        if grep -q '^api_token=' "$env_file"; then
            sed -i "s|^api_token=.*|api_token=$api_token|" "$env_file"
        else
            [ -n "$(tail -c1 "$env_file" 2>/dev/null)" ] && printf '\n' >> "$env_file"
            printf 'api_token=%s\n' "$api_token" >> "$env_file"
        fi
        chmod 600 "$env_file" 2>/dev/null
    fi

    # Legacy safety net: only touch the compose if it still carries a
    # LITERAL value (no leading $), i.e. an old template.
    if grep -qE 'REMNAWAVE_API_TOKEN=[^$[:space:]]' "$target_dir/docker-compose.yml" 2>/dev/null; then
        sed -i "s|REMNAWAVE_API_TOKEN=.*|REMNAWAVE_API_TOKEN=$api_token|" "$target_dir/docker-compose.yml"
    fi

    sleep 1

    step_ok "${LANG[API_TOKEN_ADDED]}" >&2
    return 0
}