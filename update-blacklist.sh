#!/usr/bin/env bash
#
# usage update-blacklist.sh <configuration file>
# eg: update-blacklist.sh /etc/nft-blacklist/nft-blacklist.conf
#

function exists() { command -v "$1" >/dev/null 2>&1 ; }

if [[ -z "$1" ]]; then
  echo "Error: please specify a configuration file, e.g. $0 /etc/nft-blacklist/nft-blacklist.conf"
  exit 1
fi

# shellcheck source=nft-blacklist.conf
if ! source "$1"; then
  echo "Error: can't load configuration file $1"
  exit 1
fi

if ! exists curl && exists egrep && exists grep && exists nft && exists sed && exists sort && exists wc ; then
  echo >&2 "Error: searching PATH fails to find executables among: curl egrep grep nft sed sort wc"
  exit 1
fi

DO_OPTIMIZE_CIDR=no
if exists iprange && [[ ${OPTIMIZE_CIDR:-yes} != no ]]; then
  DO_OPTIMIZE_CIDR=yes
fi

if [[ ! -d $(dirname "$IP_BLACKLIST") || ! -d $(dirname "$IP_BLACKLIST_RESTORE") ]]; then
  echo >&2 "Error: missing directory(s): $(dirname "$IP_BLACKLIST" "$IP_BLACKLIST_RESTORE"|sort -u)"
  exit 1
fi

IP_BLACKLIST_TMP=$(mktemp)
for i in "${BLACKLISTS[@]}"
do
  IP_TMP=$(mktemp)
  (( HTTP_RC=$(curl -L -A "blacklist-update/script/github" --connect-timeout 10 --max-time 10 -o "$IP_TMP" -s -w "%{http_code}" "$i") ))
  if (( HTTP_RC == 200 || HTTP_RC == 302 || HTTP_RC == 0 )); then # "0" because file:/// returns 000
    command grep -Po '^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?' "$IP_TMP" | sed -r 's/^0*([0-9]+)\.0*([0-9]+)\.0*([0-9]+)\.0*([0-9]+)$/\1.\2.\3.\4/' >> "$IP_BLACKLIST_TMP"
    [[ ${VERBOSE:-yes} == yes ]] && echo -n "."
  elif (( HTTP_RC == 503 )); then
    echo -e "\\nUnavailable (${HTTP_RC}): $i"
  else
    echo >&2 -e "\\nWarning: curl returned HTTP response code $HTTP_RC for URL $i"
  fi
  rm -f "$IP_TMP"
done

# sort -nu does not work as expected
sed -r -e '/^(0\.0\.0\.0|10\.|127\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.|22[4-9]\.|23[0-9]\.)/d' "$IP_BLACKLIST_TMP"|sort -n|sort -mu >| "$IP_BLACKLIST"
if [[ ${DO_OPTIMIZE_CIDR} == yes ]]; then
  if [[ ${VERBOSE:-no} == yes ]]; then
    echo -e "\\nAddresses before CIDR optimization: $(wc -l "$IP_BLACKLIST" | cut -d' ' -f1)"
  fi
  < "$IP_BLACKLIST" iprange --optimize - > "$IP_BLACKLIST_TMP" 2>/dev/null
  if [[ ${VERBOSE:-no} == yes ]]; then
    echo "Addresses after CIDR optimization: $(wc -l "$IP_BLACKLIST_TMP" | cut -d' ' -f1)"
  fi
  cp "$IP_BLACKLIST_TMP" "$IP_BLACKLIST"
fi

rm -f "$IP_BLACKLIST_TMP"

# family = inet for IPv4/IPv6
cat >| "$IP_BLACKLIST_RESTORE" <<EOF
add table $TABLE
add counter $TABLE $SET_NAME
add chain $TABLE input { type filter hook input priority filter - 1; policy accept; }
flush chain $TABLE input
add set $TABLE $SET_NAME { type ipv4_addr; size ${SET_SIZE:-65536}; flags interval; }
flush set $TABLE $SET_NAME
add rule $TABLE input ip saddr @$SET_NAME counter name $SET_NAME drop
add element $TABLE $SET_NAME {
EOF

# can be IPv4 including netmask notation
# IPv6 ? -e "s/^([0-9a-f:./]+).*/  \1,/p" \ IPv6
sed -rn -e '/^#|^$/d' \
  -e "s/^([0-9./]+).*/  \\1,/p" "$IP_BLACKLIST" >> "$IP_BLACKLIST_RESTORE"

cat >> "$IP_BLACKLIST_RESTORE" <<EOF
}
EOF

nft -f "$IP_BLACKLIST_RESTORE"

if [[ ${VERBOSE:-no} == yes ]]; then
  echo
  echo "Number of blacklisted IP/networks found: $(wc -l "$IP_BLACKLIST" | cut -d' ' -f1)"
fi
