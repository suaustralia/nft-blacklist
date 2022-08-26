#!/usr/bin/env bash
#
# usage update-blacklist.sh <configuration file>
# eg: update-blacklist.sh /etc/nft-blacklist/nft-blacklist.conf
#

SET_NAME_PREFIX=blacklist
SET_NAME_V4="${SET_NAME_PREFIX}_v4"
SET_NAME_V6="${SET_NAME_PREFIX}_v6"
IPV4_REGEX="(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?"
IPV6_REGEX="(\
(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|\
(?:[0-9a-fA-F]{1,4}:){1,7}:|\
(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|\
(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|\
(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|\
(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|\
(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|\
[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|\
:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|\
::(?:ffff(?::0{1,4}){0,1}:){0,1}\
(?:(25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}\
(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|\
(?:[0-9a-fA-F]{1,4}:){1,4}:\
(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}\
(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\
)\
(?:\/[0-9]{1,3})?"

function exists() { command -v "$1" >/dev/null 2>&1 ; }
function count_entries() { wc -l "$1" | cut -d' ' -f1 ; }

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

# download cidr-merger from https://github.com/zhanhb/cidr-merger/releases
DO_OPTIMIZE_CIDR=no
if exists cidr-merger ; then
  DO_OPTIMIZE_CIDR=yes
else
  echo >&2 "Warning: cidr-marger is not available, please download it from https://github.com/zhanhb/cidr-merger/releases to avoid issues with nft"
fi

if [[ ! -d $(dirname "$IP_BLACKLIST_FILE") || ! -d $(dirname "$RULESET_FILE") ]]; then
  echo >&2 "Error: missing directory(s): $(dirname "$IP_BLACKLIST_FILE" "$RULESET_FILE"|sort -u)"
  exit 1
fi

IP_BLACKLIST_TMP_FILE=$(mktemp)
IP6_BLACKLIST_TMP_FILE=$(mktemp)
for i in "${BLACKLISTS[@]}"
do
  IP_TMP=$(mktemp)
  (( HTTP_RC=$(curl -L -A "blacklist-update/script/github" --connect-timeout 10 --max-time 10 -o "$IP_TMP" -s -w "%{http_code}" "$i") ))
  if (( HTTP_RC == 200 || HTTP_RC == 302 || HTTP_RC == 0 )); then # "0" because file:/// returns 000
    command grep -Po "^$IPV4_REGEX" "$IP_TMP" | sed -r 's/^0*([0-9]+)\.0*([0-9]+)\.0*([0-9]+)\.0*([0-9]+)$/\1.\2.\3.\4/' >> "$IP_BLACKLIST_TMP_FILE"
    command grep -Po "^$IPV6_REGEX" "$IP_TMP" >> "$IP6_BLACKLIST_TMP_FILE"
    [[ ${VERBOSE:-yes} == yes ]] && echo -n "."
  elif (( HTTP_RC == 503 )); then
    echo -e "\\nUnavailable (${HTTP_RC}): $i"
  else
    echo >&2 -e "\\nWarning: curl returned HTTP response code $HTTP_RC for URL $i"
  fi
  rm -f "$IP_TMP"
done

# sort -nu does not work as expected
sed -r -e '/^(0\.0\.0\.0|10\.|127\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.|22[4-9]\.|23[0-9]\.)/d' "$IP_BLACKLIST_TMP_FILE"|sort -n|sort -mu >| "$IP_BLACKLIST_FILE"
cp "$IP6_BLACKLIST_TMP_FILE" "$IP6_BLACKLIST_FILE"
if [[ ${DO_OPTIMIZE_CIDR} == yes ]]; then
  if [[ ${VERBOSE:-no} == yes ]]; then
    echo -e "\\nAddresses before CIDR optimization: $(count_entries "$IP_BLACKLIST_FILE") IPv4, $(count_entries "$IP6_BLACKLIST_FILE") IPv6"
  fi
  cidr-merger "$IP_BLACKLIST_FILE" > "$IP_BLACKLIST_TMP_FILE" 2>/dev/null
  cidr-merger "$IP6_BLACKLIST_FILE" > "$IP6_BLACKLIST_TMP_FILE" 2>/dev/null
  if [[ ${VERBOSE:-no} == yes ]]; then
    echo "Addresses after CIDR optimization: $(count_entries "$IP_BLACKLIST_TMP_FILE") IPv4, $(count_entries "$IP6_BLACKLIST_TMP_FILE") IPv6"
  fi
  cp "$IP_BLACKLIST_TMP_FILE" "$IP_BLACKLIST_FILE"
  cp "$IP6_BLACKLIST_TMP_FILE" "$IP6_BLACKLIST_FILE"
fi

rm -f "$IP_BLACKLIST_TMP_FILE" "$IP6_BLACKLIST_TMP_FILE"

cat >| "$RULESET_FILE" <<EOF
add table inet $TABLE
add counter inet $TABLE $SET_NAME_V4
add counter inet $TABLE $SET_NAME_V6
add set inet $TABLE $SET_NAME_V4 { type ipv4_addr; size ${SET_SIZE:-65536}; flags interval; }
flush set inet $TABLE $SET_NAME_V4
add set inet $TABLE $SET_NAME_V6 { type ipv6_addr; size ${SET_SIZE:-65536}; flags interval; }
flush set inet $TABLE $SET_NAME_V6
add chain inet $TABLE input { type filter hook input priority filter - 1; policy accept; }
flush chain inet $TABLE input
add rule inet $TABLE input meta pkttype { broadcast, multicast } accept
$([ ! -z "$IP_WHITELIST" ] && echo "add rule inet $TABLE input ip saddr { $IP_WHITELIST } accept")
$([ ! -z "$IP6_WHITELIST" ] && echo "add rule inet $TABLE input ip6 saddr { $IP6_WHITELIST } accept")
add rule inet $TABLE input ip saddr @$SET_NAME_V4 counter name $SET_NAME_V4 drop
add rule inet $TABLE input ip6 saddr @$SET_NAME_V6 counter name $SET_NAME_V6 drop
EOF

if [ -s "$IP_BLACKLIST_FILE" ]; then
  cat >> "$RULESET_FILE" <<EOF
add element inet $TABLE $SET_NAME_V4 {
$(sed -rn -e '/^[#$;]/d' -e "s/^([0-9./]+).*/  \\1,/p" "$IP_BLACKLIST_FILE")
}
EOF
fi

if [ -s "$IP6_BLACKLIST_FILE" ]; then
  cat >> "$RULESET_FILE" <<EOF
add element inet $TABLE $SET_NAME_V6 {
$(sed -rn -e '/^[#$;]/d' -e "s/^(([0-9a-fA-F:.]+:+[0-9a-fA-F]*)+(\/[0-9]{1,3})?).*/  \\1,/p" "$IP6_BLACKLIST_FILE")
}
EOF
fi

nft -f "$RULESET_FILE"

if [[ ${VERBOSE:-no} == yes ]]; then
  echo
  echo "Number of blacklisted IP/networks found: $(count_entries "$IP_BLACKLIST_FILE") IPv4, $(count_entries "$IP6_BLACKLIST_FILE") IPv6"
fi
