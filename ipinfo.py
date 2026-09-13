#!/usr/bin/env python3
# -*- coding: utf-8 -*-
###
# MIT License
# 
# Copyright (c) [2026] [Joshua Canfield]
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
###

###
# Changelog
#
# 0.1 - Initial release. Setup python script using WeeChat developer’s guide
# 0.2 - Fixed broken API calls via ipinfo.io
# 0.3 - Added hostname resolver function to workaround limitations of ipinfo API calls
# 0.4 - Fixed issue where only ip address was returning output. Hostname and username should work
# TODO
# - Allow for /ipinfo USERNAME
# - Fix invalid hostname lookups (e.g. /ipinfo example.com) that return "hostname": null
#
###

import json
import re
import shlex
import socket
import weechat



SCRIPT_NAME = "ipinfo"
SCRIPT_AUTHOR = "Joshua Canfield"
SCRIPT_VERSION = "0.4"
SCRIPT_LICENSE = "GPL3"
SCRIPT_DESC = "Lookup IP/hostname/nickname info with multiple HTTP providers"


REQUESTS = {}
REQ_ID = 0

DNS_REQUESTS = {}
DNS_ID = 0

WHOIS_REQUESTS = {}
WHOIS_ID = 0

WHOIS_TIMEOUT_MS = 8000
DNS_TIMEOUT_MS = 6000


def is_ip_address(target):
    if not target:
        return False
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, target)
            return True
        except (OSError, ValueError):
            continue
    return False


def providers_for_target(target):
    if target:
        # Only providers that support arbitrary third-party lookups.
        # ifconfig.co / ifconfig.io are "what's my IP" echo services and
        # do NOT support looking up an arbitrary target, so they are
        # excluded here.
        return [
            ("ipinfo", "https://ipinfo.io/%s/json" % target),
            ("ipapi", "http://ip-api.com/json/%s" % target),
        ]
    # No target -> "what is my own IP" lookups, where the echo services work.
    return [
        ("ipinfo", "https://ipinfo.io/json"),
        ("ipapi", "http://ip-api.com/json"),
        ("ifconfigco", "https://ifconfig.co/json"),
        ("ifconfigio", "https://ifconfig.io/all.json"),
    ]


def normalize_payload(provider, payload):
    if provider == "ipinfo":
        return {
            "ip": payload.get("ip"),
            "hostname": payload.get("hostname"),
            "city": payload.get("city"),
            "region": payload.get("region"),
            "country": payload.get("country"),
            "loc": payload.get("loc"),
            "org": payload.get("org"),
            "postal": payload.get("postal"),
            "timezone": payload.get("timezone"),
        }

    if provider == "ipapi":
        # ip-api.com returns {"status": "fail", "message": "..."} on error
        if payload.get("status") == "fail":
            return None

        loc = None
        lat = payload.get("lat")
        lon = payload.get("lon")
        if lat is not None and lon is not None:
            loc = "%s,%s" % (lat, lon)

        return {
            "ip": payload.get("query"),
            "hostname": payload.get("reverse"),
            "city": payload.get("city"),
            "region": payload.get("regionName") or payload.get("region"),
            "country": payload.get("country") or payload.get("countryCode"),
            "loc": loc,
            "org": payload.get("org") or payload.get("isp") or payload.get("as"),
            "postal": payload.get("zip"),
            "timezone": payload.get("timezone"),
        }

    if provider == "ifconfigco":
        loc = None
        lat = payload.get("latitude")
        lon = payload.get("longitude")
        if lat is not None and lon is not None:
            loc = "%s,%s" % (lat, lon)

        return {
            "ip": payload.get("ip"),
            "hostname": payload.get("hostname"),
            "city": payload.get("city"),
            "region": payload.get("region_name") or payload.get("region"),
            "country": payload.get("country"),
            "loc": loc,
            "org": payload.get("asn_org") or payload.get("org"),
            "postal": payload.get("postal_code"),
            "timezone": payload.get("time_zone") or payload.get("timezone"),
        }

    if provider == "ifconfigio":
        # ifconfig.io/all.json only returns basic fields: ip, host,
        # forwarded, port, country_code, method, etc. No city/region/org.
        return {
            "ip": payload.get("ip"),
            "hostname": payload.get("host"),
            "city": None,
            "region": None,
            "country": payload.get("country_code"),
            "loc": None,
            "org": None,
            "postal": None,
            "timezone": None,
        }

    return {}


def print_result(buffer, provider, target, payload, extra_lines=None):
    weechat.prnt(buffer, "ipinfo: %s (provider: %s)" % (target, provider))
    if extra_lines:
        for line in extra_lines:
            weechat.prnt(buffer, "  %s" % line)
    fields = [
        ("ip", "IP"),
        ("hostname", "Hostname (PTR)"),
        ("city", "City"),
        ("region", "Region"),
        ("country", "Country"),
        ("loc", "Location"),
        ("org", "Org"),
        ("postal", "Postal"),
        ("timezone", "Timezone"),
    ]
    for key, label in fields:
        value = payload.get(key)
        if value:
            weechat.prnt(buffer, "  %s: %s" % (label, value))


def start_attempt(req_id):
    req = REQUESTS.get(req_id)
    if not req:
        return weechat.WEECHAT_RC_OK

    if req["index"] >= len(req["providers"]):
        weechat.prnt(
            req["buffer"],
            "%sall providers failed for %s" %
            (weechat.prefix("error"), req["target"])
        )
        for line in req["errors"]:
            weechat.prnt(req["buffer"], "%s%s" % (weechat.prefix("error"), line))
        del REQUESTS[req_id]
        return weechat.WEECHAT_RC_OK

    provider, url = req["providers"][req["index"]]
    req["stdout"] = ""
    req["stderr"] = ""
    req["provider"] = provider
    req["url"] = url

    cmd = "/usr/bin/curl -fsSL --connect-timeout 5 --max-time 10 " + shlex.quote(url)
    hook = weechat.hook_process(cmd, 15000, "ipinfo_process_cb", req_id)

    if not hook:
        req["errors"].append("%s: unable to start curl" % provider)
        req["index"] += 1
        return start_attempt(req_id)

    weechat.prnt(
        req["buffer"],
        "%sFetching info for %s via %s..." %
        (weechat.prefix("network"), req["target"], provider)
    )
    return weechat.WEECHAT_RC_OK


def ipinfo_process_cb(data, command, return_code, out, err):
    req = REQUESTS.get(data)
    if not req:
        return weechat.WEECHAT_RC_OK

    if out:
        req["stdout"] += out
    if err:
        req["stderr"] += err

    if return_code == weechat.WEECHAT_HOOK_PROCESS_RUNNING:
        return weechat.WEECHAT_RC_OK

    provider = req["provider"]

    if return_code != 0:
        msg = "%s failed (rc=%s)" % (provider, return_code)
        if req["stderr"].strip():
            msg += ": %s" % req["stderr"].strip()
        req["errors"].append(msg)
        req["index"] += 1
        return start_attempt(data)

    body = req["stdout"].strip()
    if not body:
        req["errors"].append("%s failed: empty response" % provider)
        req["index"] += 1
        return start_attempt(data)

    try:
        raw = json.loads(body)
    except Exception as e:
        req["errors"].append("%s failed: json parse error: %s" % (provider, e))
        req["index"] += 1
        return start_attempt(data)

    payload = normalize_payload(provider, raw)

    if payload is None:
        # Provider explicitly reported failure (e.g. ip-api "status":"fail")
        reason = raw.get("message", "unknown error") if isinstance(raw, dict) else "unknown error"
        req["errors"].append("%s failed: %s" % (provider, reason))
        req["index"] += 1
        return start_attempt(data)

    extra_lines = []
    if req.get("via_nick"):
        extra_lines.append("Looked up via nick: %s" % req["via_nick"])
    if req.get("resolved_from") and req["resolved_from"] != payload.get("ip"):
        extra_lines.append("Resolved from: %s" % req["resolved_from"])

    print_result(req["buffer"], provider, req["target"], payload, extra_lines)
    del REQUESTS[data]
    return weechat.WEECHAT_RC_OK


def begin_ip_lookup(buffer, target, lookup_ip, via_nick=None, resolved_from=None):
    """Kick off the curl/provider chain once we have a concrete IP (or empty
    string for a 'my own IP' lookup)."""
    global REQ_ID
    REQ_ID += 1
    req_id = str(REQ_ID)

    REQUESTS[req_id] = {
        "buffer": buffer,
        "target": target,
        "providers": providers_for_target(lookup_ip),
        "index": 0,
        "stdout": "",
        "stderr": "",
        "provider": "",
        "url": "",
        "errors": [],
        "via_nick": via_nick,
        "resolved_from": resolved_from,
    }

    return start_attempt(req_id)


# --- Forward DNS resolution (hostname -> IP), done via hook_process so it
# never blocks the WeeChat main thread. ---

def dns_resolve_cb(data, command, return_code, out, err):
    req = DNS_REQUESTS.get(data)
    if not req:
        return weechat.WEECHAT_RC_OK

    if out:
        req["stdout"] += out

    if return_code == weechat.WEECHAT_HOOK_PROCESS_RUNNING:
        return weechat.WEECHAT_RC_OK

    del DNS_REQUESTS[data]

    ip = req["stdout"].strip()
    if return_code != 0 or not ip or not is_ip_address(ip):
        weechat.prnt(
            req["buffer"],
            "%scould not resolve hostname: %s" % (weechat.prefix("error"), req["hostname"])
        )
        return weechat.WEECHAT_RC_OK

    return begin_ip_lookup(
        req["buffer"], req["display_target"], ip,
        via_nick=req.get("via_nick"), resolved_from=req["hostname"]
    )


def resolve_hostname_then_lookup(buffer, hostname, display_target, via_nick=None):
    global DNS_ID
    DNS_ID += 1
    dns_id = str(DNS_ID)

    DNS_REQUESTS[dns_id] = {
        "buffer": buffer,
        "hostname": hostname,
        "display_target": display_target,
        "via_nick": via_nick,
        "stdout": "",
    }

    py_snippet = (
        "import socket,sys\n"
        "try:\n"
        "    print(socket.gethostbyname(sys.argv[1]))\n"
        "except OSError:\n"
        "    sys.exit(1)\n"
    )
    cmd = "python3 -c %s %s" % (shlex.quote(py_snippet), shlex.quote(hostname))
    hook = weechat.hook_process(cmd, DNS_TIMEOUT_MS, "dns_resolve_cb", dns_id)

    if not hook:
        del DNS_REQUESTS[dns_id]
        weechat.prnt(buffer, "%sunable to start DNS resolver for %s" %
                     (weechat.prefix("error"), hostname))
        return weechat.WEECHAT_RC_OK

    weechat.prnt(
        buffer,
        "%sResolving hostname %s..." % (weechat.prefix("network"), hostname)
    )
    return weechat.WEECHAT_RC_OK


# --- Nickname -> host resolution via /whois, then feeds into the hostname
# resolver above. ---

def cleanup_whois(whois_id):
    req = WHOIS_REQUESTS.pop(whois_id, None)
    if not req:
        return
    for hook_key in ("hook_311", "hook_401", "hook_timeout"):
        hook = req.get(hook_key)
        if hook:
            weechat.unhook(hook)


def finish_whois_success(whois_id, host):
    req = WHOIS_REQUESTS.get(whois_id)
    if not req:
        return weechat.WEECHAT_RC_OK
    buffer, nick = req["buffer"], req["nick"]
    cleanup_whois(whois_id)

    if is_ip_address(host):
        return begin_ip_lookup(buffer, nick, host, via_nick=nick)
    return resolve_hostname_then_lookup(buffer, host, nick, via_nick=nick)


def ipinfo_whois_311_cb(data, signal, signal_data):
    req = WHOIS_REQUESTS.get(data)
    if not req:
        return weechat.WEECHAT_RC_OK

    server = signal.split(",", 1)[0]
    if server != req["server"]:
        return weechat.WEECHAT_RC_OK

    parts = signal_data.split()
    # :<serverhost> 311 <mynick> <targetnick> <user> <host> * :<realname>
    if len(parts) < 6:
        return weechat.WEECHAT_RC_OK
    target_nick, host = parts[3], parts[5]
    if target_nick.lower() != req["nick"].lower():
        return weechat.WEECHAT_RC_OK

    return finish_whois_success(data, host)


def ipinfo_whois_401_cb(data, signal, signal_data):
    req = WHOIS_REQUESTS.get(data)
    if not req:
        return weechat.WEECHAT_RC_OK

    server = signal.split(",", 1)[0]
    if server != req["server"]:
        return weechat.WEECHAT_RC_OK

    parts = signal_data.split()
    # :<serverhost> 401 <mynick> <targetnick> :No such nick/channel
    if len(parts) < 4:
        return weechat.WEECHAT_RC_OK
    target_nick = parts[3]
    if target_nick.lower() != req["nick"].lower():
        return weechat.WEECHAT_RC_OK

    buffer = req["buffer"]
    weechat.prnt(buffer, "%sno such nick: %s" % (weechat.prefix("error"), req["nick"]))
    cleanup_whois(data)
    return weechat.WEECHAT_RC_OK


def ipinfo_whois_timeout_cb(data, remaining_calls):
    req = WHOIS_REQUESTS.get(data)
    if not req:
        return weechat.WEECHAT_RC_OK
    weechat.prnt(
        req["buffer"],
        "%swhois for %s timed out" % (weechat.prefix("error"), req["nick"])
    )
    cleanup_whois(data)
    return weechat.WEECHAT_RC_OK


def resolve_nick_then_lookup(buffer, server, nick):
    global WHOIS_ID
    WHOIS_ID += 1
    whois_id = str(WHOIS_ID)

    hook_311 = weechat.hook_signal("*,irc_in2_311", "ipinfo_whois_311_cb", whois_id)
    hook_401 = weechat.hook_signal("*,irc_in2_401", "ipinfo_whois_401_cb", whois_id)
    hook_timeout = weechat.hook_timer(WHOIS_TIMEOUT_MS, 0, 1, "ipinfo_whois_timeout_cb", whois_id)

    WHOIS_REQUESTS[whois_id] = {
        "buffer": buffer,
        "server": server,
        "nick": nick,
        "hook_311": hook_311,
        "hook_401": hook_401,
        "hook_timeout": hook_timeout,
    }

    weechat.prnt(buffer, "%sLooking up host for nick %s via /whois..." %
                 (weechat.prefix("network"), nick))
    weechat.command(buffer, "/whois %s" % nick)
    return weechat.WEECHAT_RC_OK


HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,62}\.)+[A-Za-z]{2,63}$")


def ipinfo_cmd_cb(data, buffer, args):
    target = args.strip()

    if not target:
        return begin_ip_lookup(buffer, "self", "")

    if is_ip_address(target):
        return begin_ip_lookup(buffer, target, target)

    plugin = weechat.buffer_get_string(buffer, "plugin")
    server = weechat.buffer_get_string(buffer, "localvar_server")
    looks_like_hostname = bool(HOSTNAME_RE.match(target))

    if not looks_like_hostname and plugin != "irc":
        weechat.prnt(buffer, "%sERROR: Run ipinfo in channel not current buffer" %
                     weechat.prefix("error"))
        return weechat.WEECHAT_RC_OK

    if (not looks_like_hostname and plugin == "irc" and server
            and weechat.info_get("irc_is_nick", target) == "1"):
        return resolve_nick_then_lookup(buffer, server, target)

    # Treat anything else (hostname, or a nick-shaped string we can't
    # confirm via irc_is_nick, e.g. run outside an IRC buffer) as a
    # hostname and forward-resolve it before querying providers.
    return resolve_hostname_then_lookup(buffer, target, target)


if __name__ == "__main__":
    if weechat.register(
        SCRIPT_NAME,
        SCRIPT_AUTHOR,
        SCRIPT_VERSION,
        SCRIPT_LICENSE,
        SCRIPT_DESC,
        "",
        ""
    ):
        weechat.hook_command(
            "ipinfo",
            "Lookup IP/hostname/nickname info with provider fallback",
            "[ip|hostname|nickname]",
            "Examples:\n"
            "  /ipinfo 8.8.8.8\n"
            "  /ipinfo example.com\n"
            "  /ipinfo somenick\n"
            "  /ipinfo",
            "%(nicks)",
            "ipinfo_cmd_cb",
            ""
        )