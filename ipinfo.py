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
#
# TODO
# - Allow for /ipinfo USERNAME
# - Fix invalid hostname lookups (e.g. /ipinfo example.com) that return "hostname": null
#
###

import json
import shlex
import weechat


SCRIPT_NAME = "ipinfo"
SCRIPT_AUTHOR = "Joshua Canfield"
SCRIPT_VERSION = "0.3"
SCRIPT_LICENSE = "GPL3"
SCRIPT_DESC = "Lookup IP/hostname info with multiple HTTP providers"


REQUESTS = {}
REQ_ID = 0


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


def print_result(buffer, provider, target, payload):
    weechat.prnt(buffer, "ipinfo: %s (provider: %s)" % (target, provider))
    fields = [
        ("ip", "IP"),
        ("hostname", "Hostname"),
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

    print_result(req["buffer"], provider, req["target"], payload)
    del REQUESTS[data]
    return weechat.WEECHAT_RC_OK


def ipinfo_cmd_cb(data, buffer, args):
    global REQ_ID

    target = args.strip() or "self"
    lookup = args.strip()

    REQ_ID += 1
    req_id = str(REQ_ID)

    REQUESTS[req_id] = {
        "buffer": buffer,
        "target": target,
        "providers": providers_for_target(lookup),
        "index": 0,
        "stdout": "",
        "stderr": "",
        "provider": "",
        "url": "",
        "errors": [],
    }

    return start_attempt(req_id)


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
            "Lookup IP/hostname info with provider fallback",
            "[ip|hostname]",
            "Examples:\n"
            "  /ipinfo 8.8.8.8\n"
            "  /ipinfo example.com\n"
            "  /ipinfo",
            "%(*)",
            "ipinfo_cmd_cb",
            ""
        )