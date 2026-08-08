import weechat

def test_cb(data, command, return_code, out, err):
    weechat.prnt("", "rc=%s" % return_code)
    if out:
        weechat.prnt("", "OUT: %s" % out[:200])
    if err:
        weechat.prnt("", "ERR: %s" % err[:200])
    return weechat.WEECHAT_RC_OK

weechat.hook_process("url:https://ipinfo.io/8.8.8.8/json", 15000, "test_cb", "")