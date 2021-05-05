def pam_sm_authenticate(pamh, flags, argv):
    pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, "Hello Dude !"))
    msg = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_ON, "type 'more' if you want more:"))
    response= msg.resp
    if response == "more":
        msg2 = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_ON, "type somehting:"))
    pwd_msg = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "password: (hint try xxx)"))
    if pwd_msg.resp == "xxx":
        return pamh.PAM_SUCCESS
    else:
        return pamh.PAM_AUTH_ERR
