# -*- coding: utf-8 -*
def construct_http_header(host):

    request = "GET / HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\nConnection: Keep-Alive\r\nUser-Agent: curl/7.58.0\r\n\r\n".format(host)
    return request