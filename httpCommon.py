
import re


class HTTPMETHOD(object):
    GET = "GET"
    POST = "POST"
    HEAD = "HEAD"
    PUT = "PUT"
    DELETE = "DELETE"
    TRACE = "TRACE"
    OPTIONS = "OPTIONS"
    CONNECT = "CONNECT"
    PATCH = "PATCH"


class HTTP_HEADER(object):
    ACCEPT = "Accept"
    ACCEPT_CHARSET = "Accept-Charset"
    ACCEPT_ENCODING = "Accept-Encoding"
    ACCEPT_LANGUAGE = "Accept-Language"
    AUTHORIZATION = "Authorization"
    CACHE_CONTROL = "Cache-Control"
    CONNECTION = "Connection"
    CONTENT_ENCODING = "Content-Encoding"
    CONTENT_LENGTH = "Content-Length"
    CONTENT_RANGE = "Content-Range"
    CONTENT_TYPE = "Content-Type"
    COOKIE = "Cookie"
    EXPIRES = "Expires"
    HOST = "Host"
    IF_MODIFIED_SINCE = "If-Modified-Since"
    IF_NONE_MATCH = "If-None-Match"
    LAST_MODIFIED = "Last-Modified"
    LOCATION = "Location"
    PRAGMA = "Pragma"
    PROXY_AUTHORIZATION = "Proxy-Authorization"
    PROXY_CONNECTION = "Proxy-Connection"
    RANGE = "Range"
    REFERER = "Referer"
    REFRESH = "Refresh"  # Reference: http://stackoverflow.com/a/283794
    SERVER = "Server"
    SET_COOKIE = "Set-Cookie"
    TRANSFER_ENCODING = "Transfer-Encoding"
    URI = "URI"
    USER_AGENT = "User-Agent"
    VIA = "Via"
    X_POWERED_BY = "X-Powered-By"
    X_DATA_ORIGIN = "X-Data-Origin"



Proxies = {
  "http": "http://127.0.0.1:8888",
  "https": "http://127.0.0.1:8888",
}


def filterStringValue(value, charRegex, replacement=""):
    """
    Returns string value consisting only of chars satisfying supplied
    regular expression (note: it has to be in form [...])
    >>> filterStringValue('wzydeadbeef0123#', r'[0-9a-f]')
    'deadbeef0123'
    """
    retVal = value

    if value:
        retVal = re.sub(charRegex.replace("[", "[^") if "[^" not in charRegex else charRegex.replace("[^", "["), replacement, value)

    return retVal



def parseRequestFile(request):
    getPostReq = False
    url = None
    host = None
    method = None
    data = None
    cookie = None
    params = False
    newline = None
    lines = request.split('\n')
    headers = {}

    for index in range(len(lines)):
        line = lines[index]

        if not line.strip() and index == len(lines) - 1:
            break

        newline = "\r\n" if line.endswith('\r') else '\n'
        line = line.strip('\r')
        match = re.search(r"\A([A-Z]+) (.+) HTTP/[\d.]+\Z", line) if not method else None

        if len(line.strip()) == 0 and method and method != HTTPMETHOD.GET and data is None:
            data = ""
            params = True

        elif match:
            method = match.group(1)
            url = match.group(2)
            getPostReq = True

        # POST parameters
        elif data is not None and params:
            data += "%s%s" % (line, newline)

        # GET parameters
        elif "?" in line and "=" in line and ": " not in line:
            params = True

        # Headers
        elif re.search(r"\A\S+:", line):
            key, value = line.split(":", 1)
            value = value.strip().replace("\r", "").replace("\n", "")



            # Cookie and Host headers
            if key.upper() == HTTP_HEADER.COOKIE.upper():
                cookie = value
            elif key.upper() == HTTP_HEADER.HOST.upper():
                if '://' in value:
                    scheme, value = value.split('://')[:2]
                splitValue = value.split(":")
                host = splitValue[0]

                if len(splitValue) > 1:
                    port = filterStringValue(splitValue[1], "[0-9]")

            # Avoid to add a static content length header to
            # headers and consider the following lines as
            # POSTed data
            if key.upper() == HTTP_HEADER.CONTENT_LENGTH.upper():
                params = True

            # Avoid proxy and connection type related headers
            elif key not in (HTTP_HEADER.PROXY_CONNECTION, HTTP_HEADER.CONNECTION, HTTP_HEADER.IF_MODIFIED_SINCE, HTTP_HEADER.IF_NONE_MATCH):
                headers[key]= value


    data = data.rstrip("\r\n") if data else data

    return (url, method, data, cookie, headers)



if __name__ == '__main__':
    content = '''GET https://www.fiddler2.com/UpdateCheck.aspx?isBeta=False HTTP/1.1
User-Agent: Fiddler/5.0.20204.45441 (.NET 4.8; WinNT 10.0.19041.0; zh-CN; 4xAMD64; Auto Update; Full Instance; Extensions: APITesting, AutoSaveExt, EventLog, FiddlerOrchestraAddon, HostsFile, RulesTab2, SAZClipboardFactory, SimpleFilter, Timeline)
Pragma: no-cache
Host: www.fiddler2.com
Accept-Language: zh-CN
Referer: http://fiddler2.com/client/TELE/5.0.20204.45441
Accept-Encoding: gzip, deflate
Connection: close'''


    print(parseRequestFile(content))
    