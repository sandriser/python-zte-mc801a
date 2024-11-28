import requests
import urllib3
import SSL
import hashlib
import codecs
from retry import retry
from python_zte_mc801a.lib.data_processing import get_ad_value
from python_zte_mc801a.lib.constants import ALL_DATA_FIELDS
import logging

class CustomHttpAdapter (requests.adapters.HTTPAdapter):
    # "Transport adapter" that allows us to use custom ssl_context.

    def __init__(self, ssl_context=None, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = urllib3.poolmanager.PoolManager(
            num_pools=connections, maxsize=maxsize,
            block=block, ssl_context=self.ssl_context)


def get_legacy_session():
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.options |= 0x4  # OP_LEGACY_SERVER_CONNECT
    session = requests.session()
    session.mount('https://', CustomHttpAdapter(ctx))
    return session

log = logging.getLogger("rich")


@retry(tries=3, delay=2)
def get_auth_cookies(router_ip: str, user_password: str) -> dict:
    """Retrieve authentication cookies from the router

    Args:
        router_ip (str): IP (or hostname) of the router
        user_password (str): Admin user password

    Raises:
        Exception: Unable to retrieve authentication cookies

    Returns:
        dict: Authentication cookies
    """
    
    # Request the current LD
    with get_legacy_session() as s:
        s.get(
            f"https://{router_ip}/goform/goform_get_cmd_process?isTest=false&cmd=LD",
            cookies={"stok": ""},
            headers={"referer": f"https://{router_ip}/"},
            verify=False,
        ) as r_ld
    
    # The password is hashed twice
    m = hashlib.sha256()
    m.update(user_password.encode())

    m2 = hashlib.sha256()
    m2.update(f'{m.hexdigest().upper()}{r_ld.json()["LD"]}'.encode())

    pwd = m2.hexdigest().upper()

    # Login request
    with get_legacy_session() as s:
        s.get(
            f"https://{router_ip}/goform/goform_set_cmd_process?isTest=false&goformId=LOGIN&password={pwd}",
            cookies={"stok": ""},
            headers={"referer": f"https://{router_ip}/"},
            verify=False,
        ) as r_login

    if (not "result" in r_login.json().keys()) or (r_login.json()["result"] != "0"):
        raise Exception("Login unsuccessful")

    return r_login.cookies.get_dict()


def get_signal_data(router_ip: str, auth_cookies: dict) -> dict:
    """Retrieve router data related to signals

    Args:
        router_ip (str): IP (or hostname) of the router
        auth_cookies (dict): Authentication cookies obtained using `get_auth_cookies`

    Returns:
        dict: Signal data dictionary (unprocessed)
    """
    
    with get_legacy_session() as s:
        s.get(  
            f'https://{router_ip}/goform/goform_get_cmd_process?isTest=false&cmd={",".join(ALL_DATA_FIELDS)}&multi_data=1',
            cookies=auth_cookies,
            headers={f"referer": f"https://{router_ip}/"},
            verify=False,
        ) as r_data

    return r_data.json()


def get_latest_sms_messages(router_ip, auth_cookies, n=3) -> list:
    """Retrieve latest SMS messages

    Args:
        router_ip (_type_): IP (or hostname) of the router
        auth_cookies (_type_): Authentication cookies obtained using `get_auth_cookies`
        n (int, optional): Number of messages to retrieve. Defaults to 3.

    Returns:
        list: Dictionaries of messages
    """
    with get_legacy_session() as s:
        s.get(  
            f"https://{router_ip}/goform/goform_get_cmd_process?isTest=false&cmd=sms_data_total&page=0&data_per_page=500&mem_store=1&tags=10&order_by=order+by+id+desc",
            cookies=auth_cookies,
            headers={f"referer": f"https://{router_ip}/"},
            verify=False,
        ) as r_data

    json_data = r_data.json()

    messages = json_data["messages"]

    if len(messages) > n:
        messages = messages[0:n]

    # Convert hex representation to ASCII
    for index, msg in enumerate(messages):
        messages[index]["content"] = str(
            codecs.decode(msg["content"], "hex").replace(b"\x00", b""), "latin-1"
        )

    return messages


def set_5g_band(
    router_ip: str, auth_cookies: dict, bands: str, verbose: bool = False
) -> bool:
    raw_data = get_signal_data(router_ip=router_ip, auth_cookies=auth_cookies)
    ad = get_ad_value(raw_data)

    headers = {
        "Accept": "*/*",
        "Accept-Language": "en-GB,en;q=0.9,f^r-FR;q=0.8,fr;q=0.7,en-US;q=0.6",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": "http://192.168.0.1",
        "Pragma": "no-cache",
        "Referer": "http://192.168.0.1/",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36 Edg/109.0.1518.70",
        "X-Requested-With": "XMLHttpRequest",
    }

    request_data = {
        "isTest": "false",
        "goformId": "WAN_PERFORM_NR5G_BAND_LOCK",
        "nr5g_band_mask": bands,
        "AD": ad,
    }

    
    with get_legacy_session() as s:
        s.post(  
            f"https://{router_ip}/goform/goform_set_cmd_process",
            data=request_data,
            cookies=auth_cookies,
            headers=headers,
        ) as r

    if (
        r.status_code == 200
        and "result" in r.json().keys()
        and r.json()["result"] == "success"
    ):
        if verbose:
            log.info(f"Successfully set 5G bands to {bands}")
        return True
    else:
        if verbose:
            log.error(f"Error setting 5G band to {bands}: {r.content}")
        return False
