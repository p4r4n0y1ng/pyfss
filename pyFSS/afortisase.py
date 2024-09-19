import asyncio
import logging
import os
import queue
import re
import requests
import urllib3
import json
from datetime import datetime, timedelta, MINYEAR
from pyFSS.fortisase import RequestResponse
from logging.handlers import QueueHandler, QueueListener, RotatingFileHandler
from typing import Any
from json import JSONDecodeError
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from urllib.parse import urlparse


class AFortiSASETaskItem(object):
    """
    A class wrapping the concepts of a Task Item for a SASE operation. Each FSS task will have knowledge of the
    method (GET, POST, PUT, DELETE), the url (endpoint) and the body that needs to be sent if there is one. Any kwargs
    received will be added to the body UNLESS the body portion already has that key utilized.

    Attributes:
        method (str): String representing the method used. Must be one of GET, POST, PUT, DELETE.
        url (str): The FortiSASE endpoint that will be called as part of the task.
        body (Dict[str, str]): The body portion of the call. If the body isn't needed None by default.
        retry (bool): Whether to retry if a failure occurs. Defaults to True.
        retry_times (int): The amount of times the call will be retried before the task is marked as done.
        was_successful (bool): Stamp to determine if a successful operation took place.
    """
    def __init__(self, method: str, url: str, body: dict[str, str] | None = None, retry: bool = True,
                 retry_times: int = 10, **kwargs):
        self.body = body
        self.method = method
        self.url = url
        self.retry = retry
        self.retry_times = retry_times
        if kwargs:
            if self.body is None:
                self.body = {}
            for k, v in kwargs.items():
                if k not in self.body:
                    self.body[k] = v
        self.was_successful = False


class AFortiSASE(object):
    def __init__(self, login_token: str, instance_hostname: str | None = None, debug: bool = False,
                 request_timeout: float = 300.0, disable_request_warnings: bool = False, use_ssl: bool = True,
                 verify_ssl: bool = True, logger_location: str | None = None, threads: int = 10) -> None:
        super(AFortiSASE, self).__init__()
        self._logger = None
        self._threads = threads
        self._debug = debug
        self._headers = {"content-Type": "application/json", }
        self._use_ssl = use_ssl
        self._verify_ssl = verify_ssl
        self._logger_location = logger_location
        self._log = None
        self._apiId: str | None = None
        self._apiPassword: str | None = None
        self._scheme = "https" if use_ssl else "http"
        self._instance_hostname = instance_hostname
        self._base_url: str = ""
        self._url: str = ""
        self._login_token = login_token
        self._session_token_timeout: datetime = AFortiSASE._get_min_datetime()
        self._access_token: str | None = None
        self._access_token_is_hard_token: bool = False
        self._refresh_token: str | None = None
        self._request_timeout = request_timeout
        self._session: requests.Session | None = None
        self._req_resp_object = RequestResponse()
        self._async_session = ClientSession(headers=self._headers, timeout=ClientTimeout(self._request_timeout),
                                            connector=TCPConnector(limit=self._threads, ssl=self._use_ssl,
                                                                   verify_ssl=self._verify_ssl))
        if disable_request_warnings:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @staticmethod
    def _get_min_datetime():
        return datetime(1, 1, 1, 0, 0)

    def log(self, msg: str, log_level: int = -1) -> None:
        if self._logger is not None:
            self._logger.log(log_level if log_level >= 0 else self._logger.level, msg)

    @property
    def debug(self) -> bool:
        return self._debug

    @debug.setter
    def debug(self, val: bool) -> None:
        self._debug = val

    @property
    def request_timeout(self) -> float:
        return self._request_timeout

    @request_timeout.setter
    def request_timeout(self, val: float) -> None:
        self._request_timeout = val

    @property
    def access_token(self) -> str | None:
        return self._access_token

    async def _get_base_url(self) -> str:
        # method here only to provide a means to have different base_urls in the future
        prod_base_url = "portal.prod.fortisase.com"
        if self._instance_hostname is None:
            self._instance_hostname = prod_base_url
        else:
            self._instance_hostname = self._instance_hostname[:-1] if self._instance_hostname.endswith("/") else (
                self._instance_hostname)
        self.log(f"Setting instance hostname to {self._instance_hostname}")
        self.log(f"Setting base URL to {self._scheme}://{self._instance_hostname}/")
        return f"{self._scheme}://{self._instance_hostname}/"

    @property
    def session_token_times_out(self) -> bool:
        return False if self._session_token_timeout == -1.0 else True

    def set_url(self, url: str):
        u = f"{self._base_url}{'' if self._base_url.endswith('/') else '/'}{url[1:] if url.startswith("/") else url}"
        p_url = urlparse(u)
        self._url = f"{p_url.scheme}://{p_url.netloc}{p_url.path if p_url.path.startswith("/") else '/' + p_url.path}"

    async def add_header(self, key: str | None = None, value: str | None = None, **kwargs: str) -> None:
        if key is not None and value is not None:
            kwargs.update({key: value})
        if kwargs:
            self.log(f"Adding headers: {kwargs}")
            self._headers.update(kwargs)

    async def remove_header(self, key: str | None = None, *args: str) -> None:
        for arg in args:
            if self._headers.get(arg, None) is not None:
                self.log(f"Removing header {arg} from {self._headers.get(arg)}")
                self._headers.pop(arg)
        if key is not None:
            if self._headers.get(key, None) is not None:
                self.log(f"Removing header {key} from {self._headers.get(key)}")
                self._headers.pop(key)

    # def get_log(self, logger_name: str = "pyfss", lvl: LogLevel = LogLevel.INFO) -> logging.Logger:
    #     if self._logger is not None:
    #         return self._logger
    #     else:
    #         self._logger = Logger.with_default_handlers(name=logger_name, level=lvl)
    #         return self._logger

    def _create_log(self):
        if self._logger is None:
            self._que = queue.Queue()
            self._queue_handler = QueueHandler(self._que)
            rfh = RotatingFileHandler(self._logger_location, 'a', 1 * 1024 * 1024, 10)
            self._que_listener = QueueListener(self._que, rfh, logging.StreamHandler())
            self._logger = logging.getLogger()
            self._logger.addHandler(self._queue_handler)
            rfh.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
            self._logger.setLevel(logging.DEBUG if self._debug else logging.INFO)
            self._que_listener.start()

    def set_log_level(self, lvl: int) -> None:
        if self._logger is not None:
            self._logger.level = lvl

    @property
    def req_resp_object(self):
        return self._req_resp_object

    @property
    def sase_session(self) -> requests.Session:
        if self._session is None:
            with requests.sessions.session() as sess:
                self._session = sess
        return self._session

    @staticmethod
    def jprint(json_obj: Any) -> str:
        try:
            return json.dumps(json_obj, indent=2, sort_keys=True)
        except TypeError as te:
            return json.dumps({"Type Information": str(te)})

    async def dlog(self) -> None:
        if self._logger is not None:
            if self.req_resp_object.error_msg is not None:
                self.log(self.req_resp_object.error_msg, logging.ERROR)
                return
            self.log(self.req_resp_object.request_string, logging.INFO)
            if self.req_resp_object.request_json is not None:
                self.log(self.jprint(self.req_resp_object.request_json), logging.INFO)
            self.log(self.req_resp_object.response_string, logging.INFO)
            if self.req_resp_object.response_json is not None:
                self.log(self.jprint(self.req_resp_object.response_json), logging.INFO)

    async def dprint(self) -> None:
        await self.dlog()
        if not self.debug:
            return
        if self.req_resp_object.error_msg is not None:
            print(self.req_resp_object.error_msg)
            # return
        print("-" * 100 + "\n")
        print(self.req_resp_object.request_string)
        if self.req_resp_object.request_json is not None:
            print(self.jprint(self.req_resp_object.request_json))
        print("\n" + self.req_resp_object.response_string)
        if self.req_resp_object.response_json is not None:
            print(self.jprint(self.req_resp_object.response_json))
        print("\n" + "-" * 100 + "\n")

    async def test_dprint(self, request_string=None, request_json=None, response_string="RESPONSE:", response_json=None,
                          error_msg=None) -> None:
        # await self.dlog()
        if not self.debug:
            return
        print("-" * 100 + "\n")
        print(request_string)
        if request_json is not None:
            print(self.jprint(request_json))
        print("\n" + response_string)
        if response_json is not None:
            print(self.jprint(response_json))
        if error_msg is not None:
            print(error_msg)
        print("\n" + "-" * 100 + "\n")

    def _get_oauth_token(self, refresh: bool = False) -> None:
        oauth_token_path = "https://customerapiauth.fortinet.com/api/v1/oauth/token/"
        if self._apiId is not None and self._apiPassword is not None:
            body = dict()
            body["client_id"] = "FortiSASE"
            body["grant_type"] = "refresh_token" if refresh else "password"
            if refresh:
                body["refresh_token"] = self._refresh_token
            else:
                body["username"] = self._apiId,
                body["password"] = self._apiPassword,
                body["client_secret"] = ""
            self.log(f"Making {'refresh' if refresh else 'initial'} request to for oauth token")
            resp = self.sase_session.post(oauth_token_path, data=body)
            try:
                json_resp = resp.json()
                self.log(f"Received session token: {json_resp.get('access_token', 'Invalid Access Token')}. "
                         f"Token expires at {datetime.now() + timedelta(seconds=json_resp.get('expires_in', 0.0))}")
                self.log(f"Received refresh token: {json_resp.get('refresh_token', 'Invalid Refresh Token')}")
                self.log(f"Auth Message was: {json_resp.get('message', 'Invalid Message')}")
                self._access_token = json_resp.get('access_token', None)
                self._refresh_token = json_resp.get('refresh_token', None)
                self._session_token_timeout = datetime.now() + timedelta(seconds=json_resp.get("expires_in", 0.0))
            except JSONDecodeError:
                self.log(f"Failed to get access token. Received JSON Decode Error when requesting information "
                         f"from {oauth_token_path}")
                self._access_token = None
                self._refresh_token = None
                self._session_token_timeout = AFortiSASE._get_min_datetime()
        else:
            self.log(f"A request to get an oauth token was made but conditions are not appropriate.")

    async def _get_token_from_file(self, file_path: str) -> None:
        if os.path.isfile(file_path):
            try:
                with (open(file_path, 'r') as f):
                    for line in f.readlines():
                        if "apiId" in line:
                            self._apiId = line.split(":")[1].strip()
                            self.log(f"Retrieved apiId from {file_path}")
                            self._access_token_is_hard_token = False
                        elif "password" in line:
                            self._apiPassword = line.split(":")[1].strip()
                            self.log(f"Retrieved api password from {file_path}")
                            break
                        else:
                            self.log(f"Retrieving token from {file_path}")
                            self._access_token = line
                            self._session_token_timeout = AFortiSASE._get_min_datetime()
                            self._access_token_is_hard_token = True
                            break
                if not self._access_token_is_hard_token:
                    self._get_oauth_token()
            except OSError:
                self.log(f"Received an OSError when attempting to open file {file_path}")
        else:
            self.log(f"Received an invalid file path {file_path} to access token information")

    async def get_token(self, token_provided: str) -> None:
        # returns a token string as well as if this is an IAM session that will have a timeout value
        win_path_regex = r'^[a-zA-Z]:\\(?:[^<>:"/\\|?*\r\n]+\\)*[^<>:"/\\|?*\r\n]*$'
        nix_path_regex = r'^(/[^/\0]+)+/?$'
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.search(win_path_regex, token_provided) or re.search(nix_path_regex, token_provided):
            await self._get_token_from_file(token_provided)
        elif re.search(email_regex, token_provided):
            self._get_oauth_token()
            self._access_token_is_hard_token = False
        else:
            # assuming the string sent in is the hard coded token
            self.log(f"Setting token provided in login request as access token")
            self._access_token = token_provided
            self._access_token_is_hard_token = True
            self._session_token_timeout = AFortiSASE._get_min_datetime()
            self._refresh_token = None

    async def revoke_token(self) -> None:
        oauth_token_path = "https://customerapiauth.fortinet.com/api/v1/oauth/revoke_token/"
        if self._access_token is not None:
            body = dict()
            body["client_id"] = "FortiSASE"
            body["token"] = self._access_token
            if not self._access_token_is_hard_token:
                self.log(f"Making revocation attempt to revoke current token")
                async with self._async_session.post(oauth_token_path, json=body) as resp:
                    if resp.status == 200:
                        print("Revoked token")
                        self.log(f"Revoked token successfully")
                    else:
                        self.log(f"Revocation of current token was unsuccessful. This is not an error message, "
                                       f"possibly the token was already timed out or not valid")
        self._refresh_token = None
        self._access_token = None
        self._session_token_timeout = AFortiSASE._get_min_datetime()

    async def login(self) -> None:
        self._base_url = await self._get_base_url()
        if self._access_token is None:
            await self.get_token(self._login_token)
        if self._logger_location is not None:
            self._create_log()
        self.log(f"Setting instance hostname to {self._instance_hostname}")

    async def logout(self) -> None:
        await self.revoke_token()

    async def __aenter__(self) -> "AFortiSASE":
        _ = await self.login()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.logout()
        if self._logger is not None:
            self._que_listener.stop()
        await self._async_session.close()

    async def _check_session_timeout(self) -> None:
        if self.session_token_times_out and datetime.now() >= self._session_token_timeout:
            self._get_oauth_token(refresh=True)

    async def _is_invalid_post_request(self, method: str) -> tuple[bool, str]:
        if self._access_token is None:
            msg = (f"A request was made to perform a {method} to the endpoint {self._url} on a FortiSASE "
                   f"instance without a valid access token being available.")
            self.log(msg, logging.CRITICAL)
            self.req_resp_object.error_msg = msg
            await self.dprint()
            return True, msg
        else:
            return False, ""

    async def _async_handle_response(self, response, request_string, request_json):
        if response.status == 200:
            js = await response.json()
            # self.req_resp_object.response_json = js
            # await self.dprint()
            await self.test_dprint(request_string=request_string, request_json=request_json, response_json=js)
            return response.status, js
        else:
            text = await response.text()
            # self.req_resp_object.response_json = {"status": response.status, "text": text}
            # self.req_resp_object.error_msg = f"Request failed: {response.status} {text}"
            # await self.dprint()
            await self.test_dprint(request_string=request_string, request_json=request_json,
                                   error_msg=f"Request failed: {response.status} {text}")
            return response.status, text

    async def _post_request(self, method: str, params: dict[str, Any]) -> tuple[int, str | dict[str, str | int]]:
        await asyncio.sleep(1)
        await self._check_session_timeout()
        invalid, msg = await self._is_invalid_post_request(method)
        if invalid:
            return -1, msg
        if self._headers.get("Authorization", None) is None:
            await self.add_header("Authorization", "Bearer " + self.access_token)
        self.req_resp_object.reset()
        json_request = {}
        response = None
        self.req_resp_object.request_json = json_request
        try:
            if params:
                json_request.update(params)
            self.req_resp_object.request_string = f"{method.upper()} REQUEST: {self._url}"
            self.req_resp_object.request_json = json_request
            async with self._async_session.request(method, self._url, headers=self._headers,
                                                   data=json.dumps(json_request) if json_request else {}) as response:
                return await self._async_handle_response(response, f"{method.upper()} REQUEST: {self._url}",
                                                         json_request)
        except:
            # todo: add exceptions
            self.req_resp_object.error_msg = "Exception caught"
            await self.dprint()
            return -1, msg

    def common_datagram_params(self, url, **kwargs) -> dict[str, Any]:
        self.set_url(url)
        params = {}
        if kwargs:
            params = {k.replace("__", "-"): v for k, v in kwargs.items()}
        return params

    async def get(self, url: str, **kwargs) -> tuple[int, str | dict[str, str | int]]:
        return await self._post_request("get", self.common_datagram_params(url, **kwargs))

    async def post(self, url: str, **kwargs) -> tuple[int, str | dict[str, str | int]]:
        return await self._post_request("post", self.common_datagram_params(url, **kwargs))

    async def put(self, url: str, **kwargs) -> tuple[int, str | dict[str, str | int]]:
        return await self._post_request("put", self.common_datagram_params(url, **kwargs))

    async def delete(self, url: str, **kwargs) -> tuple[int, str | dict[str, str | int]]:
        return await self._post_request("delete", self.common_datagram_params(url, **kwargs))