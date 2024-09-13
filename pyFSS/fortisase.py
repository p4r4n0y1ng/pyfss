import requests
import urllib3
import re
import json
import logging
import os
from json import JSONDecodeError
from datetime import datetime, timedelta, MINYEAR
from typing import Any
from urllib.parse import urlparse


class RequestResponse(object):
    """Simple wrapper around the request response object so debugging and logging can be done with simplicity"""
    def __init__(self) -> None:
        self._identifier: int = 0
        self._request_string: str = "REQUEST:"
        self._response_string: str = "RESPONSE:"
        self._request_json: str | None = None
        self._response_json: str | None = None
        self._error_msg: str | None = None

    def reset(self) -> None:
        self._request_string = "REQUEST:"
        self.error_msg = None
        self.response_json = None
        self.request_json = None

    @property
    def request_string(self) -> str:
        return self._request_string

    @request_string.setter
    def request_string(self, val: str) -> None:
        self._request_string = val

    @property
    def response_string(self) -> str:
        return self._response_string

    @property
    def request_json(self) -> str:
        return self._request_json

    @request_json.setter
    def request_json(self, val: str):
        self._request_json = val

    @property
    def response_json(self) -> str:
        return self._response_json

    @response_json.setter
    def response_json(self, val: str):
        self._response_json = val

    @property
    def error_msg(self) -> str:
        return self._error_msg

    @error_msg.setter
    def error_msg(self, val: str):
        self._error_msg = val


class FortiSASEFormatter(object):
    def __init__(self, format_string_input: str) -> None:
        super(FortiSASEFormatter, self).__init__()
        self._format_string_input = format_string_input
        self._filter_string = ""
        self._format_string = ""
        self._load_strings()

    def _load_strings(self) -> None:
        split_strings = self._format_string_input.split("&")
        for split_string in split_strings:
            if split_string.startswith("format="):
                self._format_string = split_string.split("=")[1]
            elif split_string.startswith("filter="):
                self._filter_string = split_string[7:]
            else:
                pass

    def provide_format(self, response_to_format: dict[str, Any] | list[dict[str, Any]]) -> dict[str, Any] | list[dict[str, Any]]:
        keys_to_leave = self._format_string.split("|")
        if type(response_to_format) is dict:
            return {k: v for k, v in response_to_format.items() if k in keys_to_leave}
        elif type(response_to_format) is list:
            return [{k: v for k, v in i.items() if k in keys_to_leave} for i in response_to_format]
        else:
            # input is incorrect
            return response_to_format

    def __str__(self) -> str:
        return f"{self._format_string}&{self._filter_string}"

    def __repr__(self) -> str:
        return f"{self._format_string}&{self._filter_string}"

class FortiSASE(object):
    def __init__(self, login_token: str, instance_hostname: str | None = None, debug: bool = False,
                 request_timeout: float = 300.0, disable_request_warnings: bool = False, use_ssl: bool = True,
                 verify_ssl: bool = True, logger: logging.Logger = None) -> None:
        super(FortiSASE, self).__init__()
        self._debug = debug
        self._headers = {"content-Type": "application/json", }
        self._use_ssl = use_ssl
        self._verify_ssl = verify_ssl
        self._logger = logger
        self._apiId: str | None = None
        self._apiPassword: str | None = None
        self._scheme = "https" if use_ssl else "http"
        self._instance_hostname = instance_hostname
        self._base_url: str =  self._get_base_url()
        self._url: str = ""
        self._login_token = login_token
        self._session_token_timeout: datetime = FortiSASE._get_min_datetime()
        self._access_token: str | None = None
        self._access_token_is_hard_token: bool = False
        self._refresh_token: str | None = None
        self._request_timeout = request_timeout
        self._session: requests.Session | None = None
        self._formatter: FortiSASEFormatter | None = None
        self._req_resp_object = RequestResponse()
        if disable_request_warnings:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _get_base_url(self) -> str:
        # method here only to provide a means to have different base_urls in the future
        prod_base_url = "portal.prod.fortisase.com"
        if self._instance_hostname is None:
            self._instance_hostname = prod_base_url
        else:
            self._instance_hostname = self._instance_hostname[:-1] if self._instance_hostname.endswith("/") else (
                self._instance_hostname)
        if self._logger is not None:
            self.log(f"Setting instance hostname to {self._instance_hostname}")
            self.log(f"Setting base URL to {self._scheme}://{self._instance_hostname}/")
        return f"{self._scheme}://{self._instance_hostname}/"

    @staticmethod
    def _get_min_datetime():
        return datetime(1, 1, 1, 0, 0)

    @property
    def debug(self) -> bool:
        return self._debug

    @debug.setter
    def debug(self, val: bool) -> None:
        self._debug = val

    @property
    def request_timeout(self) -> float:
        return self.request_timeout

    @request_timeout.setter
    def request_timeout(self, val: float) -> None:
        self.request_timeout = val

    @property
    def sase_session(self) -> requests.Session:
        if self._session is None:
            with requests.sessions.session() as sess:
                self._session = sess
        return self._session

    @property
    def access_token(self) -> str | None:
        self.login()
        return self._access_token

    @property
    def session_token_times_out(self) -> bool:
        return False if self._session_token_timeout == -1.0 else True

    def set_url(self, url: str):
        self._formatter = None
        u = f"{self._base_url}{'' if self._base_url.endswith('/') else '/'}{url[1:] if url.startswith("/") else url}"
        p_url = urlparse(u)
        self._url = f"{p_url.scheme}://{p_url.netloc}{p_url.path if p_url.path.startswith("/") else '/' + p_url.path}"
        if p_url.query != "":
            self._formatter = FortiSASEFormatter(p_url.query)

    def add_header(self, key: str | None = None, value: str | None = None, **kwargs: str) -> None:
        if key is not None and value is not None:
            kwargs.update({key: value})
        if kwargs:
            self.log(f"Adding headers: {kwargs}")
            self._headers.update(kwargs)

    def remove_header(self, key: str | None = None, *args: str) -> None:
        for arg in args:
            if self._headers.get(arg, None) is not None:
                self.log(f"Removing header {arg} from {self._headers.get(arg)}")
                self._headers.pop(arg)
        if key is not None:
            if self._headers.get(key, None) is not None:
                self.log(f"Removing header {key} from {self._headers.get(key)}")
                self._headers.pop(key)

    def get_log(self, logger_name: str = "fss", lvl: int = logging.INFO) -> logging.Logger:
        if self._logger is not None:
            return self._logger
        else:
            self._logger = logging.getLogger(logger_name)
            self._logger.setLevel(lvl)
            return self._logger

    def set_log_level(self, log_level: int) -> None:
        if self._logger is not None:
            self._logger.setLevel(log_level)

    def reset_log(self) -> None:
        self._logger = None

    def add_handler(self, handler: logging.Handler) -> None:
        if self._logger is None:
            self._logger = logging.getLogger("pyfss")
            self._logger.setLevel(logging.INFO)
        self._logger.addHandler(handler)

    def remove_handler(self, handler: logging.Handler) -> None:
        if self._logger is not None:
            self._logger.removeHandler(handler)

    def log(self, msg: str, log_level: int = -1) -> None:
        if self._logger is not None:
            level = log_level if log_level >= 0 else self._logger.level
            self._logger.log(level, msg)

    @property
    def req_resp_object(self):
        return self._req_resp_object

    @staticmethod
    def jprint(json_obj: Any) -> str:
        try:
            return json.dumps(json_obj, indent=2, sort_keys=True)
        except TypeError as te:
            return json.dumps({"Type Information": str(te)})

    def dlog(self) -> None:
        if self._logger is not None:
            if self.req_resp_object.error_msg is not None:
                self._logger.log(logging.ERROR, self.req_resp_object.error_msg)
                return
            self._logger.log(logging.INFO, self.req_resp_object.request_string)
            if self.req_resp_object.request_json is not None:
                self._logger.log(logging.INFO, self.jprint(self.req_resp_object.request_json))
            self._logger.log(logging.INFO, self.req_resp_object.response_string)
            if self.req_resp_object.response_json is not None:
                self._logger.log(logging.INFO, self.jprint(self.req_resp_object.response_json))

    def dprint(self) -> None:
        self.dlog()
        if not self.debug:
            return
        if self.req_resp_object.error_msg is not None:
            print(self.req_resp_object.error_msg)
            return
        print("-" * 100 + "\n")
        print(self.req_resp_object.request_string)
        if self.req_resp_object.request_json is not None:
            print(self.jprint(self.req_resp_object.request_json))
        print("\n" + self.req_resp_object.response_string)
        if self.req_resp_object.response_json is not None:
            print(self.jprint(self.req_resp_object.response_json))
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
                self.log(f"Received session token: {json_resp.get('access_token', 'Invalid Access Token')}. Token "
                         f"expires at {datetime.now() + timedelta(seconds=json_resp.get('expires_in', 0.0))}")
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
                self._session_token_timeout = FortiSASE._get_min_datetime()
        else:
            self.log(f"A request to get an oauth token was made but conditions are not appropriate.")

    def _get_token_from_file(self, file_path: str) -> None:
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
                            self._session_token_timeout = FortiSASE._get_min_datetime()
                            self._access_token_is_hard_token = True
                            break
                if not self._access_token_is_hard_token:
                    self._get_oauth_token()
            except OSError:
                self.log(f"Received an OSError when attempting to open file {file_path}")
        else:
            self.log(f"Received an invalid file path {file_path} to access token information")

    def get_token(self, token_provided: str) -> None:
        # returns a token string as well as if this is an IAM session that will have a timeout value
        win_path_regex = r'^[a-zA-Z]:\\(?:[^<>:"/\\|?*\r\n]+\\)*[^<>:"/\\|?*\r\n]*$'
        nix_path_regex = r'^(/[^/\0]+)+/?$'
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.search(win_path_regex, token_provided) or re.search(nix_path_regex, token_provided):
            self._get_token_from_file(token_provided)
        elif re.search(email_regex, token_provided):
            self._get_oauth_token()
            self._access_token_is_hard_token = False
        else:
            # assuming the string sent in is the hard coded token
            self.log(f"Setting token provided in login request as access token")
            self._access_token = token_provided
            self._access_token_is_hard_token = True
            self._session_token_timeout = FortiSASE._get_min_datetime()
            self._refresh_token = None

    def revoke_token(self) -> None:
        oauth_token_path = "https://customerapiauth.fortinet.com/api/v1/oauth/revoke_token/"
        if self._access_token is not None:
            body = dict()
            body["client_id"] = "FortiSASE"
            body["token"] = self._access_token
            if not self._access_token_is_hard_token:
                self.log(f"Making revocation attempt to revoke current token")
                resp = self.sase_session.post(oauth_token_path, headers=self._headers, json=body)
                if resp.status_code == 200:
                    self.log(f"Revoked token successfully")
                else:
                    self.log(f"Revocation of current token was unsuccessful. This is not an error message, possibly "
                             f"the token was already timed out or not valid")
        self._refresh_token = None
        self._access_token = None
        self._session_token_timeout = FortiSASE._get_min_datetime()

    def login(self) -> None:
        if self._access_token is None:
            self.get_token(self._login_token)

    def logout(self) -> None:
        self.revoke_token()

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()

    def _handle_response(self, resp: requests.Response) -> tuple[int, str | dict[str, str | int]]:
        try:
            response = resp.json()
        except:
            # response not decoded into json return -1 as a code and the response objects text output
            return -1, resp.text
        code = response.get("code", -1)
        if code == 200:
            if self._formatter is not None:
                data = self._formatter.provide_format(response.get("data", {}))
            else:
                data = response.get("data", {})
        else:
            data = response.get("error", resp.text)
        self.req_resp_object.response_json = data
        self.dprint()
        return code, data

    def _check_session_timeout(self) -> None:
        if self.session_token_times_out and datetime.now() >= self._session_token_timeout:
            self._get_oauth_token(refresh=True)

    def _is_invalid_post_request(self, method: str) -> tuple[bool, str]:
        if self._access_token is None:
            msg = (f"A request was made to perform a {method} to the endpoint {self._url} on a FortiSASE "
                   f"instance without a valid access token being available.")
            self.log(msg, log_level=logging.CRITICAL)
            self.req_resp_object.error_msg = msg
            self.dprint()
            return True, msg
        else:
            return False, ""

    def _post_request(self, method: str, params: dict[str, Any]) -> tuple[int, str | dict[str, str | int]]:
        self._check_session_timeout()
        invalid, msg = self._is_invalid_post_request(method)
        if invalid:
            return -1, msg
        if self._headers.get("Authorization", None) is None:
            self.add_header("Authorization", "Bearer " + self.access_token)
        self.req_resp_object.reset()
        json_request = {}
        response = None
        self.req_resp_object.request_json = json_request
        try:
            if params:
                json_request.update(params)
            method_to_call = getattr(self.sase_session, method)
            self.req_resp_object.request_string = f"{method.upper()} REQUEST: {self._url}"
            self.req_resp_object.request_json = json_request
            if json_request:
                response = method_to_call(self._url, headers=self._headers, data=json.dumps(json_request),
                                          verify=self._verify_ssl, timeout=self._request_timeout)
            else:
                response = method_to_call(self._url, headers=self._headers, verify=self._verify_ssl,
                                          timeout=self._request_timeout)
        except:
            # todo: add exceptions
            msg = "Exception caught"
            self.log(msg, log_level=logging.ERROR)
            self.req_resp_object.error_msg = msg
            self.dprint()
            return -1, msg
        return self._handle_response(response)

    def common_datagram_params(self, url, **kwargs) -> dict[str, Any]:
        self.set_url(url)
        params = {}
        if kwargs:
            params = {k.replace("__", "-"): v for k, v in kwargs.items()}
        return params

    def get(self, url: str, **kwargs) -> tuple[int, str | dict[str, str | int]]:
        return self._post_request("get", self.common_datagram_params(url, **kwargs))

    def post(self, url: str, **kwargs) -> tuple[int, str | dict[str, str | int]]:
        return self._post_request("post", self.common_datagram_params(url, **kwargs))

    def put(self, url: str, **kwargs) -> tuple[int, str | dict[str, str | int]]:
        return self._post_request("put", self.common_datagram_params(url, **kwargs))

    def delete(self, url: str, **kwargs) -> tuple[int, str | dict[str, str | int]]:
        return self._post_request("delete", self.common_datagram_params(url, **kwargs))
