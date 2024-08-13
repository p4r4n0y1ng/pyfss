from json import JSONDecodeError

import requests
import re
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Any


class FortiSASE(object):
    def __init__(self, login_token: str, instance_hostname: str | None = None, debug: bool = False,
                 request_timeout: float = 300.0, disable_request_warnings: bool = False, use_ssl: bool = True,
                 logger: logging.Logger = None):
        super(FortiSASE, self).__init__()
        self._debug = debug
        self._headers = {"Content-Type": "application/json", }
        self._use_ssl = use_ssl
        self._logger = logger
        self._apiId: str | None = None
        self._apiPassword: str | None = None
        self._scheme = "https" if use_ssl else "http"
        self._instance_hostname = instance_hostname
        self._base_url: str =  self._get_base_url()
        self._login_token = login_token
        self._session_token_timeout: float = -1.0
        self._session_token: str | None = None
        self._refresh_token: str | None = None
        self._request_timeout = request_timeout
        self._session: requests.Session = requests.session()
        if disable_request_warnings:
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        # self._req_resp_object = RequestResponse()

    def _get_base_url(self) -> str:
        # method here only to provide a means to have different base_urls in the future
        prod_base_url = "portal.prod.fortisase.com"
        if self._instance_hostname is None:
            self._instance_hostname = prod_base_url

        self.log(f"Setting instance hostname to {self._instance_hostname}")
        self.log(f"Setting base URL to {self._scheme}://{self._instance_hostname}/")
        return f"{self._scheme}://{self._instance_hostname}/"

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
    def sess(self) -> requests.Session:
        return self._session

    @property
    def session_token(self) -> str:
        if self._session_token is None:
            self.get_token(self._login_token)
        return self._session_token

    @property
    def session_token_times_out(self) -> bool:
        return False if self._session_token_timeout == -1.0 else True

    def add_header(self, key: str | None = None, value: str | None = None, **kwargs: str) -> None:
        if key is not None and value is not None:
            self.log(f"Adding header: {key}={value}")
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

    def log(self, msg: str) -> None:
        if self._logger is not None:
            self._logger.log(self._logger.level, msg)

    @staticmethod
    def jprint(json_obj: Any) -> str:
        try:
            return json.dumps(json_obj, indent=2, sort_keys=True)
        except TypeError as te:
            return json.dumps({"Type Information": str(te)})

    def dlog(self) -> None:
        pass
        # if self._logger is not None:
        #     if self.req_resp_object.error_msg is not None:
        #         self._logger.log(logging.INFO, self.req_resp_object.error_msg)
        #         return
        #     self._logger.log(logging.INFO, self.req_resp_object.request_string)
        #     if self.req_resp_object.request_json is not None:
        #         self._logger.log(logging.INFO, self.jprint(self.req_resp_object.request_json))
        #     self._logger.log(logging.INFO, self.req_resp_object.response_string)
        #     if self.req_resp_object.response_json is not None:
        #         self._logger.log(logging.INFO, self.jprint(self.req_resp_object.response_json))

    def dprint(self) -> None:
        pass
        # self.dlog()
        # if not self.debug:
        #     return
        # if self.req_resp_object.error_msg is not None:
        #     print(self.req_resp_object.error_msg)
        #     return
        # print("-" * 100 + "\n")
        # print(self.req_resp_object.request_string)
        # if self.req_resp_object.request_json is not None:
        #     print(self.jprint(self.req_resp_object.request_json))
        # print("\n" + self.req_resp_object.response_string)
        # if self.req_resp_object.response_json is not None:
        #     print(self.jprint(self.req_resp_object.response_json))
        # print("\n" + "-" * 100 + "\n")

    def _get_oauth_token(self, refresh: bool = False) -> None:
        oauth_token_path = "https://customerapiauth.fortinet.com/api/v1/oauth/token/"
        if self.session_token_times_out and datetime.now() >= self._session_token_timeout and not refresh:
            self._get_oauth_token(refresh=True)
        elif self._apiId is not None and self._apiPassword is not None:
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
            resp = requests.post(oauth_token_path, data=body)
            try:
                json_resp = resp.json()
                self.log(f"Received session token: {json_resp.get('access_token', 'Invalid Access Token')}. Token "
                         f"expires at {datetime.now() + timedelta(seconds=json_resp.get('expires_in', 0.0))}")
                self.log(f"Received refresh token: {json_resp.get('refresh_token', 'Invalid Refresh Token')}")
                self.log(f"Auth Message was: {json_resp.get('message', 'Invalid Message')}")
                self._session_token = json_resp.get('access_token', None)
                self._refresh_token = json_resp.get('refresh_token', None)
                self._session_token_timeout = datetime.now() + timedelta(seconds=json_resp.get("expires_in", 0.0))
            except JSONDecodeError:
                self.log(f"Failed to get access token. Received JSON Decode Error when requesting information "
                         f"from {oauth_token_path}")
                self._session_token = None
                self._refresh_token = None
                self._session_token_timeout = -1.0
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
                        elif "password" in line:
                            self._apiPassword = line.split(":")[1].strip()
                            self.log(f"Retrieved api password from {file_path}")
                        else:
                            self.log(f"Retrieving token from {file_path}")
                            self._session_token = line
                            self._session_token_timeout = -1.0
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
        else:
            # assuming the string sent in is the hard coded token
            self.log(f"Setting token provided in login request as access token")
            self._session_token = token_provided
            self._session_token_timeout = -1.0
            self._refresh_token = None

    def revoke_token(self) -> None:
        # does not currently work
        oauth_token_path = "https://customerapiauth.fortinet.com/api/v1/oauth/revoke_token/"
        if self._session_token is not None:
            body = dict()
            body["client_id"] = "FortiSASE"
            body["token"] = self._session_token
            self.log(f"Making revocation attempt to revoke current token")
            resp = requests.post(oauth_token_path, data=body)
            if resp.status_code == 200:
                self.log(f"Revoked token successfully")
            else:
                self.log(f"Revocation of current token was unsuccessful. This is not an error message, possibly the "
                         f"token was already timed out or not valid")
        self._refresh_token = None
        self._session_token = None
        self._session_token_timeout = -1.0

    def login(self) -> None:
        if self._session_token is None:
            self.get_token(self._login_token)

    def logout(self) -> None:
        self.revoke_token()

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()

    # def get(self, url, *args, **kwargs):
    #     return self._post_request("get", self.common_datagram_params("get", url, *args, **kwargs))
    #
    # def post(self, url, *args, **kwargs):
    #     return self._post_request("add", self.common_datagram_params("add", url, *args, **kwargs))
    #
    # def delete(self, url, *args, **kwargs):
    #     return self._post_request("update", self.common_datagram_params("update", url, *args, **kwargs))
    #
    # def put(self, url, *args, **kwargs):
    #     return self._post_request("set", self.common_datagram_params("set", url, *args, **kwargs))
