from xml.etree import ElementTree
import xlwt
import os
import re
import glob

xmls = glob.glob('*.xml')

for xml in xmls:
    path = os.path.abspath(xml)
    text=open(path,encoding="utf-8").read()
    text=re.sub(u"[\x00-\x08\x0b-\x0c\x0e-\x1f]+",u"",text)
    root=ElementTree.fromstring(text)
    title = [
        "业务系统",
        "WEB站点URL",
        "WEB端口",	
        "IP地址",	
        "WEB漏洞编号",	
        "WEB漏洞名称",
        "WEB漏洞等级",	
        "影响平台",	
        "CVE",
        "漏洞描述",	
        "整改建议",	
        "存在漏洞的链接URL编号",	
        "存在漏洞的链接URL",
        "请求头",	
        "响应头",
        ]
    holes = []
    holes_rank_info = []
    text_info = []
    sove_info = []
    vuln_url_info = []
    exchange = []
    value_rank = []
    key_rank = []
    value_text = []
    key_text = []
    value_sove = []
    key_sove = []
    dict_rank = {}
    dict_text = {}
    dict_sove = {}
    print("读取:",xml)
    for ele in root.iter(tag="info"):
        holes.append(ele.attrib['vtitle'])

    for text in root.iter(tag="vdescstr"):        
        text = str(text.text)
        text = text.replace(' ','')
        value_text.append(text)

    for sove in root.iter(tag="vresolvestr"):
        sove = str(sove.text)
        sove = sove.replace(' ','')
        value_sove.append(sove)

    for rank in root.iter(tag="vuln_resove_info"):
        value_rank.append(rank.attrib['type'])
        key_rank.append(rank.attrib['vtitle'])

    for each in range(len(value_rank)):
        string = str(value_rank[each])
        string = string.replace('危','')
        value_rank[each] = string

    for k in range(len(key_rank)):
        dict_rank[key_rank[k]] = value_rank[k]
        dict_text[key_rank[k]] = value_text[k]
        dict_sove[key_rank[k]] = value_sove[k]

    for name in root.iter(tag="taskname"):
        name = name.text + ".xls"

    for ip in root.iter(tag="url_ip"):
        ip = ip.text

    for url in root.iter(tag="url"):
        url = url.text

    for vuln_url in root.iter(tag="vuln_url"):
        vuln_url = str(vuln_url.text)
        vuln_url = vuln_url.replace(' ','')
        vuln_url_info.append(vuln_url)

    for x in range(len(holes)-1):
        workbook = xlwt.Workbook(encoding="utf-8")
        worksheet = workbook.add_sheet('sheet1')

    if (len(holes) == 1):
        workbook = xlwt.Workbook(encoding="utf-8")
        worksheet = workbook.add_sheet('sheet1')

    for j in range(len(title)):
        worksheet.write(0,j,title[j])

    for i in range(len(holes)):
        l = i + 1
        worksheet.write(l,5,holes[i])
        for j in dict_rank.keys():
            if j == holes[i]:
                worksheet.write(l,6,dict_rank.get(j))
        worksheet.write(l,3,ip)
        worksheet.write(l,1,url)
        for j in dict_text.keys():
            if j == holes[i]:
                worksheet.write(l,9,dict_text.get(j)) 
        for j in dict_sove.keys():
            if j == holes[i]:
                worksheet.write(l,10,dict_sove.get(j))
        worksheet.write(l,12,vuln_url_info[i])
        name = name.replace('https://','')
        name = name.replace('http://','')
        name = name.replace('/','-')
        workbook.save(name)
    print("生成报告:",name)
