import telebot
import socket
import requests
import ssl
import whois
import urllib3
from bs4 import BeautifulSoup
from datetime import datetime
import re
import concurrent.futures
import nmap
import dns.resolver
import ipaddress
import subprocess
import json

# توكن البوت - استبدله بتوكنك
BOT_TOKEN = '7842557859:AAFJmg7hwHTHFjAdF8EKlCq08v7qsUa3Iu8'

# إنشاء البوت
bot = telebot.TeleBot(BOT_TOKEN)

def extract_domain(url):
    """استخراج اسم النطاق من الرابط"""
    try:
        # إزالة البروتوكولات
        url = url.replace('https://', '').replace('http://', '').replace('www.', '')
        # أخذ الجزء الأول قبل أي مسارات
        domain = url.split('/')[0]
        return domain
    except Exception as e:
        return None

def get_ip_from_domain(domain):
    """استخراج IP من اسم النطاق"""
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        return None

def advanced_port_scan(ip):
    """فحص متقدم للمنافذ باستخدام nmap"""
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-sV -sC -p-')
        
        detailed_ports = []
        for proto in nm[ip].all_protocols():
            ports = nm[ip][proto].keys()
            for port in ports:
                service = nm[ip][proto][port]
                
                port_details = {
                    'port': port,
                    'state': service['state'],
                    'service': service['name'],
                    'product': service.get('product', 'غير معروف'),
                    'version': service.get('version', 'غير معروف'),
                    'extra_info': service.get('extrainfo', '')
                }
                
                # تقييم المخاطر
                risk_level = assess_port_risk(port, port_details)
                
                detailed_ports.append(f"""
🔹 المنفذ {port}/{proto}:
   - الحالة: {port_details['state']}
   - الخدمة: {port_details['service']} ({port_details['product']})
   - الإصدار: {port_details['version']}
   - المخاطر: {risk_level}
   - معلومات إضافية: {port_details['extra_info']}
""")
        
        return detailed_ports
    except Exception as e:
        return [f"❌ خطأ في فحص المنافذ: {str(e)}"]

def assess_port_risk(port, port_details):
    """تقييم مخاطر المنفذ بشكل متقدم"""
    risks = {
        22: {
            'description': 'SSH - قد يسمح بتسلل المهاجم عبر كلمات مرور ضعيفة أو ثغرات في الإصدار',
            'severity': '🔴 خطورة عالية جداً'
        },
        21: {
            'description': 'FTP - يسمح بنقل الملفات دون تشفير، مما يعرض البيانات للاختراق',
            'severity': '🔴 خطورة عالية'
        },
        23: {
            'description': 'Telnet - نقل البيانات بدون تشفير، سهل الاختراق',
            'severity': '🔴 خطورة عالية'
        },
        3389: {
            'description': 'RDP - قد يكون عرضة لهجمات الاختراق عن بُعد والتسلل',
            'severity': '🔴 خطورة عالية'
        },
        80: {
            'description': 'HTTP - غير آمن ويمكن التنصت على البيانات المنقولة',
            'severity': '🟠 خطورة متوسطة'
        },
        443: {
            'description': 'HTTPS - يحتاج لفحص شهادة SSL بعناية',
            'severity': '🟡 خطورة محتملة'
        }
    }
    
    if port in risks:
        return f"{risks[port]['severity']}: {risks[port]['description']}"
    
    # منافذ عامة أخرى
    if 1024 < port < 49151:
        return "🟠 منفذ مخصص - يحتاج للتدقيق"
    
    return "🟢 مخاطر منخفضة"

def check_subdomain_takeover(domain):
    """فحص إمكانية استيلاء المهاجم على النطاق الفرعي"""
    subdomains = [
        f'test.{domain}', 
        f'dev.{domain}', 
        f'staging.{domain}'
    ]
    takeover_risks = []
    
    for sub in subdomains:
        try:
            dns_records = dns.resolver.resolve(sub, 'CNAME')
            for rdata in dns_records:
                cname = rdata.target.to_text()
                # فحص الخدمات الشائعة
                services = ['herokuapp.com', 'azure.com', 's3.amazonaws.com']
                for service in services:
                    if service in cname:
                        takeover_risks.append(f"""
⚠️ احتمال استيلاء على النطاق الفرعي:
   - النطاق: {sub}
   - CNAME: {cname}
   - الخطر: يمكن للمهاجم السيطرة على هذا النطاق الفرعي!
""")
        except Exception:
            pass
    
    return takeover_risks

def check_ssl_vulnerabilities(domain):
    """فحص ثغرات SSL بشكل متقدم"""
    try:
        # إجراء فحص SSL متقدم
        output = subprocess.check_output(['testssl.sh', domain], universal_newlines=True)
        
        # البحث عن الثغرات الرئيسية
        critical_issues = []
        if 'VULNERABLE' in output:
            critical_issues = re.findall(r'VULNERABLE.*', output)
        
        return critical_issues if critical_issues else ["🟢 لا توجد ثغرات SSL واضحة"]
    
    except Exception as e:
        return [f"❌ تعذر فحص SSL: {str(e)}"]

def check_headers_security(domain):
    """فحص أمان الرؤوس HTTP"""
    try:
        response = requests.get(f'https://{domain}', timeout=5)
        headers = response.headers
        
        security_headers = {
            'Strict-Transport-Security': '🟢 HSTS موجود',
            'X-Frame-Options': '🟢 حماية من هجمات التزوير',
            'X-XSS-Protection': '🟢 حماية من هجمات XSS',
            'Content-Security-Policy': '🟢 سياسة أمان المحتوى'
        }
        
        missing_headers = []
        for header, message in security_headers.items():
            if header not in headers:
                missing_headers.append(f"⚠️ مفقود: {header} - {message}")
        
        return missing_headers if missing_headers else ["🟢 جميع الرؤوس الأساسية موجودة"]
    
    except Exception as e:
        return [f"❌ تعذر فحص الرؤوس: {str(e)}"]

@bot.message_handler(func=lambda message: True)
def comprehensive_website_scan(message):
    """تحليل شامل للموقع"""
    url = message.text.strip()
    
    try:
        # استخراج النطاق
        domain = extract_domain(url)
        if not domain:
            bot.reply_to(message, "❌ رابط غير صالح")
            return
        
        # استخراج IP
        ip = get_ip_from_domain(domain)
        if not ip:
            bot.reply_to(message, "❌ تعذر استخراج عنوان IP")
            return
        
        # جمع المعلومات
        response = f"🌐 التقرير الأمني الشامل للموقع:\n\n"
        response += f"• النطاق: {domain}\n"
        response += f"• IP: {ip}\n\n"
        
        # فحص المنافذ
        ports = advanced_port_scan(ip)
        response += "🔓 فحص المنافذ:\n"
        response += "\n".join(ports) + "\n\n"
        
        # فحص SSL
        ssl_vulns = check_ssl_vulnerabilities(domain)
        response += "🛡️ ثغرات SSL:\n"
        response += "\n".join(ssl_vulns) + "\n\n"
        
        # فحص استيلاء النطاق الفرعي
        subdomain_risks = check_subdomain_takeover(domain)
        if subdomain_risks:
            response += "🚨 مخاطر النطاقات الفرعية:\n"
            response += "\n".join(subdomain_risks) + "\n\n"
        
        # فحص رؤوس الأمان
        header_issues = check_headers_security(domain)
        response += "🔒 الرؤوس الأمنية:\n"
        response += "\n".join(header_issues) + "\n"
        
        bot.reply_to(message, response)
    
    except Exception as e:
        bot.reply_to(message, f"❌ خطأ في التحليل: {str(e)}")

# تشغيل البوت
print('جار تشغيل البوت...')
bot.polling(none_stop=True)
