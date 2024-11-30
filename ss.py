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
import os
import shodan
import sslyze
from sslyze import ServerConnector
from sslyze.plugins import HttpHeaderScannerPlugin
from sslyze.server_connectivity_tester import ServerConnectivityTester

# توكن البوت
BOT_TOKEN = '7842557859:AAFJmg7hwHTHFjAdF8EKlCq08v7qsUa3Iu8'

# مفتاح Shodan للبحث عن الثغرات
SHODAN_API_KEY = 'wmzOdzuFAUTCpTJ0nKxxQU6h57NC8F34'

# إنشاء البوت
bot = telebot.TeleBot(BOT_TOKEN)
shodan_api = shodan.Shodan(SHODAN_API_KEY)

class ComprehensiveSecurity:
    def __init__(self, domain):
        self.domain = domain
        self.ip = self.get_ip()
    
    def get_ip(self):
        """استخراج عنوان IP"""
        try:
            return socket.gethostbyname(self.domain)
        except Exception as e:
            return None
    
    def advanced_port_scan(self):
        """فحص شامل للمنافذ"""
        try:
            nm = nmap.PortScanner()
            # فحص شامل مع استكشاف الثغرات
            nm.scan(self.ip, arguments='-sV -sC -p- -A -O --script vuln')
            
            detailed_ports = []
            vulnerabilities = []
            
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    
                    for port in ports:
                        service = nm[host][proto][port]
                        
                        # تفاصيل المنفذ
                        port_info = {
                            'port': port,
                            'state': service['state'],
                            'service': service.get('name', 'Unknown'),
                            'product': service.get('product', 'Unknown'),
                            'version': service.get('version', 'Unknown'),
                            'extra_info': service.get('extrainfo', '')
                        }
                        
                        # استخراج الثغرات المحتملة
                        if 'script' in service:
                            for script_name, script_output in service['script'].items():
                                if 'vuln' in script_name.lower():
                                    vulnerabilities.append({
                                        'port': port,
                                        'service': port_info['service'],
                                        'vulnerability': script_name,
                                        'details': script_output
                                    })
                        
                        detailed_ports.append(port_info)
            
            return detailed_ports, vulnerabilities
        
        except Exception as e:
            return [], [f"خطأ في فحص المنافذ: {str(e)}"]
    
    def shodan_vulnerability_check(self):
        """فحص الثغرات باستخدام Shodan"""
        try:
            host = shodan_api.host(self.ip)
            vulnerabilities = []
            
            # استخراج الثغرات المعروفة
            if 'vulns' in host:
                for cve, details in host['vulns'].items():
                    vulnerabilities.append({
                        'cve': cve,
                        'severity': details.get('severity', 'غير محدد'),
                        'description': details.get('description', 'لا توجد تفاصيل')
                    })
            
            return vulnerabilities
        
        except Exception as e:
            return [f"خطأ في فحص Shodan: {str(e)}"]
    
    def ssl_deep_scan(self):
        """فحص متعمق لبروتوكول SSL"""
        try:
            # اختبار الاتصال
            server_test = ServerConnectivityTester().perform(
                hostname=self.domain, 
                port=443
            )
            
            # فحص شامل للشهادة
            ssl_scanner = ServerConnector.connect(server_test)
            
            # التحقق من الثغرات
            vulnerabilities = []
            
            # فحص إصدارات بروتوكول TLS
            if ssl_scanner.tls_version_used < TlsVersionEnum.TLS_1_2:
                vulnerabilities.append({
                    'type': 'بروتوكول TLS قديم',
                    'risk': 'عالي',
                    'description': 'يستخدم إصدار TLS قديم وغير آمن'
                })
            
            # فحص الشهادة
            cert = ssl_scanner.get_cert()
            if cert.not_valid_after < datetime.now():
                vulnerabilities.append({
                    'type': 'شهادة SSL منتهية',
                    'risk': 'عالي',
                    'description': 'شهادة SSL منتهية الصلاحية'
                })
            
            return vulnerabilities
        
        except Exception as e:
            return [f"خطأ في فحص SSL: {str(e)}"]
    
    def web_vulnerability_scan(self):
        """فحص الثغرات الويب"""
        try:
            # إعداد طلب HTTPS
            url = f'https://{self.domain}'
            response = requests.get(url, timeout=10)
            
            # تحليل HTML للبحث عن ثغرات محتملة
            soup = BeautifulSoup(response.text, 'html.parser')
            
            vulnerabilities = []
            
            # التحقق من رؤوس الأمان
            headers = response.headers
            security_headers = [
                'Strict-Transport-Security',
                'X-Frame-Options',
                'X-XSS-Protection',
                'Content-Security-Policy'
            ]
            
            for header in security_headers:
                if header not in headers:
                    vulnerabilities.append({
                        'type': 'رأس أمان مفقود',
                        'header': header,
                        'risk': 'متوسط',
                        'description': 'مفقود رأس أمان مهم'
                    })
            
            # البحث عن معلومات حساسة في HTML
            sensitive_patterns = [
                r'password',
                r'secret',
                r'key',
                r'token'
            ]
            
            for pattern in sensitive_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': 'تسريب محتمل للمعلومات',
                        'pattern': pattern,
                        'risk': 'عالي',
                        'description': 'اكتشاف كلمات دالة على تسريب معلومات'
                    })
            
            return vulnerabilities
        
        except Exception as e:
            return [f"خطأ في فحص الويب: {str(e)}"]
    
    def comprehensive_report(self):
        """إنشاء تقرير شامل"""
        # جمع نتائج الفحوصات
        ports, port_vulns = self.advanced_port_scan()
        shodan_vulns = self.shodan_vulnerability_check()
        ssl_vulns = self.ssl_deep_scan()
        web_vulns = self.web_vulnerability_scan()
        
        # تجميع التقرير
        report = f"""🔍 التقرير الأمني الشامل للموقع: {self.domain}
        
📍 معلومات أساسية:
- عنوان IP: {self.ip}

🔓 المنافذ المفتوحة:
{self.format_ports(ports)}

🚨 الثغرات المكتشفة:
{self.format_vulnerabilities(port_vulns + shodan_vulns + ssl_vulns + web_vulns)}
"""
        return report
    
    def format_ports(self, ports):
        """تنسيق قائمة المنافذ"""
        if not ports:
            return "لا توجد منافذ مفتوحة"
        
        return "\n".join([
            f"- المنفذ {p['port']}: {p['service']} ({p['product']} {p['version']})"
            for p in ports
        ])
    
    def format_vulnerabilities(self, vulns):
        """تنسيق قائمة الثغرات"""
        if not vulns:
            return "لم يتم العثور على ثغرات"
        
        return "\n".join([
            f"🔴 {v.get('type', 'ثغرة غير محددة')}: {v.get('description', 'لا توجد تفاصيل')}"
            for v in vulns
        ])

@bot.message_handler(commands=['start'])
def send_welcome(message):
    """رسالة الترحيب"""
    bot.reply_to(message, "مرحباً! أرسل رابط الموقع للفحص الأمني الشامل 🕵️‍♂️")

@bot.message_handler(func=lambda message: True)
def scan_website(message):
    """معالجة رسائل المسح"""
    url = message.text.strip().replace('https://', '').replace('http://', '').replace('www.', '')
    
    try:
        # إنشاء كائن فحص شامل
        security_scanner = ComprehensiveSecurity(url)
        
        # إرسال رسالة انتظار
        wait_message = bot.reply_to(message, "🔍 جارٍ إجراء الفحص الأمني الشامل...")
        
        # توليد التقرير
        report = security_scanner.comprehensive_report()
        
        # حذف رسالة الانتظار وإرسال التقرير
        bot.delete_message(wait_message.chat.id, wait_message.message_id)
        bot.reply_to(message, report)
    
    except Exception as e:
        bot.reply_to(message, f"❌ خطأ في المسح: {str(e)}")

# تشغيل البوت
print('البوت جاهز للعمل...')
bot.polling(none_stop=True)
