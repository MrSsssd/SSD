import telebot
import socket
import requests
import whois
import nmap
import dns.resolver
import ipaddress
import concurrent.futures
import json
import re
import os
from datetime import datetime
from bs4 import BeautifulSoup
import shodan
import ssl
import urllib3
import cryptography
from urllib.parse import urlparse

# توكن البوت
BOT_TOKEN = '8166843437:AAEZ-BJyWtzA2nKdKGhCLavP7iwg7hk5tsE'

# مفتاح Shodan للبحث عن الثغرات
SHODAN_API_KEY = 'wmzOdzuFAUTCpTJ0nKxxQU6h57NC8F34'

# إنشاء البوت
bot = telebot.TeleBot(BOT_TOKEN)
shodan_api = shodan.Shodan(SHODAN_API_KEY)

class AdvancedSecurityScanner:
    def __init__(self, target):
        self.target = target.replace('https://', '').replace('http://', '').replace('www.', '')
        self.ip = self.resolve_ip()
    
    def resolve_ip(self):
        """استخراج عنوان IP"""
        try:
            return socket.gethostbyname(self.target)
        except Exception as e:
            return None

    def advanced_port_scan(self):
        """فحص شامل للمنافذ مع تفاصيل الثغرات"""
        try:
            nm = nmap.PortScanner()
            # فحص شامل مع تفاصيل الثغرات
            nm.scan(self.ip, arguments='-sV -sC -p- -A -O --script vuln,exploit')
            
            detailed_vulnerabilities = []
            
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    
                    for port in ports:
                        service = nm[host][proto][port]
                        
                        # استخراج الثغرات التفصيلية
                        if 'script' in service:
                            for script_name, script_output in service['script'].items():
                                if 'vuln' in script_name.lower() or 'exploit' in script_name.lower():
                                    vulnerability = self.analyze_vulnerability(
                                        port=port, 
                                        service=service.get('name', 'Unknown'),
                                        script_name=script_name,
                                        script_output=script_output
                                    )
                                    detailed_vulnerabilities.append(vulnerability)
            
            return detailed_vulnerabilities
        
        except Exception as e:
            return [self.create_vulnerability_report(
                type='فشل المسح',
                name='خطأ في فحص المنافذ',
                description=str(e),
                severity='حرج',
                potential_impact='تعطيل الفحص الأمني',
                exploit_method='غير متاح'
            )]

    def analyze_vulnerability(self, port, service, script_name, script_output):
        """تحليل الثغرات بالتفصيل"""
        severity = self.determine_severity(script_name, script_output)
        
        return self.create_vulnerability_report(
            type='ثغرة منفذ',
            name=script_name,
            description=script_output,
            port=port,
            service=service,
            severity=severity,
            potential_impact=self.assess_potential_impact(severity),
            exploit_method=self.suggest_exploit_method(script_name)
        )

    def determine_severity(self, script_name, script_output):
        """تحديد درجة خطورة الثغرة"""
        severity_keywords = {
            'حرج': ['critical', 'remote code', 'rce', 'root', 'admin', 'system'],
            'عالي': ['high', 'exploit', 'vulnerability', 'remote', 'dangerous'],
            'متوسط': ['medium', 'potential', 'possible', 'moderate'],
            'منخفض': ['low', 'information', 'minor']
        }
        
        script_lower = script_name.lower() + ' ' + str(script_output).lower()
        
        for severity, keywords in severity_keywords.items():
            if any(keyword in script_lower for keyword in keywords):
                return severity
        
        return 'منخفض'

    def assess_potential_impact(self, severity):
        """تقييم التأثير المحتمل للثغرة"""
        impact_map = {
            'حرج': 'إمكانية التحكم الكامل في النظام، سرقة البيانات، تعطيل الخدمات',
            'عالي': 'اختراق جزئي، سرقة بيانات محدودة، تعديل إعدادات النظام',
            'متوسط': 'الوصول المحدود، تسريب معلومات غير حساسة',
            'منخفض': 'تأثير محدود، معلومات غير هامة'
        }
        return impact_map.get(severity, 'غير معروف')

    def suggest_exploit_method(self, script_name):
        """اقتراح طرق الاستغلال المحتملة"""
        exploit_methods = {
            'rce': 'إرسال أوامر تنفيذ عن بعد، حقن كود ضار',
            'injection': 'إدخال أوامر خبيثة في المدخلات',
            'remote': 'استغلال اتصال عن بعد دون مصادقة',
            'traversal': 'الوصول للملفات خارج المجلد المسموح',
            'xss': 'حقن برمجيات خبيثة في صفحات الويب',
            'default': 'استغلال ضعف في التكوين أو الإعدادات'
        }
        
        for key, method in exploit_methods.items():
            if key in script_name.lower():
                return method
        
        return 'استغلال عام للثغرة'

    def create_vulnerability_report(self, **kwargs):
        """إنشاء تقرير مفصل عن الثغرة"""
        return {
            'النوع': kwargs.get('type', 'غير محدد'),
            'الاسم': kwargs.get('name', 'ثغرة مجهولة'),
            'الوصف': kwargs.get('description', 'لا توجد تفاصيل'),
            'المنفذ': kwargs.get('port', 'غير محدد'),
            'الخدمة': kwargs.get('service', 'غير محددة'),
            'درجة الخطورة': kwargs.get('severity', 'منخفض'),
            'التأثير المحتمل': kwargs.get('potential_impact', 'لا يوجد'),
            'طريقة الاستغلال': kwargs.get('exploit_method', 'غير معروفة')
        }

    def web_vulnerability_scan(self):
        """فحص شامل لثغرات الويب"""
        vulnerabilities = []
        try:
            url = f'https://{self.target}'
            response = requests.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # فحص رؤوس الأمان
            security_headers_check = self.check_security_headers(response.headers)
            vulnerabilities.extend(security_headers_check)
            
            # فحص تسريب المعلومات
            info_leakage = self.detect_information_leakage(response.text, soup)
            vulnerabilities.extend(info_leakage)
            
            # فحص ضعف XSS
            xss_vulnerabilities = self.check_xss_vulnerabilities(soup)
            vulnerabilities.extend(xss_vulnerabilities)
            
            return vulnerabilities
        
        except Exception as e:
            return [self.create_vulnerability_report(
                type='فحص الويب',
                name='فشل فحص الموقع',
                description=str(e),
                severity='عالي',
                potential_impact='عدم القدرة على فحص الموقع',
                exploit_method='غير متاح'
            )]

    def check_security_headers(self, headers):
        """فحص رؤوس الأمان"""
        vulnerabilities = []
        critical_headers = {
            'Strict-Transport-Security': 'HSTS مفقود',
            'X-Frame-Options': 'حماية من clickjacking مفقودة',
            'X-XSS-Protection': 'حماية XSS مفقودة',
            'Content-Security-Policy': 'سياسة أمان المحتوى مفقودة',
            'X-Content-Type-Options': 'حماية من MIME type sniffing مفقودة'
        }
        
        for header, description in critical_headers.items():
            if header not in headers:
                vulnerabilities.append(self.create_vulnerability_report(
                    type='رأس أمان مفقود',
                    name=header,
                    description=description,
                    severity='متوسط',
                    potential_impact='إمكانية تنفيذ هجمات XSS وClickjacking',
                    exploit_method='حقن برمجيات خبيثة'
                ))
        
        return vulnerabilities

    def detect_information_leakage(self, text, soup):
        """كشف تسريب المعلومات"""
        vulnerabilities = []
        sensitive_patterns = [
            r'password',
            r'secret',
            r'key',
            r'token',
            r'credentials',
            r'admin',
            r'config'
        ]
        
        for pattern in sensitive_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                vulnerabilities.append(self.create_vulnerability_report(
                    type='تسريب معلومات',
                    name=f'نمط حساس: {pattern}',
                    description=f'تم العثور على {len(matches)} من أنماط: {pattern}',
                    severity='عالي',
                    potential_impact='سرقة معلومات حساسة',
                    exploit_method='استخراج المعلومات المسربة'
                ))
        
        return vulnerabilities

    def check_xss_vulnerabilities(self, soup):
        """فحص ضعف XSS"""
        vulnerabilities = []
        # فحص الإدخالات المحتملة
        inputs = soup.find_all(['input', 'textarea'])
        
        for input_tag in inputs:
            if not input_tag.get('type') or input_tag.get('type').lower() in ['text', 'search']:
                vulnerabilities.append(self.create_vulnerability_report(
                    type='ضعف XSS',
                    name='إدخال غير محمي',
                    description=f'إدخال محتمل للهجوم: {input_tag}',
                    severity='متوسط',
                    potential_impact='تنفيذ هجمات حقن برمجي',
                    exploit_method='حقن كود JavaScript خبيث'
                ))
        
        return vulnerabilities

    def comprehensive_report(self):
        """توليد تقرير شامل"""
        # جمع نتائج الفحوصات
        port_vulns = self.advanced_port_scan()
        web_vulns = self.web_vulnerability_scan()
        
        # دمج النتائج
        all_vulnerabilities = port_vulns + web_vulns
        
        # تصنيف الثغرات حسب الخطورة
        sorted_vulns = sorted(
            all_vulnerabilities, 
            key=lambda x: ['حرج', 'عالي', 'متوسط', 'منخفض'].index(x.get('درجة الخطورة', 'منخفض'))
        )
        
        # بناء التقرير
        report = f"""🔍 التقرير الأمني المتقدم للموقع: {self.target}

📍 معلومات أساسية:
- عنوان IP: {self.ip}

🚨 الثغرات المكتشفة:
"""
        
        if not sorted_vulns:
            report += "لم يتم العثور على ثغرات 🎉"
        else:
            for vuln in sorted_vulns:
                report += f"""
▶️ {vuln['النوع']}
   - الاسم: {vuln['الاسم']}
   - الوصف: {vuln['الوصف']}
   - درجة الخطورة: {vuln['درجة الخطورة']} 🔴
   - التأثير المحتمل: {vuln['التأثير المحتمل']}
   - طريقة الاستغلال: {vuln['طريقة الاستغلال']}
"""
        
        return report

@bot.message_handler(commands=['start'])
def send_welcome(message):
    """رسالة الترحيب"""
    bot.reply_to(message, "مرحباً! أرسل رابط الموقع للفحص الأمني المتقدم 🕵️‍♂️")

@bot.message_handler(func=lambda message: True)
def scan_website(message):
    """معالجة رسائل المسح"""
    target = message.text.strip().replace('https://', '').replace('http://', '').replace('www.', '')
    
    try:
        # إنشاء كائن فحص متقدم
        security_scanner = AdvancedSecurityScanner(target)
        
        # إرسال رسالة انتظار
        wait_message = bot.reply_to(message, "🔍 جارٍ إجراء الفحص الأمني المتقدم...")
        
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
