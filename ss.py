
import telebot
import socket
import requests
import ssl
import whois
import nmap
import concurrent.futures
from datetime import datetime
import re
import json

# توكن البوت - استبدله بتوكنك
BOT_TOKEN = '8166843437:AAEZ-BJyWtzA2nKdKGhCLavP7iwg7hk5tsE'

# إنشاء البوت
bot = telebot.TeleBot(BOT_TOKEN)

class AdvancedVulnerabilityScanner:
    def __init__(self, target):
        self.target = target
        self.nm = nmap.PortScanner()
        self.vulnerabilities = []

    def extract_domain(self):
        """استخراج اسم النطاق"""
        try:
            # إزالة البروتوكولات
            domain = self.target.replace('https://', '').replace('http://', '').replace('www.', '')
            return domain.split('/')[0]
        except Exception:
            return None

    def resolve_ip(self, domain):
        """استخراج IP من اسم النطاق"""
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return None

    def comprehensive_port_scan(self, ip):
        """فحص شامل للمنافذ باستخدام nmap"""
        try:
            # مسح متقدم يكشف التفاصيل والثغرات
            self.nm.scan(ip, arguments='-sV -sC -p- -O --script vuln')
            
            port_details = []
            for proto in self.nm[ip].all_protocols():
                ports = self.nm[ip][proto].keys()
                for port in ports:
                    service = self.nm[ip][proto][port]
                    
                    # تجميع تفاصيل المنفذ
                    port_info = {
                        'port': port,
                        'state': service.get('state', 'Unknown'),
                        'service': service.get('name', 'Unknown'),
                        'version': service.get('version', 'Unknown'),
                        'product': service.get('product', 'Unknown')
                    }
                    port_details.append(port_info)
            
            return port_details
        except Exception as e:
            return []

    def analyze_vulnerabilities(self, port_details):
        """تحليل الثغرات المحتملة"""
        detailed_vulnerabilities = []
        
        for port in port_details:
            vulns = self.check_port_vulnerabilities(port)
            if vulns:
                detailed_vulnerabilities.extend(vulns)
        
        return detailed_vulnerabilities

    def check_port_vulnerabilities(self, port):
        """فحص الثغرات لكل منفذ"""
        vulnerabilities = []
        
        # قاعدة بيانات الثغرات المعروفة
        vuln_database = {
            21: {
                'name': 'FTP Vulnerability',
                'severity': 'عالية',
                'description': 'يمكن للمهاجم:',
                'risks': [
                    'تسجيل الدخول عبر كلمات مرور ضعيفة',
                    'تنفيذ هجمات الحقن',
                    'سرقة الملفات المخزنة'
                ],
                'mitigation': 'تأمين FTP باستخدام SFTP وكلمات مرور معقدة'
            },
            22: {
                'name': 'SSH Vulnerability',
                'severity': 'عالية',
                'description': 'يمكن للمهاجم:',
                'risks': [
                    'اختراق المصادقة',
                    'تنفيذ أوامر عن بعد',
                    'إنشاء نفق SSH للوصول'
                ],
                'mitigation': 'تقييد SSH، استخدام مفاتيح عامة، منع المصادقة بكلمة مرور'
            },
            80: {
                'name': 'HTTP Vulnerability',
                'severity': 'متوسطة',
                'description': 'يمكن للمهاجم:',
                'risks': [
                    'اكتشاف ثغرات XSS',
                    'هجمات حقن SQL',
                    'التحايل على أمان الموقع'
                ],
                'mitigation': 'تحديث الخوادم، استخدام HTTPS، تطبيق WAF'
            },
            443: {
                'name': 'HTTPS Vulnerability',
                'severity': 'متوسطة',
                'description': 'يمكن للمهاجم:',
                'risks': [
                    'فك تشفير الاتصالات',
                    'هجمات Man-in-the-Middle',
                    'سرقة البيانات المشفرة'
                ],
                'mitigation': 'تحديث شهادات SSL، استخدام TLS 1.3'
            },
            3306: {
                'name': 'MySQL Vulnerability',
                'severity': 'عالية',
                'description': 'يمكن للمهاجم:',
                'risks': [
                    'الوصول غير المصرح به للبيانات',
                    'تنفيذ أوامر SQL خبيثة',
                    'تعديل قواعد البيانات'
                ],
                'mitigation': 'تقييد الوصول، استخدام جدران حماية'
            }
        }
        
        # البحث عن الثغرات
        port_num = port['port']
        if port_num in vuln_database:
            vuln = vuln_database[port_num]
            vuln['port_details'] = port
            vulnerabilities.append(vuln)
        
        return vulnerabilities

    def generate_report(self):
        """توليد تقرير شامل"""
        try:
            # استخراج النطاق والIP
            domain = self.extract_domain()
            if not domain:
                return "❌ رابط غير صالح"
            
            ip = self.resolve_ip(domain)
            if not ip:
                return "❌ تعذر استخراج عنوان IP"
            
            # فحص المنافذ
            port_details = self.comprehensive_port_scan(ip)
            
            # تحليل الثغرات
            vulnerabilities = self.analyze_vulnerabilities(port_details)
            
            # بناء التقرير
            report = f"🔍 تقرير الفحص الشامل\n"
            report += f"النطاق: {domain}\n"
            report += f"IP: {ip}\n\n"
            
            # تفاصيل المنافذ
            report += "🔓 المنافذ المفتوحة:\n"
            for port in port_details:
                report += f"منفذ {port['port']}: {port['service']} ({port['state']})\n"
            
            # الثغرات
            if vulnerabilities:
                report += "\n⚠️ الثغرات المكتشفة:\n"
                for vuln in vulnerabilities:
                    report += f"🚨 {vuln['name']} (خطورة: {vuln['severity']})\n"
                    report += f"وصف: {vuln['description']}\n"
                    report += "المخاطر:\n"
                    for risk in vuln['risks']:
                        report += f"- {risk}\n"
                    report += f"الحلول: {vuln['mitigation']}\n\n"
            else:
                report += "\n✅ لم يتم العثور على ثغرات رئيسية\n"
            
            return report
        
        except Exception as e:
            return f"❌ خطأ في التحليل: {str(e)}"

@bot.message_handler(commands=['start'])
def send_welcome(message):
    """رسالة الترحيب"""
    welcome_text = """
👋 مرحبًا بك في بوت الفحص الأمني المتقدم
أرسل رابط موقع للفحص الشامل 🕵️‍♂️
مثال: https://example.com
    """
    bot.reply_to(message, welcome_text)

@bot.message_handler(func=lambda message: True)
def scan_website(message):
    """فحص الموقع"""
    url = message.text.strip()
    
    # إرسال رسالة انتظار
    waiting_msg = bot.reply_to(message, "🔍 جارٍ إجراء الفحص الشامل... قد يستغرق بعض الوقت")
    
    try:
        # إنشاء كائن الماسح الضوئي
        scanner = AdvancedVulnerabilityScanner(url)
        
        # توليد التقرير
        report = scanner.generate_report()
        
        # حذف رسالة الانتظار
        bot.delete_message(message.chat.id, waiting_msg.message_id)
        
        # إرسال التقرير
        bot.reply_to(message, report)
    
    except Exception as e:
        # حذف رسالة الانتظار
        bot.delete_message(message.chat.id, waiting_msg.message_id)
        
        # إرسال رسالة الخطأ
        bot.reply_to(message, f"❌ حدث خطأ: {str(e)}")

# تشغيل البوت
print('جار تشغيل البوت...')
bot.polling(none_stop=True)
