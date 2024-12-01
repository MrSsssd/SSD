
import telebot
import socket
import requests
import ssl
import subprocess
import re
import json
import os
import concurrent.futures
import nmap  # إضافة مسح نmap المتقدم
import shodan  # للبحث عن المعلومات الخارجية
import whois   # للحصول على معلومات التسجيل
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta

BOT_TOKEN = '7883917822:AAE_l6SIdBgzHuEbJ8eIVxfN9mDg_RnzPx4'

# إنشاء البوت
bot = telebot.TeleBot(BOT_TOKEN)

class AdvancedNetworkSecurityScanner:
    def __init__(self, target):
        self.target = target
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        # إضافة مفاتيح API للخدمات الخارجية
        self.shodan_api_key = 'wmzOdzuFAUTCpTJ0nKxxQU6h57NC8F34'
        
    def extended_dns_enumeration(self, domain):
        """فحص DNS المتقدم"""
        dns_records = {}
        try:
            import dns.resolver
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_records[record_type] = [str(rdata) for rdata in answers]
                except Exception as e:
                    dns_records[record_type] = f"فشل في استرداد: {str(e)}"
            
            return dns_records
        except ImportError:
            return {"error": "يرجى تثبيت مكتبة dnspython"}

    def advanced_whois_lookup(self, domain):
        """معلومات التسجيل المتقدمة"""
        try:
            w = whois.whois(domain)
            return {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers
            }
        except Exception as e:
            return {"error": f"فشل في البحث: {str(e)}"}

    def advanced_nmap_scan(self, ip):
        """مسح المنافذ والخدمات باستخدام nmap"""
        try:
            nm = nmap.PortScanner()
            nm.scan(ip, arguments='-sV -sC -O')  # مسح متقدم مع كشف الإصدارات والنظام
            
            scan_results = []
            for proto in nm[ip].all_protocols():
                ports = nm[ip][proto].keys()
                for port in ports:
                    service_info = nm[ip][proto][port]
                    scan_results.append({
                        'port': port,
                        'state': service_info['state'],
                        'service': service_info['name'],
                        'version': service_info.get('version', 'غير معروف'),
                        'product': service_info.get('product', 'غير معروف')
                    })
            
            return scan_results
        except Exception as e:
            return [{"error": f"فشل في مسح nmap: {str(e)}"}]

    def comprehensive_ssl_analysis(self, domain):
        """تحليل SSL المتكامل"""
        try:
            # استخراج الشهادة مباشرة
            cert = ssl.get_server_certificate((domain, 443))
            x509_cert = x509.load_pem_x509_certificate(cert.encode('ascii'), default_backend())
            
            # تحليل متقدم للشهادة
            return {
                'subject': x509_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
                'issuer': x509_cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
                'version': x509_cert.version.name,
                'serial_number': x509_cert.serial_number,
                'not_valid_before': x509_cert.not_valid_before,
                'not_valid_after': x509_cert.not_valid_after,
                'days_to_expiry': (x509_cert.not_valid_after - datetime.now()).days,
                'is_expired': datetime.now() > x509_cert.not_valid_after,
                'signature_algorithm': x509_cert.signature_algorithm_oid._name
            }
        except Exception as e:
            return {"error": f"فشل التحليل: {str(e)}"}

    def advanced_vulnerability_check(self, services):
        """فحص الثغرات المتقدم"""
        vulnerabilities = []
        vuln_db = {
            'ssh': {
                'risks': [
                    'إمكانية هجمات القوة الغاشمة',
                    'مخاطر المصادقة الضعيفة',
                    'احتمال استغلال نقاط الضعف في البروتوكول'
                ],
                'recommendations': [
                    'استخدام مفاتيح SSH بدلاً من كلمات المرور',
                    'تقييد الوصول من IP محددة',
                    'تحديث OpenSSH لأحدث إصدار'
                ]
            },
            'http': {
                'risks': [
                    'احتمال هجمات XSS',
                    'تسريب معلومات حساسة',
                    'مخاطر الحقن'
                ],
                'recommendations': [
                    'تطبيق CSP headers',
                    'استخدام HTTPS بشكل حصري',
                    'التحقق من المدخلات'
                ]
            }
        }
        
        for service in services:
            service_name = service.get('service', '').lower()
            if service_name in vuln_db:
                vulnerabilities.append({
                    'service': service_name,
                    'port': service.get('port', 'غير محدد'),
                    'risks': vuln_db[service_name]['risks'],
                    'recommendations': vuln_db[service_name]['recommendations']
                })
        
        return vulnerabilities

    def generate_comprehensive_report(self):
        """توليد التقرير الشامل"""
        try:
            domain = urlparse(self.target).netloc or urlparse(self.target).path
            domain = domain.replace('www.', '').split(':')[0]
            ip = socket.gethostbyname(domain)
            
            # جمع المعلومات
            dns_info = self.extended_dns_enumeration(domain)
            whois_info = self.advanced_whois_lookup(domain)
            nmap_results = self.advanced_nmap_scan(ip)
            ssl_details = self.comprehensive_ssl_analysis(domain)
            vulnerabilities = self.advanced_vulnerability_check(nmap_results)
            
            # بناء التقرير التفصيلي
            report = [
                f"🔍 تقرير الفحص الأمني المتكامل\n" +
                f"النطاق: {domain}\n" +
                f"IP: {ip}\n\n"
            ]
            
            # معلومات DNS
            report.append("🌐 معلومات DNS:\n" + 
                          "\n".join([f"• {key}: {value}" for key, value in dns_info.items()]) + "\n\n")
            
            # معلومات التسجيل
            report.append("📋 معلومات التسجيل:\n" +
                          "\n".join([f"• {key}: {value}" for key, value in whois_info.items()]) + "\n\n")
            
            # نتائج nmap
            report.append("🔓 المنافذ والخدمات:\n" +
                          "\n".join([
                              f"• المنفذ {service.get('port', 'غير معروف')}: " +
                              f"{service.get('service', 'غير معروف')} " +
                              f"(الحالة: {service.get('state', 'غير معروف')})"
                              for service in nmap_results
                          ]) + "\n\n")
            
            # تفاصيل SSL
            report.append("🔒 تحليل SSL:\n" +
                          "\n".join([f"• {key}: {value}" for key, value in ssl_details.items()]) + "\n\n")
            
            # الثغرات والتوصيات
            report.append("⚠️ المخاطر والتوصيات:\n" +
                          "\n".join([
                              f"🚨 الخدمة: {vuln['service']} (المنفذ {vuln['port']})\n" +
                              "المخاطر:\n" + 
                              "\n".join(f"• {risk}" for risk in vuln['risks']) + "\n" +
                              "التوصيات:\n" +
                              "\n".join(f"• {rec}" for rec in vuln['recommendations'])
                              for vuln in vulnerabilities
                          ]) + "\n"
            )
            
            return report
        
        except Exception as e:
            return [f"❌ خطأ في التحليل: {str(e)}"]

def split_messages(report_sections, max_length=4000):
    """تقسيم الرسائل بشكل آمن"""
    messages = []
    current_message = ""
    
    for section in report_sections:
        if len(current_message) + len(section) > max_length:
            messages.append(current_message.strip())
            current_message = section
        else:
            current_message += section
    
    if current_message:
        messages.append(current_message.strip())
    
    return messages

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
    
    try:
        # إنشاء كائن الماسح الضوئي
        scanner = ComprehensiveNetworkScanner(url)
        
        # توليد التقرير
        report_sections = scanner.generate_comprehensive_report()
        
        # تقسيم الرسائل
        messages = split_messages(report_sections)
        
        # إرسال التقرير بشكل متقطع
        for msg in messages:
            bot.reply_to(message, msg)
    
    except Exception as e:
        # إرسال رسالة الخطأ
        bot.reply_to(message, f"❌ حدث خطأ: {str(e)}")

# تشغيل البوت
print('جار تشغيل البوت...')
bot.polling(none_stop=True)
