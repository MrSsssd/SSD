import telebot
import socket
import requests
import ssl
import concurrent.futures
import subprocess
import re
import json
import os
import nmap  # إضافة مكتبة nmap للفحص المتقدم

# توكن البوت - استبدله بتوكنك
BOT_TOKEN='8166843437:AAEZ-BJyWtzA2nKdKGhCLavP7iwg7hk5tsE'

# إنشاء البوت
bot = telebot.TeleBot(BOT_TOKEN)

class AdvancedNetworkScanner:
    def __init__(self, target):
        self.target = target
        self.nm = nmap.PortScanner()  # إنشاء كائن nmap

    def extract_domain(self):
        """استخراج اسم النطاق"""
        try:
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

    def advanced_port_scan(self, ip):
        """فحص متقدم للمنافذ باستخدام nmap"""
        try:
            # مسح جميع المنافذ مع اكتشاف الخدمات والإصدارات
            self.nm.scan(ip, arguments='-p- -sV -sC -O')
            
            open_ports = []
            for proto in self.nm[ip].all_protocols():
                ports = self.nm[ip][proto].keys()
                for port in ports:
                    service = self.nm[ip][proto][port]
                    open_ports.append({
                        'port': port,
                        'state': service['state'],
                        'service': service.get('name', 'Unknown'),
                        'version': service.get('product', '') + ' ' + service.get('version', ''),
                        'additional_info': service.get('script', {})
                    })
            
            return open_ports
        except Exception as e:
            print(f"خطأ في مسح المنافذ: {e}")
            return []

    def advanced_ssl_check(self, domain):
        """فحص SSL المتقدم"""
        try:
            # استخدام openssl للحصول على معلومات SSL التفصيلية
            cmd = f"openssl s_client -connect {domain}:443 -brief"
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
            
            # فحص صلاحية الشهادة
            verify_cmd = f"openssl s_client -connect {domain}:443 -verify 5"
            verify_result = subprocess.check_output(verify_cmd, shell=True, stderr=subprocess.STDOUT, text=True)
            
            return {
                'ssl_details': result,
                'verification': verify_result
            }
        except Exception as e:
            return {'error': str(e)}

    def vulnerability_analysis(self, open_ports):
        """تحليل الثغرات المتقدم"""
        vulnerabilities = []
        
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service']
            version = port_info['version']
            
            # قاعدة بيانات الثغرات المتقدمة
            vuln_db = {
                'ssh': {
                    'high_risk_versions': ['OpenSSH < 7.4'],
                    'description': 'احتمال وجود ثغرات في إصدارات قديمة من SSH',
                    'mitigation': ['تحديث الخدمة', 'تقييد الوصول']
                },
                'http': {
                    'high_risk_versions': ['Apache < 2.4.41', 'Nginx < 1.16.1'],
                    'description': 'احتمال وجود ثغرات XSS وRCE',
                    'mitigation': ['تحديث الخادم', 'تطبيق جدار حماية']
                }
            }
            
            # البحث عن الثغرات
            for service_type, details in vuln_db.items():
                if service_type in service.lower():
                    for risky_version in details['high_risk_versions']:
                        if risky_version.split()[-1] in version:
                            vulnerabilities.append({
                                'port': port,
                                'service': service,
                                'version': version,
                                'risk_level': 'عالية',
                                'description': details['description'],
                                'mitigation': details['mitigation']
                            })
        
        return vulnerabilities

    def generate_comprehensive_report(self):
        """توليد تقرير شامل"""
        try:
            # استخراج النطاق والIP
            domain = self.extract_domain()
            if not domain:
                return "❌ رابط غير صالح"
            
            ip = self.resolve_ip(domain)
            if not ip:
                return "❌ تعذر استخراج عنوان IP"
            
            # فحص المنافذ المفتوحة
            open_ports = self.advanced_port_scan(ip)
            
            # فحص SSL
            ssl_details = self.advanced_ssl_check(domain)
            
            # تحليل الثغرات
            vulnerabilities = self.vulnerability_analysis(open_ports)
            
            # بناء التقرير المفصل
            report_sections = [
                f"🔍 تقرير الفحص الأمني المتقدم\n",
                f"النطاق: {domain}\n",
                f"IP: {ip}\n\n",
                
                "🔓 المنافذ والخدمات:\n" + 
                "\n".join([
                    f"• المنفذ {port['port']} ({port['service']}):\n"
                    f"  الحالة: {port['state']}\n"
                    f"  الإصدار: {port['version']}\n"
                    for port in open_ports
                ]) + "\n",
                
                "🔒 فحص SSL:\n" + 
                str(ssl_details) + "\n\n",
                
                "⚠️ الثغرات المحتملة:\n" + 
                "\n".join([
                    f"🚨 خدمة: {vuln['service']} (المنفذ {vuln['port']})\n"
                    f"مستوى الخطورة: {vuln['risk_level']}\n"
                    f"الوصف: {vuln['description']}\n"
                    "طرق التخفيف:\n" + 
                    "\n".join(f"• {mitigation}" for mitigation in vuln['mitigation']) + "\n"
                    for vuln in vulnerabilities
                ])
            ]
            
            return report_sections
        
        except Exception as e:
            return [f"❌ خطأ في التحليل: {str(e)}"]

def split_long_message(message_parts, max_length=4096):
    """تقسيم الرسائل الطويلة"""
    messages = []
    current_message = ""
    
    for section in message_parts:
        if len(current_message) + len(section) > max_length:
            messages.append(current_message)
            current_message = section
        else:
            current_message += section
    
    if current_message:
        messages.append(current_message)
    
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
    
    # إرسال رسالة انتظار
    waiting_msg = bot.reply_to(message, "🔍 جارٍ إجراء الفحص الشامل... قد يستغرق بعض الوقت")
    
    try:
        # إنشاء كائن الماسح الضوئي
        scanner = AdvancedNetworkScanner(url)
        
        # توليد التقرير
        report_sections = scanner.generate_comprehensive_report()
        
        # تقسيم الرسائل الطويلة
        messages = split_long_message(report_sections)
        
        # حذف رسالة الانتظار
        bot.delete_message(message.chat.id, waiting_msg.message_id)
        
        # إرسال التقرير بشكل متقطع
        for msg in messages:
            bot.reply_to(message, msg)
    
    except Exception as e:
        # حذف رسالة الانتظار
        bot.delete_message(message.chat.id, waiting_msg.message_id)
        
        # إرسال رسالة الخطأ
        bot.reply_to(message, f"❌ حدث خطأ: {str(e)}")

# تشغيل البوت
print('جار تشغيل البوت...')
bot.polling(none_stop=True)
