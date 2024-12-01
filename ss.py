import telebot
import socket
import requests
import ssl
import concurrent.futures
import subprocess
import re
import json
import os

# توكن البوت - استبدله بتوكنك
BOT_TOKEN = '8166843437:AAEZ-BJyWtzA2nKdKGhCLavP7iwg7hk5tsE'

# إنشاء البوت
bot = telebot.TeleBot(BOT_TOKEN)

class UltimateVulnerabilityScanner:
    def __init__(self, target):
        self.target = target
        self.vulnerabilities = []

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
        """فحص متقدم للمنافذ باستخدام أدوات متعددة"""
        open_ports = []
        all_ports = list(range(1, 65536))  # مسح جميع المنافذ

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    service = self.identify_service(port)
                    return {
                        'port': port,
                        'service': service,
                        'details': self.get_port_details(ip, port)
                    }
                sock.close()
            except Exception:
                pass
            return None

        # مسح المنافذ بالتزامن
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            results = list(executor.map(scan_port, all_ports))
        
        # تصفية النتائج
        open_ports = [port for port in results if port is not None]
        return open_ports

    def identify_service(self, port):
        """تحديد الخدمة للمنفذ"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 
            443: 'HTTPS', 3306: 'MySQL', 3389: 'RDP', 
            5900: 'VNC', 8080: 'HTTP Proxy'
        }
        return services.get(port, 'Unknown Service')

    def get_port_details(self, ip, port):
        """استخراج تفاصيل المنفذ"""
        try:
            # استخدام nmap للحصول على معلومات تفصيلية
            cmd = f"nmap -sV -p {port} {ip}"
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
            return result
        except Exception:
            return "تعذر جمع التفاصيل"

    def check_vulnerabilities(self, open_ports):
        """فحص الثغرات المحتملة"""
        vulnerabilities = []
        
        # قاعدة بيانات الثغرات المتقدمة
        vuln_database = {
            22: {
                'name': 'SSH Vulnerability',
                'severity': 'حرجة',
                'cve': 'CVE-2018-15473',
                'description': 'ثغرة في خدمة SSH تسمح باستخراج أسماء المستخدمين',
                'exploit': 'يمكن للمهاجم استخراج قائمة المستخدمين الصالحة',
                'mitigation': [
                    'تحديث OpenSSH',
                    'تقييد المصادقة',
                    'استخدام مفاتيح SSH بدلاً من كلمات المرور'
                ]
            },
            21: {
                'name': 'FTP Vulnerability',
                'severity': 'عالية',
                'cve': 'CVE-2017-7546',
                'description': 'ثغرات في خدمات FTP تسمح بالدخول غير المصرح به',
                'exploit': 'يمكن للمهاجم تسجيل الدخول باستخدام كلمات مرور ضعيفة',
                'mitigation': [
                    'استخدام SFTP بدلاً من FTP',
                    'تطبيق كلمات مرور معقدة',
                    'تقييد الوصول IP'
                ]
            },
            80: {
                'name': 'HTTP Vulnerability',
                'severity': 'متوسطة',
                'cve': 'CVE-2020-15910',
                'description': 'ثغرات في خوادم HTTP تسمح بهجمات XSS',
                'exploit': 'يمكن حقن أكواد خبيثة في موقع الويب',
                'mitigation': [
                    'تطبيق WAF',
                    'تحديث الخادم',
                    'التحقق من صحة المدخلات'
                ]
            }
        }

        for port_info in open_ports:
            port = port_info['port']
            if port in vuln_database:
                vuln = vuln_database[port]
                vuln['port_details'] = port_info
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def run_advanced_scans(self, ip):
        """إجراء فحوصات متقدمة"""
        scans = []
        
        # فحص SSL
        try:
            ssl_check = self.check_ssl(ip)
            scans.append(ssl_check)
        except Exception:
            pass
        
        # فحص الاتصال بالخوادم
        try:
            network_check = self.check_network_security(ip)
            scans.append(network_check)
        except Exception:
            pass
        
        return scans

    def check_ssl(self, ip):
        """فحص SSL وتفاصيل الشهادة"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ip, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as secure_sock:
                    cert = secure_sock.getpeercert()
                    
                    return {
                        'type': 'SSL Check',
                        'details': f"Issuer: {cert.get('issuer', 'Unknown')}\n" +
                                   f"Expiration: {cert.get('notAfter', 'Unknown')}"
                    }
        except Exception:
            return {
                'type': 'SSL Check',
                'details': 'فحص SSL غير ممكن أو غير مكتمل'
            }

    def check_network_security(self, ip):
        """فحص أمان الشبكة"""
        try:
            # استخدام traceroute للتحليل
            cmd = f"traceroute {ip}"
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
            
            return {
                'type': 'Network Security',
                'details': result
            }
        except Exception:
            return {
                'type': 'Network Security',
                'details': 'تعذر إجراء فحص الشبكة'
            }

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
            
            # تحليل الثغرات
            vulnerabilities = self.check_vulnerabilities(open_ports)
            
            # فحوصات متقدمة
            advanced_scans = self.run_advanced_scans(ip)
            
            # بناء التقرير
            report = f"🔍 تقرير الفحص الأمني المتقدم\n"
            report += f"النطاق: {domain}\n"
            report += f"IP: {ip}\n\n"
            
            # المنافذ المفتوحة
            report += "🔓 المنافذ المفتوحة:\n"
            if open_ports:
                for port_info in open_ports:
                    report += f"• منفذ {port_info['port']}: {port_info['service']}\n"
            else:
                report += "لا توجد منافذ مفتوحة\n"
            
            # الثغرات
            report += "\n⚠️ الثغرات والمخاطر:\n"
            if vulnerabilities:
                for vuln in vulnerabilities:
                    report += f"🚨 {vuln['name']}\n"
                    report += f"CVE: {vuln.get('cve', 'غير محدد')}\n"
                    report += f"الخطورة: {vuln['severity']}\n"
                    report += f"الوصف: {vuln['description']}\n"
                    report += "كيفية الاستغلال:\n"
                    report += f"• {vuln['exploit']}\n"
                    report += "طرق التخفيف:\n"
                    for mitigation in vuln['mitigation']:
                        report += f"• {mitigation}\n\n"
            else:
                report += "لم يتم العثور على ثغرات معروفة\n"
            
            # الفحوصات المتقدمة
            report += "\n🌐 الفحوصات الإضافية:\n"
            for scan in advanced_scans:
                report += f"• {scan['type']}:\n{scan['details']}\n"
            
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
        scanner = UltimateVulnerabilityScanner(url)
        
        # توليد التقرير
        report = scanner.generate_comprehensive_report()
        
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
