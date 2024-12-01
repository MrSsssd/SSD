
import telebot
import socket
import requests
import ssl
import concurrent.futures
from urllib.parse import urlparse
import nmap  # تأكد من تثبيته

# توكن البوت - استبدله بتوكنك
BOT_TOKEN = '8166843437:AAEZ-BJyWtzA2nKdKGhCLavP7iwg7hk5tsE'

# إنشاء البوت
bot = telebot.TeleBot(BOT_TOKEN)

class ComprehensiveNetworkScanner:
    def __init__(self, target):
        self.target = target
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

    def extract_domain(self):
        """استخراج اسم النطاق بشكل دقيق"""
        try:
            parsed_url = urlparse(self.target)
            domain = parsed_url.netloc or parsed_url.path
            domain = domain.replace('www.', '').split(':')[0]
            return domain.strip()
        except Exception as e:
            print(f"خطأ في استخراج النطاق: {e}")
            return None

    def resolve_ip(self, domain):
        """استخراج IP من اسم النطاق"""
        try:
            return socket.gethostbyname(domain)
        except Exception as e:
            print(f"خطأ في استخراج IP: {e}")
            return None

    def advanced_port_scan(self, ip):
        """فحص المنافذ المتقدم باستخدام nmap"""
        try:
            nm = nmap.PortScanner()
            nm.scan(ip, arguments='-sV -sT -p-')  # مسح جميع المنافذ مع كشف الإصدارات
            
            open_ports = []
            for proto in nm[ip].all_protocols():
                ports = nm[ip][proto].keys()
                for port in ports:
                    port_state = nm[ip][proto][port]
                    if port_state['state'] == 'open':
                        open_ports.append({
                            'port': port,
                            'state': 'Open',
                            'service': port_state.get('name', 'Unknown'),
                            'version': port_state.get('version', 'Unknown')
                        })
            
            return open_ports
        except Exception as e:
            print(f"خطأ في المسح: {e}")
            return []

    def advanced_ssl_check(self, domain):
        """فحص SSL المتقدم"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                    cert = secure_sock.getpeercert()
                    
                    return {
                        'ssl_status': 'متصل',
                        'issuer': dict(cert.get('issuer', {})).get('commonName', 'غير معروف'),
                        'expiration': cert.get('notAfter', 'غير محدد'),
                        'subject': dict(cert.get('subject', {})).get('commonName', 'غير معروف')
                    }
        except Exception as e:
            return {
                'ssl_status': 'فشل الاتصال',
                'error': str(e)
            }

    def security_headers_check(self, domain):
        """فحص رؤوس الأمان"""
        try:
            response = requests.get(f'https://{domain}', 
                                    headers=self.headers, 
                                    timeout=5)
            
            security_headers = {
                'Strict-Transport-Security': response.headers.get('Strict-Transport-Security', 'غير موجود'),
                'X-Frame-Options': response.headers.get('X-Frame-Options', 'غير موجود'),
                'X-XSS-Protection': response.headers.get('X-XSS-Protection', 'غير موجود'),
                'Content-Security-Policy': response.headers.get('Content-Security-Policy', 'غير موجود')
            }
            
            return security_headers
        except Exception as e:
            return {'error': str(e)}

    def vulnerability_analysis(self, open_ports):
        """تحليل الثغرات المحتملة"""
        vulnerabilities = []
        
        vuln_database = {
            22: {
                'name': 'SSH',
                'risks': [
                    'احتمال هجمات القوة الغاشمة',
                    'مخاطر المصادقة',
                    'إمكانية الوصول غير المصرح به'
                ]
            },
            21: {
                'name': 'FTP',
                'risks': [
                    'اتصالات غير مشفرة', 
                    'إمكانية التنصت', 
                    'مخاطر الرفع والتنزيل'
                ]
            },
            80: {
                'name': 'HTTP',
                'risks': [
                    'هجمات XSS',
                    'تسريب معلومات', 
                    'عدم وجود HTTPS'
                ]
            },
            443: {
                'name': 'HTTPS',
                'risks': [
                    'تكوين SSL ضعيف', 
                    'شهادات منتهية',
                    'بروتوكولات قديمة'
                ]
            }
        }
        
        for port_info in open_ports:
            port = port_info['port']
            if port in vuln_database:
                vulnerabilities.append({
                    'port': port,
                    'service': vuln_database[port]['name'],
                    'risks': vuln_database[port]['risks']
                })
        
        return vulnerabilities

    def generate_comprehensive_report(self):
        """توليد تقرير شامل"""
        try:
            # استخراج النطاق
            domain = self.extract_domain()
            if not domain:
                return ["❌ رابط غير صالح"]
            
            # استخراج IP
            ip = self.resolve_ip(domain)
            if not ip:
                return ["❌ تعذر استخراج عنوان IP"]
            
            # فحص المنافذ
            open_ports = self.advanced_port_scan(ip)
            
            # فحص SSL
            ssl_details = self.advanced_ssl_check(domain)
            
            # فحص رؤوس الأمان
            security_headers = self.security_headers_check(domain)
            
            # تحليل الثغرات
            vulnerabilities = self.vulnerability_analysis(open_ports)
            
            # بناء التقرير
            report_sections = []
            
            # معلومات أساسية
            report_sections.append(
                f"🔍 تقرير الفحص الأمني الشامل\n" + 
                f"النطاق: {domain}\n" + 
                f"IP: {ip}\n\n"
            )
            
            # المنافذ المفتوحة
            ports_section = "🔓 المنافذ المفتوحة:\n" + \
                            "\n".join([
                                f"• المنفذ {port['port']}: {port['service']} (الحالة: {port['state']}) " + 
                                f"(الإصدار: {port.get('version', 'غير معروف')})"
                                for port in open_ports
                            ]) + "\n\n"
            report_sections.append(ports_section)
            
            # معلومات SSL
            ssl_section = "🔒 معلومات SSL:\n" + \
                          f"الحالة: {ssl_details.get('ssl_status', 'غير معروف')}\n" + \
                          f"الجهة المصدرة: {ssl_details.get('issuer', 'غير معروف')}\n" + \
                          f"تاريخ الانتهاء: {ssl_details.get('expiration', 'غير معروف')}\n\n"
            report_sections.append(ssl_section)
            
            # رؤوس الأمان
            headers_section = "🛡️ رؤوس الأمان:\n" + \
                              "\n".join([
                                  f"• {key}: {value}"
                                  for key, value in security_headers.items()
                              ]) + "\n\n"
            report_sections.append(headers_section)
            
            # الثغرات المحتملة
            vulnerabilities_section = "⚠️ المخاطر المحتملة:\n" + \
                                      "\n".join([
                                          f"🚨 الخدمة: {vuln['service']} (المنفذ {vuln['port']})\n" + 
                                          "المخاطر:\n" + 
                                          "\n".join(f"• {risk}" for risk in vuln['risks'])
                                          for vuln in vulnerabilities
                                      ]) + "\n"
            report_sections.append(vulnerabilities_section)
            
            return report_sections
        
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
