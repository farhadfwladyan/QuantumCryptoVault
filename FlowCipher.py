import sys
import os
import shutil
import json
import base64
import hashlib
import secrets
import string
from datetime import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac
from cryptography.fernet import Fernet

from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *


class StyleManager:
    DARK_STYLE = """
    QMainWindow {
        background-color: #1a1a2e;
    }
    QTabWidget::pane {
        background-color: #16213e;
        border: 2px solid #0f3460;
        border-radius: 10px;
    }
    QTabBar::tab {
        background-color: #0f3460;
        color: white;
        padding: 10px 20px;
        margin: 2px;
        border-radius: 5px;
        font-family: 'Vazir';
        font-size: 12px;
    }
    QTabBar::tab:selected {
        background-color: #e94560;
    }
    QTextEdit, QLineEdit, QPlainTextEdit {
        background-color: #0f3460;
        color: white;
        border: 2px solid #e94560;
        border-radius: 8px;
        padding: 8px;
        font-family: 'Vazir';
        font-size: 12px;
    }
    QPushButton {
        background-color: #e94560;
        color: white;
        border: none;
        border-radius: 8px;
        padding: 10px 20px;
        font-family: 'Vazir';
        font-size: 12px;
        font-weight: bold;
    }
    QPushButton:hover {
        background-color: #ff6b6b;
    }
    QPushButton:pressed {
        background-color: #c92a3a;
    }
    QComboBox {
        background-color: #0f3460;
        color: white;
        border: 2px solid #e94560;
        border-radius: 5px;
        padding: 5px;
        font-family: 'Vazir';
        font-size: 12px;
    }
    QLabel {
        color: white;
        font-family: 'Vazir';
        font-size: 12px;
    }
    QMenuBar {
        background-color: #16213e;
        color: white;
        font-family: 'Vazir';
        font-size: 12px;
    }
    QMenuBar::item:selected {
        background-color: #e94560;
    }
    QMenu {
        background-color: #16213e;
        color: white;
        font-family: 'Vazir';
        font-size: 12px;
    }
    QMenu::item:selected {
        background-color: #e94560;
    }
    QProgressBar {
        border: 2px solid #e94560;
        border-radius: 5px;
        text-align: center;
        color: white;
    }
    QProgressBar::chunk {
        background-color: #e94560;
        border-radius: 3px;
    }
    QListWidget {
        background-color: #0f3460;
        color: white;
        border: 2px solid #e94560;
        border-radius: 5px;
        font-family: 'Vazir';
        font-size: 12px;
    }
    QCheckBox {
        color: white;
        font-family: 'Vazir';
        font-size: 12px;
    }
    QRadioButton {
        color: white;
        font-family: 'Vazir';
        font-size: 12px;
    }
    """


APP_SECRET_KEY = Fernet.generate_key()
fernet = Fernet(APP_SECRET_KEY)


class MultiLayerCrypto:
    def __init__(self):
        self.encryption_methods = []
        self.keys = {}
        
    def add_encryption_layer(self, method, key=None):

        self.encryption_methods.append({
            'method': method,
            'key': key
        })
    
    def encrypt_multi_layer(self, data):
 
        encrypted = data
        for layer in self.encryption_methods:
            if layer['method'] == 'fernet':
                key = layer['key'] if layer['key'] else Fernet.generate_key()
                f = Fernet(key if isinstance(key, bytes) else key.encode())
                encrypted = f.encrypt(encrypted.encode()).decode()
            elif layer['method'] == 'base64':
                encrypted = base64.b64encode(encrypted.encode()).decode()
            elif layer['method'] == 'reverse':
                encrypted = encrypted[::-1]
            elif layer['method'] == 'rot13':
                encrypted = self.rot13(encrypted)
            elif layer['method'] == 'aes':
                encrypted = self.aes_encrypt(encrypted, layer['key'])
        return encrypted
    
    def decrypt_multi_layer(self, encrypted_data):

        decrypted = encrypted_data
        for layer in reversed(self.encryption_methods):
            if layer['method'] == 'fernet':
                key = layer['key'] if layer['key'] else Fernet.generate_key()
                f = Fernet(key if isinstance(key, bytes) else key.encode())
                decrypted = f.decrypt(decrypted.encode()).decode()
            elif layer['method'] == 'base64':
                decrypted = base64.b64decode(decrypted.encode()).decode()
            elif layer['method'] == 'reverse':
                decrypted = decrypted[::-1]
            elif layer['method'] == 'rot13':
                decrypted = self.rot13(decrypted)
            elif layer['method'] == 'aes':
                decrypted = self.aes_decrypt(decrypted, layer['key'])
        return decrypted
    
    def rot13(self, text):

        result = []
        for char in text:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)
    
    def aes_encrypt(self, data, key=None):
  
        if not key:
            key = secrets.token_bytes(32)
        elif isinstance(key, str):
            key = key.encode()[:32].ljust(32, b'\0')
            
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        

        data_bytes = data.encode()
        padded_data = data_bytes + b'\0' * (16 - len(data_bytes) % 16)
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        return base64.b64encode(iv + encrypted).decode()
    
    def aes_decrypt(self, encrypted_data, key=None):
   
        if not key:
            return encrypted_data
        elif isinstance(key, str):
            key = key.encode()[:32].ljust(32, b'\0')
            
        data = base64.b64decode(encrypted_data.encode())
        iv = data[:16]
        encrypted = data[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted) + decryptor.finalize()
        
        return decrypted.rstrip(b'\0').decode()


class QuantumCryptoVault(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 Quantum Crypto Vault - رمزنگاری پیشرفته چندلایه")
        self.setGeometry(100, 100, 1400, 800)
        
    
        try:
            self.setWindowIcon(QIcon("icon.png"))
        except:
            pass
        

        self.setStyleSheet(StyleManager.DARK_STYLE)
        
       
        self.current_file = None
        self.encryption_history = []
        self.multi_crypto = MultiLayerCrypto()
        self.rsa_keys = {}
        self.keys = {}  
        

        self.create_menu()
        
 
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.North)
        self.setCentralWidget(self.tabs)
        

        self.create_quick_encrypt_tab()
        self.create_rsa_tab()
        self.create_multi_layer_tab()
        self.create_file_encrypt_tab()
        self.create_key_manager_tab()
        self.create_digital_signature_tab()
        self.create_history_tab()
        self.create_settings_tab()
        

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("🚀 آماده به کار")
        

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_status)
        self.timer.start(1000)
        
    
        self.load_settings()
        
    def create_menu(self):
 
        menubar = self.menuBar()
        
    
        file_menu = menubar.addMenu("📁 فایل")
        
        new_action = QAction("📄 جدید", self)
        new_action.triggered.connect(self.new_file)
        file_menu.addAction(new_action)
        
        open_action = QAction("📂 باز کردن", self)
        open_action.triggered.connect(self.open_file)
        file_menu.addAction(open_action)
        
        save_action = QAction("💾 ذخیره", self)
        save_action.triggered.connect(self.save_file)
        file_menu.addAction(save_action)
        
        file_menu.addSeparator()
        
        export_action = QAction("📤 خروجی گرفتن", self)
        export_action.triggered.connect(self.export_data)
        file_menu.addAction(export_action)
        
        import_action = QAction("📥 ورودی گرفتن", self)
        import_action.triggered.connect(self.import_data)
        file_menu.addAction(import_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("🚪 خروج", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
 
        crypto_menu = menubar.addMenu("🔒 رمزنگاری")
        
        quick_action = QAction("⚡ رمزنگاری سریع", self)
        quick_action.triggered.connect(lambda: self.tabs.setCurrentIndex(0))
        crypto_menu.addAction(quick_action)
        
        rsa_action = QAction("🔑 RSA", self)
        rsa_action.triggered.connect(lambda: self.tabs.setCurrentIndex(1))
        crypto_menu.addAction(rsa_action)
        
        multi_action = QAction("🔄 چندلایه", self)
        multi_action.triggered.connect(lambda: self.tabs.setCurrentIndex(2))
        crypto_menu.addAction(multi_action)
        
        file_action = QAction("📁 رمزنگاری فایل", self)
        file_action.triggered.connect(lambda: self.tabs.setCurrentIndex(3))
        crypto_menu.addAction(file_action)
        

        tools_menu = menubar.addMenu("🛠️ ابزارها")
        
        hash_action = QAction("🔐 هش ساز", self)
        hash_action.triggered.connect(self.open_hash_tool)
        tools_menu.addAction(hash_action)
        
        password_action = QAction("🔑 رمز ساز", self)
        password_action.triggered.connect(self.open_password_generator)
        tools_menu.addAction(password_action)
        
  
        help_menu = menubar.addMenu("❓ راهنما")
        
        about_action = QAction("ℹ️ درباره", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        tutorial_action = QAction("📚 آموزش", self)
        tutorial_action.triggered.connect(self.show_tutorial)
        help_menu.addAction(tutorial_action)
        
    def create_quick_encrypt_tab(self):

        tab = QWidget()
        layout = QVBoxLayout()
        
 
        title = QLabel("⚡ رمزنگاری سریع با Fernet")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #e94560; padding: 10px;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        

        self.quick_progress = QProgressBar()
        self.quick_progress.setVisible(False)
        layout.addWidget(self.quick_progress)
        

        input_label = QLabel("📝 متن ورودی:")
        layout.addWidget(input_label)
        
        self.quick_input = QTextEdit()
        self.quick_input.setPlaceholderText("متن خود را وارد کنید...")
        layout.addWidget(self.quick_input)
        

        button_layout = QHBoxLayout()
        
        self.quick_encrypt_btn = QPushButton("🔒 رمزنگاری")
        self.quick_encrypt_btn.clicked.connect(self.quick_encrypt)
        button_layout.addWidget(self.quick_encrypt_btn)
        
        self.quick_decrypt_btn = QPushButton("🔓 رمزگشایی")
        self.quick_decrypt_btn.clicked.connect(self.quick_decrypt)
        button_layout.addWidget(self.quick_decrypt_btn)
        
        self.quick_copy_btn = QPushButton("📋 کپی")
        self.quick_copy_btn.clicked.connect(lambda: self.copy_to_clipboard(self.quick_output.toPlainText()))
        button_layout.addWidget(self.quick_copy_btn)
        
        self.quick_clear_btn = QPushButton("🧹 پاک کردن")
        self.quick_clear_btn.clicked.connect(lambda: self.quick_input.clear())
        button_layout.addWidget(self.quick_clear_btn)
        
        layout.addLayout(button_layout)
        

        output_label = QLabel("📄 نتیجه:")
        layout.addWidget(output_label)
        
        self.quick_output = QTextEdit()
        self.quick_output.setReadOnly(True)
        self.quick_output.setPlaceholderText("نتیجه در اینجا نمایش داده می‌شود...")
        layout.addWidget(self.quick_output)
        

        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("🔑 کلید فعلی:"))
        
        self.quick_key_display = QLineEdit()
        self.quick_key_display.setReadOnly(True)
        self.quick_key_display.setText(APP_SECRET_KEY.decode())
        key_layout.addWidget(self.quick_key_display)
        
        self.quick_new_key_btn = QPushButton("🔄 تولید کلید جدید")
        self.quick_new_key_btn.clicked.connect(self.generate_new_fernet_key)
        key_layout.addWidget(self.quick_new_key_btn)
        
        layout.addLayout(key_layout)
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "⚡ سریع")
        
    def create_rsa_tab(self):

        tab = QWidget()
        layout = QVBoxLayout()
        

        title = QLabel("🔑 رمزنگاری RSA نامتقارن")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #e94560; padding: 10px;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        

        rsa_toolbar = QHBoxLayout()
        
        self.generate_rsa_btn = QPushButton("🆕 تولید کلیدهای RSA")
        self.generate_rsa_btn.clicked.connect(self.generate_rsa_keys)
        rsa_toolbar.addWidget(self.generate_rsa_btn)
        
        self.load_public_btn = QPushButton("📂 بارگذاری کلید عمومی")
        self.load_public_btn.clicked.connect(self.load_public_key)
        rsa_toolbar.addWidget(self.load_public_btn)
        
        self.load_private_btn = QPushButton("📂 بارگذاری کلید خصوصی")
        self.load_private_btn.clicked.connect(self.load_private_key)
        rsa_toolbar.addWidget(self.load_private_btn)
        
        layout.addLayout(rsa_toolbar)
        

        keys_splitter = QSplitter(Qt.Horizontal)
        
  
        public_widget = QWidget()
        public_layout = QVBoxLayout()
        public_layout.addWidget(QLabel("🔓 کلید عمومی:"))
        
        self.public_key_display = QTextEdit()
        self.public_key_display.setReadOnly(True)
        self.public_key_display.setMaximumHeight(150)
        public_layout.addWidget(self.public_key_display)
        
        public_btn_layout = QHBoxLayout()
        copy_public_btn = QPushButton("📋 کپی")
        copy_public_btn.clicked.connect(lambda: self.copy_to_clipboard(self.public_key_display.toPlainText()))
        public_btn_layout.addWidget(copy_public_btn)
        
        save_public_btn = QPushButton("💾 ذخیره")
        save_public_btn.clicked.connect(lambda: self.save_key_to_file(self.public_key_display.toPlainText(), "public"))
        public_btn_layout.addWidget(save_public_btn)
        
        public_layout.addLayout(public_btn_layout)
        public_widget.setLayout(public_layout)
        

        private_widget = QWidget()
        private_layout = QVBoxLayout()
        private_layout.addWidget(QLabel("🔒 کلید خصوصی (محرمانه):"))
        
        self.private_key_display = QTextEdit()
        self.private_key_display.setReadOnly(True)
        self.private_key_display.setMaximumHeight(150)
        private_layout.addWidget(self.private_key_display)
        
        private_btn_layout = QHBoxLayout()
        copy_private_btn = QPushButton("📋 کپی")
        copy_private_btn.clicked.connect(lambda: self.copy_to_clipboard(self.private_key_display.toPlainText()))
        private_btn_layout.addWidget(copy_private_btn)
        
        save_private_btn = QPushButton("💾 ذخیره")
        save_private_btn.clicked.connect(lambda: self.save_key_to_file(self.private_key_display.toPlainText(), "private"))
        private_btn_layout.addWidget(save_private_btn)
        
        private_layout.addLayout(private_btn_layout)
        private_widget.setLayout(private_layout)
        
        keys_splitter.addWidget(public_widget)
        keys_splitter.addWidget(private_widget)
        keys_splitter.setSizes([400, 400])
        layout.addWidget(keys_splitter)
        

        layout.addWidget(QLabel("📝 متن:"))
        
        self.rsa_input = QTextEdit()
        self.rsa_input.setPlaceholderText("متن مورد نظر برای رمزنگاری...")
        self.rsa_input.setMaximumHeight(100)
        layout.addWidget(self.rsa_input)
        

        rsa_ops_layout = QHBoxLayout()
        
        self.rsa_encrypt_btn = QPushButton("🔒 رمزنگاری با کلید عمومی")
        self.rsa_encrypt_btn.clicked.connect(self.rsa_encrypt)
        rsa_ops_layout.addWidget(self.rsa_encrypt_btn)
        
        self.rsa_decrypt_btn = QPushButton("🔓 رمزگشایی با کلید خصوصی")
        self.rsa_decrypt_btn.clicked.connect(self.rsa_decrypt)
        rsa_ops_layout.addWidget(self.rsa_decrypt_btn)
        
        layout.addLayout(rsa_ops_layout)
        

        layout.addWidget(QLabel("📄 نتیجه:"))
        
        self.rsa_output = QTextEdit()
        self.rsa_output.setReadOnly(True)
        layout.addWidget(self.rsa_output)
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "🔑 RSA")
        
    def create_multi_layer_tab(self):

        tab = QWidget()
        layout = QVBoxLayout()
        
    
        title = QLabel("🔄 رمزنگاری چندلایه (ابدی)")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #e94560; padding: 10px;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        

        desc = QLabel("می‌توانید چندین لایه رمزنگاری را به ترتیب اعمال کنید")
        desc.setStyleSheet("color: #888; padding: 5px;")
        desc.setAlignment(Qt.AlignCenter)
        layout.addWidget(desc)
        

        layers_label = QLabel("📋 لایه‌های رمزنگاری:")
        layout.addWidget(layers_label)
        
        self.layers_list = QListWidget()
        self.layers_list.setMaximumHeight(150)
        layout.addWidget(self.layers_list)
        

        layers_control = QHBoxLayout()
        
        self.layer_method = QComboBox()
        self.layer_method.addItems(["fernet", "base64", "reverse", "rot13", "aes"])
        layers_control.addWidget(self.layer_method)
        
        self.add_layer_btn = QPushButton("➕ افزودن لایه")
        self.add_layer_btn.clicked.connect(self.add_encryption_layer)
        layers_control.addWidget(self.add_layer_btn)
        
        self.remove_layer_btn = QPushButton("➖ حذف لایه")
        self.remove_layer_btn.clicked.connect(self.remove_encryption_layer)
        layers_control.addWidget(self.remove_layer_btn)
        
        self.clear_layers_btn = QPushButton("🧹 پاک کردن همه")
        self.clear_layers_btn.clicked.connect(self.clear_layers)
        layers_control.addWidget(self.clear_layers_btn)
        
        layout.addLayout(layers_control)
        

        layout.addWidget(QLabel("📝 متن:"))
        
        self.multi_input = QTextEdit()
        self.multi_input.setPlaceholderText("متن مورد نظر...")
        layout.addWidget(self.multi_input)
        

        multi_ops = QHBoxLayout()
        
        self.multi_encrypt_btn = QPushButton("🔒 رمزنگاری چندلایه")
        self.multi_encrypt_btn.clicked.connect(self.multi_layer_encrypt)
        multi_ops.addWidget(self.multi_encrypt_btn)
        
        self.multi_decrypt_btn = QPushButton("🔓 رمزگشایی چندلایه")
        self.multi_decrypt_btn.clicked.connect(self.multi_layer_decrypt)
        multi_ops.addWidget(self.multi_decrypt_btn)
        
        layout.addLayout(multi_ops)
        

        layout.addWidget(QLabel("📄 نتیجه:"))
        
        self.multi_output = QTextEdit()
        self.multi_output.setReadOnly(True)
        layout.addWidget(self.multi_output)
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "🔄 چندلایه")
        
    def create_file_encrypt_tab(self):

        tab = QWidget()
        layout = QVBoxLayout()
        

        title = QLabel("📁 رمزنگاری فایل‌ها")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #e94560; padding: 10px;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
 
        file_select = QHBoxLayout()
        
        self.file_path = QLineEdit()
        self.file_path.setPlaceholderText("مسیر فایل را انتخاب کنید...")
        file_select.addWidget(self.file_path)
        
        self.browse_file_btn = QPushButton("📂 انتخاب فایل")
        self.browse_file_btn.clicked.connect(self.browse_file)
        file_select.addWidget(self.browse_file_btn)
        
        layout.addLayout(file_select)
        
 
        options_group = QGroupBox("تنظیمات رمزنگاری")
        options_layout = QVBoxLayout()
        

        method_layout = QHBoxLayout()
        method_layout.addWidget(QLabel("روش رمزنگاری:"))
        
        self.file_encrypt_method = QComboBox()
        self.file_encrypt_method.addItems(["AES-256", "Fernet", "RSA + AES", "چندلایه"])
        method_layout.addWidget(self.file_encrypt_method)
        
        options_layout.addLayout(method_layout)
        

        password_layout = QHBoxLayout()
        password_layout.addWidget(QLabel("رمز عبور:"))
        
        self.file_password = QLineEdit()
        self.file_password.setEchoMode(QLineEdit.Password)
        self.file_password.setPlaceholderText("اختیاری - در صورت نیاز")
        password_layout.addWidget(self.file_password)
        
        options_layout.addLayout(password_layout)
        

        self.delete_original = QCheckBox("حذف فایل اصلی پس از رمزنگاری")
        options_layout.addWidget(self.delete_original)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        

        file_ops = QHBoxLayout()
        
        self.encrypt_file_btn = QPushButton("🔒 رمزنگاری فایل")
        self.encrypt_file_btn.clicked.connect(self.encrypt_file)
        file_ops.addWidget(self.encrypt_file_btn)
        
        self.decrypt_file_btn = QPushButton("🔓 رمزگشایی فایل")
        self.decrypt_file_btn.clicked.connect(self.decrypt_file)
        file_ops.addWidget(self.decrypt_file_btn)
        
        layout.addLayout(file_ops)
        

        self.file_progress = QProgressBar()
        layout.addWidget(self.file_progress)
        

        recent_label = QLabel("📋 فایل‌های اخیر:")
        layout.addWidget(recent_label)
        
        self.recent_files = QListWidget()
        self.recent_files.setMaximumHeight(150)
        self.recent_files.itemDoubleClicked.connect(self.load_recent_file)
        layout.addWidget(self.recent_files)
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "📁 فایل")
        
    def create_key_manager_tab(self):

        tab = QWidget()
        layout = QVBoxLayout()
        

        title = QLabel("🔐 مدیریت کلیدها")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #e94560; padding: 10px;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        

        keys_label = QLabel("📋 کلیدهای ذخیره شده:")
        layout.addWidget(keys_label)
        
        self.keys_list = QListWidget()
        layout.addWidget(self.keys_list)
        

        keys_control = QHBoxLayout()
        
        self.add_key_btn = QPushButton("➕ افزودن کلید")
        self.add_key_btn.clicked.connect(self.add_key_dialog)
        keys_control.addWidget(self.add_key_btn)
        
        self.delete_key_btn = QPushButton("➖ حذف کلید")
        self.delete_key_btn.clicked.connect(self.delete_key)
        keys_control.addWidget(self.delete_key_btn)
        
        self.export_keys_btn = QPushButton("📤 خروجی کلیدها")
        self.export_keys_btn.clicked.connect(self.export_keys)
        keys_control.addWidget(self.export_keys_btn)
        
        self.import_keys_btn = QPushButton("📥 ورودی کلیدها")
        self.import_keys_btn.clicked.connect(self.import_keys)
        keys_control.addWidget(self.import_keys_btn)
        
        layout.addLayout(keys_control)
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "🔐 کلیدها")
        
    def create_digital_signature_tab(self):

        tab = QWidget()
        layout = QVBoxLayout()
        

        title = QLabel("📝 امضای دیجیتال")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #e94560; padding: 10px;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        

        layout.addWidget(QLabel("📝 متن:"))
        
        self.sign_input = QTextEdit()
        self.sign_input.setPlaceholderText("متن مورد نظر برای امضا...")
        layout.addWidget(self.sign_input)
        

        sign_ops = QHBoxLayout()
        
        self.create_signature_btn = QPushButton("✍️ ایجاد امضا")
        self.create_signature_btn.clicked.connect(self.create_signature)
        sign_ops.addWidget(self.create_signature_btn)
        
        self.verify_signature_btn = QPushButton("✅ بررسی امضا")
        self.verify_signature_btn.clicked.connect(self.verify_signature)
        sign_ops.addWidget(self.verify_signature_btn)
        
        layout.addLayout(sign_ops)
        

        layout.addWidget(QLabel("🔏 امضا:"))
        
        self.signature_display = QTextEdit()
        self.signature_display.setReadOnly(True)
        self.signature_display.setMaximumHeight(100)
        layout.addWidget(self.signature_display)
        
    
        layout.addWidget(QLabel("📊 نتیجه بررسی:"))
        
        self.verify_result = QLabel()
        self.verify_result.setStyleSheet("padding: 10px; border-radius: 5px;")
        self.verify_result.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.verify_result)
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "📝 امضا")
        
    def create_history_tab(self):
        """تب تاریخچه"""
        tab = QWidget()
        layout = QVBoxLayout()
        
 
        title = QLabel("📜 تاریخچه عملیات")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #e94560; padding: 10px;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        

        self.history_table = QTableWidget()
        self.history_table.setColumnCount(4)
        self.history_table.setHorizontalHeaderLabels(["زمان", "عملیات", "نتیجه", "وضعیت"])
        self.history_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.history_table)
        

        history_ops = QHBoxLayout()
        
        self.clear_history_btn = QPushButton("🧹 پاک کردن تاریخچه")
        self.clear_history_btn.clicked.connect(self.clear_history)
        history_ops.addWidget(self.clear_history_btn)
        
        self.export_history_btn = QPushButton("📤 خروجی تاریخچه")
        self.export_history_btn.clicked.connect(self.export_history)
        history_ops.addWidget(self.export_history_btn)
        
        layout.addLayout(history_ops)
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "📜 تاریخچه")
        
    def create_settings_tab(self):
        """تب تنظیمات"""
        tab = QWidget()
        layout = QVBoxLayout()
        

        title = QLabel("⚙️ تنظیمات")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #e94560; padding: 10px;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        

        appearance_group = QGroupBox("ظاهر")
        appearance_layout = QVBoxLayout()
        
        theme_layout = QHBoxLayout()
        theme_layout.addWidget(QLabel("تم:"))
        
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["تاریک", "روشن", "آبی", "بنفش"])
        self.theme_combo.currentTextChanged.connect(self.change_theme)
        theme_layout.addWidget(self.theme_combo)
        
        appearance_layout.addLayout(theme_layout)
        
        font_size_layout = QHBoxLayout()
        font_size_layout.addWidget(QLabel("اندازه فونت:"))
        
        self.font_size_spin = QSpinBox()
        self.font_size_spin.setRange(8, 20)
        self.font_size_spin.setValue(12)
        self.font_size_spin.valueChanged.connect(self.change_font_size)
        font_size_layout.addWidget(self.font_size_spin)
        
        appearance_layout.addLayout(font_size_layout)
        
        appearance_group.setLayout(appearance_layout)
        layout.addWidget(appearance_group)

        security_group = QGroupBox("امنیت")
        security_layout = QVBoxLayout()
        
        self.auto_clear = QCheckBox("پاک کردن خودکار کلیپ‌بورد پس از 30 ثانیه")
        self.auto_clear.setChecked(True)
        security_layout.addWidget(self.auto_clear)
        
        self.save_history = QCheckBox("ذخیره تاریخچه عملیات")
        self.save_history.setChecked(True)
        security_layout.addWidget(self.save_history)
        
        self.confirm_operations = QCheckBox("دریافت تایید برای عملیات مهم")
        self.confirm_operations.setChecked(True)
        security_layout.addWidget(self.confirm_operations)
        
        security_group.setLayout(security_layout)
        layout.addWidget(security_group)
        

        save_settings_btn = QPushButton("💾 ذخیره تنظیمات")
        save_settings_btn.clicked.connect(self.save_settings)
        layout.addWidget(save_settings_btn)
        
        layout.addStretch()
        tab.setLayout(layout)
        self.tabs.addTab(tab, "⚙️ تنظیمات")
        

    
    def quick_encrypt(self):
        """رمزنگاری سریع با Fernet"""
        text = self.quick_input.toPlainText()
        if not text:
            QMessageBox.warning(self, "خطا", "لطفاً متنی وارد کنید")
            return
        
        try:
            self.quick_progress.setVisible(True)
            self.quick_progress.setValue(50)
            
            encrypted = fernet.encrypt(text.encode()).decode()
            self.quick_output.setText(encrypted)
            
            self.quick_progress.setValue(100)
            QTimer.singleShot(1000, lambda: self.quick_progress.setVisible(False))
            
            self.add_to_history("رمزنگاری سریع", "موفق", encrypted[:50] + "...")
            self.status_bar.showMessage("✅ رمزنگاری با موفقیت انجام شد")
            
        except Exception as e:
            QMessageBox.critical(self, "خطا", f"خطا در رمزنگاری: {str(e)}")
            self.quick_progress.setVisible(False)
    
    def quick_decrypt(self):
        """رمزگشایی سریع با Fernet"""
        text = self.quick_input.toPlainText()
        if not text:
            QMessageBox.warning(self, "خطا", "لطفاً متنی وارد کنید")
            return
        
        try:
            self.quick_progress.setVisible(True)
            self.quick_progress.setValue(50)
            
            decrypted = fernet.decrypt(text.encode()).decode()
            self.quick_output.setText(decrypted)
            
            self.quick_progress.setValue(100)
            QTimer.singleShot(1000, lambda: self.quick_progress.setVisible(False))
            
            self.add_to_history("رمزگشایی سریع", "موفق", decrypted[:50] + "...")
            self.status_bar.showMessage("✅ رمزگشایی با موفقیت انجام شد")
            
        except Exception as e:
            QMessageBox.critical(self, "خطا", "متن معتبر نیست یا رمزگشایی ممکن نیست")
            self.quick_progress.setVisible(False)
    
    def generate_new_fernet_key(self):
        """تولید کلید جدید Fernet"""
        global APP_SECRET_KEY, fernet
        APP_SECRET_KEY = Fernet.generate_key()
        fernet = Fernet(APP_SECRET_KEY)
        self.quick_key_display.setText(APP_SECRET_KEY.decode())
        self.status_bar.showMessage("✅ کلید جدید ساخته شد")
    
    def generate_rsa_keys(self):
        """تولید کلیدهای RSA"""
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            

            self.rsa_private_key = private_key
            self.rsa_public_key = public_key
            

            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            self.private_key_display.setText(private_pem.decode())
            self.public_key_display.setText(public_pem.decode())
            
            self.status_bar.showMessage("✅ کلیدهای RSA با موفقیت ساخته شدند")
            self.add_to_history("تولید کلید RSA", "موفق", "کلیدهای 2048 بیتی")
            
        except Exception as e:
            QMessageBox.critical(self, "خطا", f"خطا در تولید کلیدها: {str(e)}")
    
    def rsa_encrypt(self):
        """رمزنگاری با RSA"""
        if not hasattr(self, 'rsa_public_key'):
            QMessageBox.warning(self, "خطا", "لطفاً ابتدا کلید عمومی را بارگذاری کنید")
            return
        
        text = self.rsa_input.toPlainText()
        if not text:
            QMessageBox.warning(self, "خطا", "لطفاً متنی وارد کنید")
            return
        
        try:

            max_length = 190  
            text_bytes = text.encode()
            
            if len(text_bytes) > max_length:

                QMessageBox.warning(self, "خطا", f"متن بسیار بلند است. حداکثر {max_length} کاراکتر مجاز است.")
                return
            
            encrypted = self.rsa_public_key.encrypt(
                text_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            self.rsa_output.setText(base64.b64encode(encrypted).decode())
            self.status_bar.showMessage("✅ رمزنگاری RSA انجام شد")
            self.add_to_history("رمزنگاری RSA", "موفق", text[:50] + "...")
            
        except Exception as e:
            QMessageBox.critical(self, "خطا", f"خطا در رمزنگاری: {str(e)}")
    
    def rsa_decrypt(self):
        """رمزگشایی با RSA"""
        if not hasattr(self, 'rsa_private_key'):
            QMessageBox.warning(self, "خطا", "لطفاً ابتدا کلید خصوصی را بارگذاری کنید")
            return
        
        text = self.rsa_input.toPlainText()
        if not text:
            QMessageBox.warning(self, "خطا", "لطفاً متنی وارد کنید")
            return
        
        try:
            encrypted = base64.b64decode(text.encode())
            
            decrypted = self.rsa_private_key.decrypt(
                encrypted,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            self.rsa_output.setText(decrypted.decode())
            self.status_bar.showMessage("✅ رمزگشایی RSA انجام شد")
            self.add_to_history("رمزگشایی RSA", "موفق", decrypted.decode()[:50] + "...")
            
        except Exception as e:
            QMessageBox.critical(self, "خطا", f"خطا در رمزگشایی: {str(e)}")
    
    def load_public_key(self):
        """بارگذاری کلید عمومی از فایل"""
        filename, _ = QFileDialog.getOpenFileName(self, "انتخاب کلید عمومی", "", "PEM Files (*.pem);;All Files (*.*)")
        if filename:
            try:
                with open(filename, 'rb') as f:
                    public_key_data = f.read()
                
                self.rsa_public_key = serialization.load_pem_public_key(
                    public_key_data,
                    backend=default_backend()
                )
                
                self.public_key_display.setText(public_key_data.decode())
                self.status_bar.showMessage("✅ کلید عمومی بارگذاری شد")
                
            except Exception as e:
                QMessageBox.critical(self, "خطا", f"خطا در بارگذاری کلید: {str(e)}")
    
    def load_private_key(self):
        """بارگذاری کلید خصوصی از فایل"""
        filename, _ = QFileDialog.getOpenFileName(self, "انتخاب کلید خصوصی", "", "PEM Files (*.pem);;All Files (*.*)")
        if filename:
            try:
                with open(filename, 'rb') as f:
                    private_key_data = f.read()
                
                self.rsa_private_key = serialization.load_pem_private_key(
                    private_key_data,
                    password=None,
                    backend=default_backend()
                )
                
                self.private_key_display.setText(private_key_data.decode())
                self.status_bar.showMessage("✅ کلید خصوصی بارگذاری شد")
                
            except Exception as e:
                QMessageBox.critical(self, "خطا", f"خطا در بارگذاری کلید: {str(e)}")
    
    def save_key_to_file(self, key_data, key_type):
        """ذخیره کلید در فایل"""
        filename, _ = QFileDialog.getSaveFileName(self, f"ذخیره کلید {key_type}", "", "PEM Files (*.pem);;All Files (*.*)")
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(key_data)
                self.status_bar.showMessage(f"✅ کلید {key_type} ذخیره شد")
                
            except Exception as e:
                QMessageBox.critical(self, "خطا", f"خطا در ذخیره کلید: {str(e)}")
    
    def add_encryption_layer(self):
        """افزودن لایه رمزنگاری"""
        method = self.layer_method.currentText()
        self.layers_list.addItem(method)
        self.multi_crypto.add_encryption_layer(method)
        self.status_bar.showMessage(f"✅ لایه {method} اضافه شد")
    
    def remove_encryption_layer(self):
        """حذف لایه رمزنگاری"""
        current_row = self.layers_list.currentRow()
        if current_row >= 0:
            self.layers_list.takeItem(current_row)
            if current_row < len(self.multi_crypto.encryption_methods):
                self.multi_crypto.encryption_methods.pop(current_row)
            self.status_bar.showMessage("✅ لایه حذف شد")
    
    def clear_layers(self):
        """پاک کردن همه لایه‌ها"""
        self.layers_list.clear()
        self.multi_crypto.encryption_methods.clear()
        self.status_bar.showMessage("🧹 همه لایه‌ها پاک شدند")
    
    def multi_layer_encrypt(self):
        """رمزنگاری چندلایه"""
        text = self.multi_input.toPlainText()
        if not text:
            QMessageBox.warning(self, "خطا", "لطفاً متنی وارد کنید")
            return
        
        if not self.multi_crypto.encryption_methods:
            QMessageBox.warning(self, "خطا", "لطفاً حداقل یک لایه رمزنگاری اضافه کنید")
            return
        
        try:
            encrypted = self.multi_crypto.encrypt_multi_layer(text)
            self.multi_output.setText(encrypted)
            self.status_bar.showMessage("✅ رمزنگاری چندلایه انجام شد")
            self.add_to_history("رمزنگاری چندلایه", "موفق", f"{len(self.multi_crypto.encryption_methods)} لایه")
            
        except Exception as e:
            QMessageBox.critical(self, "خطا", f"خطا در رمزنگاری: {str(e)}")
    
    def multi_layer_decrypt(self):
        """رمزگشایی چندلایه"""
        text = self.multi_input.toPlainText()
        if not text:
            QMessageBox.warning(self, "خطا", "لطفاً متنی وارد کنید")
            return
        
        if not self.multi_crypto.encryption_methods:
            QMessageBox.warning(self, "خطا", "لطفاً لایه‌های رمزنگاری را مشخص کنید")
            return
        
        try:
            decrypted = self.multi_crypto.decrypt_multi_layer(text)
            self.multi_output.setText(decrypted)
            self.status_bar.showMessage("✅ رمزگشایی چندلایه انجام شد")
            self.add_to_history("رمزگشایی چندلایه", "موفق", f"{len(self.multi_crypto.encryption_methods)} لایه")
            
        except Exception as e:
            QMessageBox.critical(self, "خطا", f"خطا در رمزگشایی: {str(e)}")
    
    def browse_file(self):
        """انتخاب فایل برای رمزنگاری"""
        filename, _ = QFileDialog.getOpenFileName(self, "انتخاب فایل")
        if filename:
            self.file_path.setText(filename)
            self.add_to_recent_files(filename)
    
    def encrypt_file(self):
        """رمزنگاری فایل"""
        filename = self.file_path.text()
        if not filename:
            QMessageBox.warning(self, "خطا", "لطفاً یک فایل انتخاب کنید")
            return
        
        if not os.path.exists(filename):
            QMessageBox.warning(self, "خطا", "فایل وجود ندارد")
            return
        
        try:
            self.file_progress.setValue(10)
            

            with open(filename, 'rb') as f:
                data = f.read()
            
            self.file_progress.setValue(30)
            

            method = self.file_encrypt_method.currentText()
            password = self.file_password.text()
            
            if method == "AES-256":
                if not password:
                    password = secrets.token_urlsafe(32)
                
        
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b'salt_',
                    iterations=100000,
                    backend=default_backend()
                )
                key = kdf.derive(password.encode())
                
         
                iv = secrets.token_bytes(16)
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                encryptor = cipher.encryptor()
                
      
                padded_data = data + b'\0' * (16 - len(data) % 16)
                encrypted = encryptor.update(padded_data) + encryptor.finalize()
                
                result = iv + encrypted
                
            elif method == "Fernet":
                f = Fernet(APP_SECRET_KEY)
                result = f.encrypt(data)
                
            elif method == "RSA + AES":
         
                aes_key = secrets.token_bytes(32)
                
         
                iv = secrets.token_bytes(16)
                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
                encryptor = cipher.encryptor()
                padded_data = data + b'\0' * (16 - len(data) % 16)
                encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
                
      
                if hasattr(self, 'rsa_public_key'):
                    encrypted_key = self.rsa_public_key.encrypt(
                        aes_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    result = encrypted_key + iv + encrypted_data
                else:
                    QMessageBox.warning(self, "خطا", "لطفاً ابتدا کلید عمومی RSA را بارگذاری کنید")
                    return
                    
            elif method == "چندلایه":
      
                temp = base64.b64encode(data).decode()
                for layer in self.multi_crypto.encryption_methods:
                    temp = self.multi_crypto.encrypt_multi_layer(temp)
                result = temp.encode()
            
            self.file_progress.setValue(70)
            
      
            output_filename = filename + ".encrypted"
            with open(output_filename, 'wb') as f:
                f.write(result)
            
            self.file_progress.setValue(100)
            
        
            if self.delete_original.isChecked():
                os.remove(filename)
            
            QMessageBox.information(self, "موفق", f"✅ فایل با موفقیت رمزنگاری شد\nمسیر: {output_filename}")
            self.status_bar.showMessage("✅ رمزنگاری فایل انجام شد")
            self.add_to_history("رمزنگاری فایل", "موفق", os.path.basename(filename))
            
            QTimer.singleShot(2000, lambda: self.file_progress.setValue(0))
            
        except Exception as e:
            QMessageBox.critical(self, "خطا", f"خطا در رمزنگاری فایل: {str(e)}")
            self.file_progress.setValue(0)
    
    def decrypt_file(self):
        """رمزگشایی فایل"""
        filename = self.file_path.text()
        if not filename:
            QMessageBox.warning(self, "خطا", "لطفاً یک فایل انتخاب کنید")
            return
        
        if not os.path.exists(filename):
            QMessageBox.warning(self, "خطا", "فایل وجود ندارد")
            return
        
        try:
            self.file_progress.setValue(10)
            
    
            with open(filename, 'rb') as f:
                data = f.read()
            
            self.file_progress.setValue(30)
            
     
            method = self.file_encrypt_method.currentText()
            password = self.file_password.text()
            
            if method == "AES-256":
                if not password:
                    QMessageBox.warning(self, "خطا", "لطفاً رمز عبور را وارد کنید")
                    return
                
      
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b'salt_',
                    iterations=100000,
                    backend=default_backend()
                )
                key = kdf.derive(password.encode())
                

                iv = data[:16]
                encrypted_data = data[16:]
                
         
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
                
                result = decrypted.rstrip(b'\0')
                
            elif method == "Fernet":
                f = Fernet(APP_SECRET_KEY)
                result = f.decrypt(data)
                
            elif method == "RSA + AES":
                if not hasattr(self, 'rsa_private_key'):
                    QMessageBox.warning(self, "خطا", "لطفاً ابتدا کلید خصوصی RSA را بارگذاری کنید")
                    return
                
      
                encrypted_key = data[:256]  
                iv = data[256:272]  
                encrypted_data = data[272:]
                
   
                aes_key = self.rsa_private_key.decrypt(
                    encrypted_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                

                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
                
                result = decrypted.rstrip(b'\0')
                
            elif method == "چندلایه":
      
                temp = data.decode()
                for layer in reversed(self.multi_crypto.encryption_methods):
                    temp = self.multi_crypto.decrypt_multi_layer(temp)
                result = base64.b64decode(temp)
            
            self.file_progress.setValue(70)
            
     
            if filename.endswith('.encrypted'):
                output_filename = filename[:-10]
            else:
                output_filename = filename + ".decrypted"
            
            with open(output_filename, 'wb') as f:
                f.write(result)
            
            self.file_progress.setValue(100)
            
            QMessageBox.information(self, "موفق", f"✅ فایل با موفقیت رمزگشایی شد\nمسیر: {output_filename}")
            self.status_bar.showMessage("✅ رمزگشایی فایل انجام شد")
            self.add_to_history("رمزگشایی فایل", "موفق", os.path.basename(filename))
            
            QTimer.singleShot(2000, lambda: self.file_progress.setValue(0))
            
        except Exception as e:
            QMessageBox.critical(self, "خطا", f"خطا در رمزگشایی فایل: {str(e)}")
            self.file_progress.setValue(0)
    
    def create_signature(self):
 
        text = self.sign_input.toPlainText()
        if not text:
            QMessageBox.warning(self, "خطا", "لطفاً متنی وارد کنید")
            return
        
        if not hasattr(self, 'rsa_private_key'):
            QMessageBox.warning(self, "خطا", "لطفاً ابتدا کلید خصوصی را بارگذاری کنید")
            return
        
        try:
        
            signature = self.rsa_private_key.sign(
                text.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            self.signature_display.setText(base64.b64encode(signature).decode())
            self.status_bar.showMessage("✅ امضا ایجاد شد")
            self.add_to_history("ایجاد امضا", "موفق", text[:50] + "...")
            
        except Exception as e:
            QMessageBox.critical(self, "خطا", f"خطا در ایجاد امضا: {str(e)}")
    
    def verify_signature(self):
        """بررسی امضای دیجیتال"""
        text = self.sign_input.toPlainText()
        signature_text = self.signature_display.toPlainText()
        
        if not text or not signature_text:
            QMessageBox.warning(self, "خطا", "لطفاً متن و امضا را وارد کنید")
            return
        
        if not hasattr(self, 'rsa_public_key'):
            QMessageBox.warning(self, "خطا", "لطفاً ابتدا کلید عمومی را بارگذاری کنید")
            return
        
        try:
            signature = base64.b64decode(signature_text.encode())
            
     
            self.rsa_public_key.verify(
                signature,
                text.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            self.verify_result.setText("✅ امضا معتبر است")
            self.verify_result.setStyleSheet("background-color: #4caf50; color: white; padding: 10px; border-radius: 5px;")
            self.status_bar.showMessage("✅ امضا معتبر است")
            self.add_to_history("بررسی امضا", "موفق", "امضا معتبر")
            
        except Exception:
            self.verify_result.setText("❌ امضا نامعتبر است")
            self.verify_result.setStyleSheet("background-color: #f44336; color: white; padding: 10px; border-radius: 5px;")
            self.status_bar.showMessage("❌ امضا نامعتبر است")
            self.add_to_history("بررسی امضا", "ناموفق", "امضا نامعتبر")
    
    def open_hash_tool(self):
        """باز کردن ابزار هش"""
        dialog = QDialog(self)
        dialog.setWindowTitle("🔐 تولید هش")
        dialog.setGeometry(200, 200, 500, 400)
        
        layout = QVBoxLayout()
        

        layout.addWidget(QLabel("📝 متن:"))
        hash_input = QTextEdit()
        layout.addWidget(hash_input)
        

        hash_type = QComboBox()
        hash_type.addItems(["MD5", "SHA-1", "SHA-256", "SHA-512"])
        layout.addWidget(hash_type)
        
   
        generate_btn = QPushButton("🔄 تولید هش")
        layout.addWidget(generate_btn)
        
 
        layout.addWidget(QLabel("📄 نتیجه:"))
        hash_output = QTextEdit()
        hash_output.setReadOnly(True)
        layout.addWidget(hash_output)
        
        def generate_hash():
            text = hash_input.toPlainText()
            if not text:
                return
            
            if hash_type.currentText() == "MD5":
                result = hashlib.md5(text.encode()).hexdigest()
            elif hash_type.currentText() == "SHA-1":
                result = hashlib.sha1(text.encode()).hexdigest()
            elif hash_type.currentText() == "SHA-256":
                result = hashlib.sha256(text.encode()).hexdigest()
            else:
                result = hashlib.sha512(text.encode()).hexdigest()
            
            hash_output.setText(result)
        
        generate_btn.clicked.connect(generate_hash)
        
        dialog.setLayout(layout)
        dialog.exec_()
    
    def open_password_generator(self):
        """باز کردن ابزار تولید رمز عبور"""
        dialog = QDialog(self)
        dialog.setWindowTitle("🔑 تولید رمز عبور قوی")
        dialog.setGeometry(200, 200, 400, 350)
        
        layout = QVBoxLayout()
        
  
        length_label = QLabel("طول رمز عبور:")
        layout.addWidget(length_label)
        
        length_spin = QSpinBox()
        length_spin.setRange(8, 64)
        length_spin.setValue(16)
        layout.addWidget(length_spin)
        

        use_upper = QCheckBox("حروف بزرگ (A-Z)")
        use_upper.setChecked(True)
        layout.addWidget(use_upper)
        
        use_lower = QCheckBox("حروف کوچک (a-z)")
        use_lower.setChecked(True)
        layout.addWidget(use_lower)
        
        use_digits = QCheckBox("اعداد (0-9)")
        use_digits.setChecked(True)
        layout.addWidget(use_digits)
        
        use_symbols = QCheckBox("نمادها (!@#$%)")
        use_symbols.setChecked(True)
        layout.addWidget(use_symbols)
        
  
        generate_btn = QPushButton("🔄 تولید رمز عبور")
        layout.addWidget(generate_btn)
        

        result_label = QLineEdit()
        result_label.setReadOnly(True)
        layout.addWidget(result_label)
        

        copy_btn = QPushButton("📋 کپی")
        copy_btn.clicked.connect(lambda: self.copy_to_clipboard(result_label.text()))
        layout.addWidget(copy_btn)
        
        def generate():
            chars = ""
            if use_upper.isChecked():
                chars += string.ascii_uppercase
            if use_lower.isChecked():
                chars += string.ascii_lowercase
            if use_digits.isChecked():
                chars += string.digits
            if use_symbols.isChecked():
                chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
            
            if not chars:
                QMessageBox.warning(dialog, "خطا", "حداقل یک گزینه را انتخاب کنید")
                return
            
            password = ''.join(secrets.choice(chars) for _ in range(length_spin.value()))
            result_label.setText(password)
        
        generate_btn.clicked.connect(generate)
        
        dialog.setLayout(layout)
        dialog.exec_()
    
    def add_to_recent_files(self, filename):
        """افزودن به لیست فایل‌های اخیر"""
        items = [self.recent_files.item(i).text() for i in range(self.recent_files.count())]
        if filename not in items:
            self.recent_files.addItem(filename)
            if self.recent_files.count() > 10:
                self.recent_files.takeItem(0)
    
    def load_recent_file(self, item):
        """بارگذاری فایل از لیست اخیر"""
        self.file_path.setText(item.text())
    
    def add_key_dialog(self):
        """دیالوگ افزودن کلید جدید"""
        dialog = QDialog(self)
        dialog.setWindowTitle("➕ افزودن کلید جدید")
        dialog.setGeometry(200, 200, 500, 400)
        
        layout = QVBoxLayout()
        

        layout.addWidget(QLabel("نام کلید:"))
        key_name = QLineEdit()
        layout.addWidget(key_name)
        
  
        layout.addWidget(QLabel("نوع کلید:"))
        key_type = QComboBox()
        key_type.addItems(["RSA Public", "RSA Private", "Fernet", "AES", "Custom"])
        layout.addWidget(key_type)
        
       
        layout.addWidget(QLabel("مقدار کلید:"))
        key_value = QTextEdit()
        layout.addWidget(key_value)
        
      
        save_btn = QPushButton("💾 ذخیره کلید")
        layout.addWidget(save_btn)
        
        def save_key():
            name = key_name.text()
            if not name:
                QMessageBox.warning(dialog, "خطا", "لطفاً نام کلید را وارد کنید")
                return
            
            value = key_value.toPlainText()
            if not value:
                QMessageBox.warning(dialog, "خطا", "لطفاً مقدار کلید را وارد کنید")
                return
            
            self.keys_list.addItem(f"{name} ({key_type.currentText()})")
            self.keys[name] = {
                'type': key_type.currentText(),
                'value': value
            }
            
            dialog.accept()
            self.status_bar.showMessage(f"✅ کلید {name} اضافه شد")
        
        save_btn.clicked.connect(save_key)
        
        dialog.setLayout(layout)
        dialog.exec_()
    
    def delete_key(self):
        """حذف کلید انتخاب شده"""
        current_row = self.keys_list.currentRow()
        if current_row >= 0:
            item = self.keys_list.takeItem(current_row)
            key_name = item.text().split(' ')[0]
            if key_name in self.keys:
                del self.keys[key_name]
            self.status_bar.showMessage(f"✅ کلید {key_name} حذف شد")
    
    def export_keys(self):
        """خروجی گرفتن از کلیدها"""
        filename, _ = QFileDialog.getSaveFileName(self, "ذخیره کلیدها", "", "JSON Files (*.json)")
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self.keys, f, indent=4, ensure_ascii=False)
                self.status_bar.showMessage("✅ کلیدها ذخیره شدند")
                
            except Exception as e:
                QMessageBox.critical(self, "خطا", f"خطا در ذخیره کلیدها: {str(e)}")
    
    def import_keys(self):
        """ورودی گرفتن کلیدها"""
        filename, _ = QFileDialog.getOpenFileName(self, "بارگذاری کلیدها", "", "JSON Files (*.json)")
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    imported_keys = json.load(f)
                
                self.keys.update(imported_keys)
                

                self.keys_list.clear()
                for name, info in self.keys.items():
                    self.keys_list.addItem(f"{name} ({info['type']})")
                
                self.status_bar.showMessage("✅ کلیدها بارگذاری شدند")
                
            except Exception as e:
                QMessageBox.critical(self, "خطا", f"خطا در بارگذاری کلیدها: {str(e)}")
    
    def add_to_history(self, operation, status, result):
        """افزودن به تاریخچه"""
        if hasattr(self, 'save_history') and not self.save_history.isChecked():
            return
        
        row = self.history_table.rowCount()
        self.history_table.insertRow(row)
        
        time_item = QTableWidgetItem(datetime.now().strftime("%H:%M:%S"))
        op_item = QTableWidgetItem(operation)
        result_item = QTableWidgetItem(result)
        status_item = QTableWidgetItem(status)
        
        if status == "موفق":
            status_item.setForeground(QColor("#4caf50"))
        else:
            status_item.setForeground(QColor("#f44336"))
        
        self.history_table.setItem(row, 0, time_item)
        self.history_table.setItem(row, 1, op_item)
        self.history_table.setItem(row, 2, result_item)
        self.history_table.setItem(row, 3, status_item)
        
        self.history_table.resizeColumnsToContents()
    
    def clear_history(self):
        """پاک کردن تاریخچه"""
        self.history_table.setRowCount(0)
        self.status_bar.showMessage("🧹 تاریخچه پاک شد")
    
    def export_history(self):
        """خروجی گرفتن از تاریخچه"""
        filename, _ = QFileDialog.getSaveFileName(self, "ذخیره تاریخچه", "", "CSV Files (*.csv)")
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("زمان,عملیات,نتیجه,وضعیت\n")
                    for row in range(self.history_table.rowCount()):
                        time = self.history_table.item(row, 0).text()
                        op = self.history_table.item(row, 1).text()
                        result = self.history_table.item(row, 2).text()
                        status = self.history_table.item(row, 3).text()
                        f.write(f"{time},{op},{result},{status}\n")
                
                self.status_bar.showMessage("✅ تاریخچه ذخیره شد")
                
            except Exception as e:
                QMessageBox.critical(self, "خطا", f"خطا در ذخیره تاریخچه: {str(e)}")
    
    def copy_to_clipboard(self, text):
        """کپی متن به کلیپ‌بورد"""
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        self.status_bar.showMessage("📋 کپی شد")
        
        if hasattr(self, 'auto_clear') and self.auto_clear.isChecked():
            QTimer.singleShot(30000, lambda: self.clear_clipboard_if_match(text))
    
    def clear_clipboard_if_match(self, original_text):
        """پاک کردن کلیپ‌بورد اگر متن مطابقت داشت"""
        clipboard = QApplication.clipboard()
        if clipboard.text() == original_text:
            clipboard.clear()
            self.status_bar.showMessage("🧹 کلیپ‌بورد پاک شد")
    
    def new_file(self):
        """ایجاد فایل جدید"""
        self.quick_input.clear()
        self.quick_output.clear()
        self.rsa_input.clear()
        self.rsa_output.clear()
        self.multi_input.clear()
        self.multi_output.clear()
        self.sign_input.clear()
        self.signature_display.clear()
        self.status_bar.showMessage("📄 فایل جدید ایجاد شد")
    
    def open_file(self):
        """باز کردن فایل"""
        filename, _ = QFileDialog.getOpenFileName(self, "باز کردن فایل", "", "All Files (*.*)")
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                
       
                current_tab = self.tabs.currentIndex()
                if current_tab == 0:  
                    self.quick_input.setText(content)
                elif current_tab == 1: 
                    self.rsa_input.setText(content)
                elif current_tab == 2:  
                    self.multi_input.setText(content)
                
                self.current_file = filename
                self.status_bar.showMessage(f"📂 فایل باز شد: {os.path.basename(filename)}")
                
            except Exception as e:
                QMessageBox.critical(self, "خطا", f"خطا در باز کردن فایل: {str(e)}")
    
    def save_file(self):
        """ذخیره فایل"""
        if not self.current_file:
            filename, _ = QFileDialog.getSaveFileName(self, "ذخیره فایل", "", "Text Files (*.txt)")
            if filename:
                self.current_file = filename
            else:
                return
        
        try:
      
            current_tab = self.tabs.currentIndex()
            if current_tab == 0:  
                content = self.quick_input.toPlainText()
            elif current_tab == 1:  
                content = self.rsa_input.toPlainText()
            elif current_tab == 2:  
                content = self.multi_input.toPlainText()
            else:
                content = ""
            
            with open(self.current_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            self.status_bar.showMessage(f"💾 فایل ذخیره شد: {os.path.basename(self.current_file)}")
            
        except Exception as e:
            QMessageBox.critical(self, "خطا", f"خطا در ذخیره فایل: {str(e)}")
    
    def export_data(self):
        """خروجی گرفتن از داده‌ها"""
        filename, _ = QFileDialog.getSaveFileName(self, "خروجی گرفتن", "", "JSON Files (*.json)")
        if filename:
            data = {
                'quick_input': self.quick_input.toPlainText(),
                'quick_output': self.quick_output.toPlainText(),
                'rsa_input': self.rsa_input.toPlainText(),
                'rsa_output': self.rsa_output.toPlainText(),
                'multi_input': self.multi_input.toPlainText(),
                'multi_output': self.multi_output.toPlainText(),
                'history': []
            }
            
        
            for row in range(self.history_table.rowCount()):
                data['history'].append({
                    'time': self.history_table.item(row, 0).text(),
                    'operation': self.history_table.item(row, 1).text(),
                    'result': self.history_table.item(row, 2).text(),
                    'status': self.history_table.item(row, 3).text()
                })
            
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=4, ensure_ascii=False)
                self.status_bar.showMessage("✅ خروجی گرفته شد")
                
            except Exception as e:
                QMessageBox.critical(self, "خطا", f"خطا در خروجی: {str(e)}")
    
    def import_data(self):
        """ورودی گرفتن از داده‌ها"""
        filename, _ = QFileDialog.getOpenFileName(self, "ورودی گرفتن", "", "JSON Files (*.json)")
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                self.quick_input.setText(data.get('quick_input', ''))
                self.quick_output.setText(data.get('quick_output', ''))
                self.rsa_input.setText(data.get('rsa_input', ''))
                self.rsa_output.setText(data.get('rsa_output', ''))
                self.multi_input.setText(data.get('multi_input', ''))
                self.multi_output.setText(data.get('multi_output', ''))
                
                self.status_bar.showMessage("✅ ورودی گرفته شد")
                
            except Exception as e:
                QMessageBox.critical(self, "خطا", f"خطا در ورودی: {str(e)}")
    
    def change_theme(self, theme):
        """تغییر تم برنامه"""
        themes = {
            "تاریک": StyleManager.DARK_STYLE,
            "روشن": """
                QMainWindow { background-color: #f5f5f5; }
                QTabWidget::pane { background-color: white; border: 2px solid #2196F3; }
                QTabBar::tab { background-color: #e3f2fd; color: black; }
                QTabBar::tab:selected { background-color: #2196F3; color: white; }
                QTextEdit, QLineEdit { background-color: white; color: black; border: 2px solid #2196F3; }
                QPushButton { background-color: #2196F3; color: white; }
                QPushButton:hover { background-color: #1976D2; }
                QLabel { color: black; }
                QComboBox { background-color: white; color: black; border: 2px solid #2196F3; }
                QListWidget { background-color: white; color: black; border: 2px solid #2196F3; }
                QMenuBar { background-color: #e3f2fd; color: black; }
                QMenu { background-color: white; color: black; }
            """,
            "آبی": """
                QMainWindow { background-color: #e3f2fd; }
                QTabWidget::pane { background-color: #bbdefb; border: 2px solid #1976D2; }
                QTabBar::tab { background-color: #90caf9; color: black; }
                QTabBar::tab:selected { background-color: #1976D2; color: white; }
                QTextEdit, QLineEdit { background-color: white; color: black; border: 2px solid #1976D2; }
                QPushButton { background-color: #1976D2; color: white; }
                QLabel { color: #0d47a1; }
            """,
            "بنفش": """
                QMainWindow { background-color: #f3e5f5; }
                QTabWidget::pane { background-color: #e1bee7; border: 2px solid #7b1fa2; }
                QTabBar::tab { background-color: #ce93d8; color: black; }
                QTabBar::tab:selected { background-color: #7b1fa2; color: white; }
                QTextEdit, QLineEdit { background-color: white; color: black; border: 2px solid #7b1fa2; }
                QPushButton { background-color: #7b1fa2; color: white; }
                QLabel { color: #4a148c; }
            """
        }
        
        self.setStyleSheet(themes.get(theme, StyleManager.DARK_STYLE))
    
    def change_font_size(self, size):
        """تغییر اندازه فونت"""
        font = QFont("Vazir", size)
        self.setFont(font)
    
    def save_settings(self):
        """ذخیره تنظیمات"""
        settings = {
            'theme': self.theme_combo.currentText(),
            'font_size': self.font_size_spin.value(),
            'auto_clear': self.auto_clear.isChecked(),
            'save_history': self.save_history.isChecked(),
            'confirm_operations': self.confirm_operations.isChecked()
        }
        
        try:
            with open('settings.json', 'w', encoding='utf-8') as f:
                json.dump(settings, f, indent=4, ensure_ascii=False)
            
            QMessageBox.information(self, "موفق", "✅ تنظیمات با موفقیت ذخیره شد")
            self.status_bar.showMessage("✅ تنظیمات ذخیره شد")
            
        except Exception as e:
            QMessageBox.critical(self, "خطا", f"خطا در ذخیره تنظیمات: {str(e)}")
    
    def load_settings(self):
        """بارگذاری تنظیمات"""
        try:
            if os.path.exists('settings.json'):
                with open('settings.json', 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                
                if hasattr(self, 'theme_combo'):
                    self.theme_combo.setCurrentText(settings.get('theme', 'تاریک'))
                if hasattr(self, 'font_size_spin'):
                    self.font_size_spin.setValue(settings.get('font_size', 12))
                if hasattr(self, 'auto_clear'):
                    self.auto_clear.setChecked(settings.get('auto_clear', True))
                if hasattr(self, 'save_history'):
                    self.save_history.setChecked(settings.get('save_history', True))
                if hasattr(self, 'confirm_operations'):
                    self.confirm_operations.setChecked(settings.get('confirm_operations', True))
                
        except Exception as e:
            print(f"خطا در بارگذاری تنظیمات: {e}")
    
    def update_status(self):
        """به‌روزرسانی نوار وضعیت"""
      
        pass
    
    def show_about(self):
        """نمایش درباره برنامه"""
        about_text = """
        <div style='text-align: center;'>
            <h1>🔐 Quantum Crypto Vault</h1>
            <h3>نسخه ۲.۰ - پیشرفته</h3>
            <br/>
            <p>یک برنامه رمزنگاری پیشرفته و چندلایه</p>
            <p>با قابلیت‌های:</p>
            <ul style='text-align: left;'>
                <li>✅ رمزنگاری سریع با Fernet</li>
                <li>✅ رمزنگاری نامتقارن RSA</li>
                <li>✅ رمزنگاری چندلایه (ابدی)</li>
                <li>✅ رمزنگاری فایل‌ها با روش‌های مختلف</li>
                <li>✅ امضای دیجیتال</li>
                <li>✅ مدیریت کلیدها</li>
                <li>✅ تولید رمز عبور قوی</li>
                <li>✅ و بسیاری قابلیت‌های دیگر...</li>
            </ul>
            <br/>
            <p>توسعه یافته توسط: تیم نوآوران</p>
            <p>تمامی حقوق محفوظ است © ۲۰۲۴</p>
        </div>
        """
        
        QMessageBox.about(self, "درباره برنامه", about_text)
    
    def show_tutorial(self):
        """نمایش آموزش"""
        tutorial_text = """
        <div style='text-align: right;'>
            <h2>📚 آموزش استفاده از برنامه</h2>
            
            <h3>⚡ رمزنگاری سریع:</h3>
            <p>1. متن خود را وارد کنید</p>
            <p>2. روی دکمه رمزنگاری کلیک کنید</p>
            <p>3. نتیجه را کپی یا ذخیره کنید</p>
            
            <h3>🔑 رمزنگاری RSA:</h3>
            <p>1. ابتدا کلیدهای RSA را تولید کنید</p>
            <p>2. کلید عمومی را برای دوستان خود ارسال کنید</p>
            <p>3. با کلید عمومی دوستان، پیام را رمزنگاری کنید</p>
            <p>4. برای رمزگشایی از کلید خصوصی خود استفاده کنید</p>
            
            <h3>🔄 رمزنگاری چندلایه:</h3>
            <p>1. لایه‌های رمزنگاری را به ترتیب اضافه کنید</p>
            <p>2. متن را وارد و رمزنگاری کنید</p>
            <p>3. برای رمزگشایی، همان لایه‌ها را به ترتیب معکوس اعمال کنید</p>
            
            <h3>📁 رمزنگاری فایل:</h3>
            <p>1. فایل مورد نظر را انتخاب کنید</p>
            <p>2. روش رمزنگاری را انتخاب کنید</p>
            <p>3. در صورت نیاز رمز عبور وارد کنید</p>
            <p>4. روی دکمه رمزنگاری کلیک کنید</p>
            
            <h3>⚠️ نکات امنیتی:</h3>
            <ul>
                <li>هرگز کلید خصوصی خود را در اختیار کسی قرار ندهید</li>
                <li>از رمزهای عبور قوی استفاده کنید</li>
                <li>فایل‌های مهم را در چند مکان ذخیره کنید</li>
                <li>تنظیمات امنیتی را بررسی کنید</li>
            </ul>
        </div>
        """
        
        msg = QMessageBox()
        msg.setWindowTitle("آموزش")
        msg.setText(tutorial_text)
        msg.setTextFormat(Qt.RichText)
        msg.exec_()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    

    font = QFont("Vazir", 12)
    app.setFont(font)
    

    window = QuantumCryptoVault()
    window.show()
    
    sys.exit(app.exec_())
