import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog, QLineEdit, QMessageBox
)
from PyQt5.QtCore import Qt
from cryptography.fernet import Fernet, InvalidToken
import base64
import hashlib

class XillenFileEncryptor(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Xillen File Encryptor")
        self.setMinimumSize(500, 300)
        self.file_path = ""
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.label = QLabel("Выберите файл для шифрования или расшифровки")
        self.label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.label)

        self.btn_choose = QPushButton("Выбрать файл")
        self.btn_choose.clicked.connect(self.choose_file)
        layout.addWidget(self.btn_choose)

        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("Введите пароль")
        self.pass_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.pass_input)

        self.btn_encrypt = QPushButton("Зашифровать файл")
        self.btn_encrypt.clicked.connect(self.encrypt_file)
        layout.addWidget(self.btn_encrypt)

        self.btn_decrypt = QPushButton("Расшифровать файл")
        self.btn_decrypt.clicked.connect(self.decrypt_file)
        layout.addWidget(self.btn_decrypt)

        self.setLayout(layout)

    def choose_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выбрать файл")
        if path:
            self.file_path = path
            self.label.setText(f"Файл: {os.path.basename(path)}")

    def get_key(self):
        password = self.pass_input.text().strip().encode()
        if not password:
            return None
        key = hashlib.sha256(password).digest()
        return base64.urlsafe_b64encode(key)

    def encrypt_file(self):
        if not self.file_path or not self.pass_input.text():
            QMessageBox.warning(self, "Ошибка", "Выберите файл и введите пароль!")
            return
        key = self.get_key()
        fernet = Fernet(key)
        try:
            with open(self.file_path, "rb") as f:
                data = f.read()
            enc = fernet.encrypt(data)
            base, ext = os.path.splitext(self.file_path)
            out_path = f"{base}_encrypted{ext}"
            with open(out_path, "wb") as f:
                f.write(enc)
            QMessageBox.information(self, "Успех", f"Файл зашифрован: {out_path}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось зашифровать: {e}")

    def decrypt_file(self):
        if not self.file_path or not self.pass_input.text():
            QMessageBox.warning(self, "Ошибка", "Выберите файл и введите пароль!")
            return
        key = self.get_key()
        fernet = Fernet(key)
        try:
            with open(self.file_path, "rb") as f:
                data = f.read()
            dec = fernet.decrypt(data)
            base, ext = os.path.splitext(self.file_path)
            out_path = f"{base}_decrypted{ext}"
            with open(out_path, "wb") as f:
                f.write(dec)
            QMessageBox.information(self, "Успех", f"Файл расшифрован: {out_path}")
        except InvalidToken:
            QMessageBox.critical(self, "Ошибка", "Неверный пароль или файл повреждён!")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось расшифровать: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = XillenFileEncryptor()
    win.show()
    sys.exit(app.exec_())
