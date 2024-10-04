import sys
import subprocess
import json
import os
import zipfile
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QMessageBox, QFormLayout, QScrollArea,
    QFrame, QDialog, QCheckBox, QInputDialog, QGroupBox, QStyle
)
from PyQt5.QtCore import Qt, QSettings, QThread, pyqtSignal
from PyQt5.QtGui import QIcon, QFont
import socket
import time

class ConnectionThread(QThread):
    connection_finished = pyqtSignal(str, bool)

    def __init__(self, pcoip_args):
        super().__init__()
        self.pcoip_args = pcoip_args

    def run(self):
        try:
            result = subprocess.run(self.pcoip_args, capture_output=True, text=True, check=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
            self.connection_finished.emit(result.stdout, True)
        except subprocess.CalledProcessError as e:
            error_message = e.stderr if e.stderr else f"Error running command: {e}"
            self.connection_finished.emit(error_message, False)
        except subprocess.TimeoutExpired:
            self.connection_finished.emit('Connection closed or attempt timed out after 10 seconds.', False)
        except Exception as e:
            self.connection_finished.emit(f'Unexpected error: {e}', False)

class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('User Login')
        self.setFixedSize(300, 180)

        self.layout = QVBoxLayout()
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        self.show_password_checkbox = QCheckBox('Show Password')
        self.show_password_checkbox.stateChanged.connect(self.toggle_password_visibility)

        self.buttons_layout = QHBoxLayout()
        self.ok_button = QPushButton('OK')
        self.cancel_button = QPushButton('Cancel')
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)

        self.layout.addWidget(QLabel('Enter Username:'))
        self.layout.addWidget(self.username_input)
        self.layout.addWidget(QLabel('Enter Password:'))
        self.layout.addWidget(self.password_input)
        self.layout.addWidget(self.show_password_checkbox)
        self.buttons_layout.addWidget(self.ok_button)
        self.buttons_layout.addWidget(self.cancel_button)
        self.layout.addLayout(self.buttons_layout)
        self.setLayout(self.layout)

    def toggle_password_visibility(self):
        if self.show_password_checkbox.isChecked():
            self.password_input.setEchoMode(QLineEdit.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.Password)

    def get_credentials(self):
        return self.username_input.text(), self.password_input.text()

class UpdateLoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Update Login Information')
        self.setFixedSize(300, 200)

        self.layout = QVBoxLayout()

        self.ip_input = QLineEdit()
        self.domain_input = QLineEdit()
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        self.show_password_checkbox = QCheckBox('Show Password')
        self.show_password_checkbox.stateChanged.connect(self.toggle_password_visibility)

        form_layout = QFormLayout()
        form_layout.addRow('IP or FQDN:', self.ip_input)
        form_layout.addRow('Domain Name:', self.domain_input)
        form_layout.addRow('Username:', self.username_input)
        form_layout.addRow('Password:', self.password_input)
        form_layout.addWidget(self.show_password_checkbox)

        self.buttons_layout = QHBoxLayout()
        self.save_button = QPushButton('Save')
        self.cancel_button = QPushButton('Cancel')
        
        self.save_button.clicked.connect(self.save_login_info)
        self.cancel_button.clicked.connect(self.reject)

        self.buttons_layout.addWidget(self.save_button)
        self.buttons_layout.addWidget(self.cancel_button)

        self.layout.addLayout(form_layout)
        self.layout.addLayout(self.buttons_layout)
        self.setLayout(self.layout)

    def toggle_password_visibility(self):
        if self.show_password_checkbox.isChecked():
            self.password_input.setEchoMode(QLineEdit.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.Password)

    def save_login_info(self):
        ip = self.ip_input.text().strip()
        domain = self.domain_input.text().strip()
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        if not all([ip, domain, username, password]):
            QMessageBox.warning(self, 'Input Error', 'Please fill in all fields.')
            return

        desktop_path = os.path.join(os.path.expanduser('~'), 'Desktop')
        bin_path = os.path.join(desktop_path, 'bin')
        if not os.path.exists(bin_path):
            os.makedirs(bin_path)

        login_info_path = os.path.join(bin_path, 'login_info.txt')

        if os.path.exists(login_info_path):
            with open(login_info_path, 'r') as file:
                lines = file.readlines()
        else:
            lines = []

        entry = f"{ip} {domain} {username} {password}\n"
        
        if entry in lines:
            lines.remove(entry)
            lines.insert(0, entry)
            QMessageBox.information(self, 'Duplicate Entry', 'This entry was moved to the top.')
        else:
            lines.insert(0, entry)
            QMessageBox.information(self, 'Success', 'Login information updated successfully.')

        try:
            with open(login_info_path, 'w') as file:
                file.writelines(lines)
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, 'File Error', f'Failed to save login information: {e}')

class PCoIPClientApp(QWidget):
    def __init__(self):
        super().__init__()
        self.connections = {}
        self.connection_details = {}
        self.settings = QSettings('YourCompany', 'PCoIPClientApp')
        self.load_connections()
        self.load_connection_details()
        self.credentials = self.load_credentials()
        self.initUI()
        self.connection_thread = None
        self.active_connection = None

        self.extract_bin_to_desktop()

    def extract_bin_to_desktop(self):
        desktop_path = os.path.join(os.path.expanduser('~'), 'Desktop')
        target_path = os.path.join(desktop_path, 'bin')

        if os.path.exists(target_path):
            print("Folder is already there.")
            return

        if getattr(sys, 'frozen', False):
            zip_path = os.path.join(sys._MEIPASS, 'bin.zip')
        else:
            zip_path = 'C:\\Python\\SDK\\bin.zip'

        os.makedirs(target_path, exist_ok=True)

        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                for member in zip_ref.namelist():
                    member_filename = os.path.basename(member)
                    if not member_filename:
                        continue
                    target_file_path = os.path.join(target_path, member_filename)
                    with open(target_file_path, 'wb') as file:
                        file.write(zip_ref.read(member))

            print(f"Extracted {zip_path} to {target_path} without nested directories.")
        except Exception as e:
            print(f"Failed to extract {zip_path}: {e}")

    def initUI(self):
        self.setWindowTitle('PCoIP Connection Manager')
        self.setFixedSize(800, 600)
        self.setWindowIcon(QIcon('icon.png'))
        self.setFont(QFont('Segoe UI', 10))

        main_layout = QVBoxLayout(self)

        global_check_layout = QHBoxLayout()

        self.remote_check_button = QPushButton()
        self.remote_check_button.setIcon(self.style().standardIcon(QStyle.SP_DialogApplyButton))
        self.remote_check_button.setFixedSize(50, 50)
        self.remote_check_button.setToolTip('Perform Remote Check')
        self.remote_check_button.setStyleSheet("""
            QPushButton {
                border: 1px solid #d0d0d0; 
                border-radius: 5px; 
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
        """)
        self.remote_check_button.clicked.connect(self.check_remote)

        self.local_check_button = QPushButton()
        self.local_check_button.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        self.local_check_button.setFixedSize(50, 50)
        self.local_check_button.setToolTip('Perform Local Check')
        self.local_check_button.setStyleSheet("""
            QPushButton {
                border: 1px solid #d0d0d0; 
                border-radius: 5px; 
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
        """)
        self.local_check_button.clicked.connect(self.perform_local_checks)

        self.login_info_button = QPushButton()
        self.login_info_button.setIcon(self.style().standardIcon(QStyle.SP_DialogOpenButton))
        self.login_info_button.setFixedSize(50, 50)
        self.login_info_button.setStyleSheet("""
            QPushButton {
                border: 1px solid #d0d0d0; 
                border-radius: 5px; 
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
        """)
        self.login_info_button.setToolTip('Update Login Info')
        self.login_info_button.clicked.connect(self.open_login_info_dialog)

        global_check_layout.addWidget(self.remote_check_button)
        global_check_layout.addWidget(self.local_check_button)
        global_check_layout.addWidget(self.login_info_button)

        add_connection_group = QGroupBox("Add Connection")
        add_connection_layout = QFormLayout()

        self.host_input = QLineEdit()
        self.name_input = QLineEdit()

        self.add_button = QPushButton('Add Connection')
        self.add_button.setFixedSize(150, 40)
        self.add_button.clicked.connect(self.add_connection)

        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel('Host Address:'))
        input_layout.addWidget(self.host_input)
        input_layout.addWidget(QLabel('Connection Name:'))
        input_layout.addWidget(self.name_input)
        input_layout.addWidget(self.add_button)

        add_connection_group.setLayout(input_layout)

        saved_connections_group = QGroupBox("Saved Connections")
        saved_connections_layout = QVBoxLayout()

        self.connections_widget = QWidget()
        self.connections_layout = QVBoxLayout()
        self.connections_layout.setContentsMargins(0, 0, 0, 0)
        self.connections_layout.setSpacing(5)
        self.connections_layout.setAlignment(Qt.AlignTop)
        self.connections_widget.setLayout(self.connections_layout)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(self.connections_widget)
        saved_connections_layout.addWidget(scroll_area)

        saved_connections_group.setLayout(saved_connections_layout)

        main_layout.addLayout(global_check_layout)
        main_layout.addWidget(add_connection_group)
        main_layout.addWidget(saved_connections_group)

        self.refresh_connections_ui()

    def open_login_info_dialog(self):
        dialog = UpdateLoginDialog(self)
        dialog.exec()

    def add_connection(self):
        host = self.host_input.text().strip()
        name = self.name_input.text().strip()

        if not host or not name:
            QMessageBox.warning(self, 'Input Error', 'Please provide both a host address and connection name.')
            return

        self.connections[name] = (host, name)
        self.save_connections()
        self.add_connection_to_ui(name, host)
        self.host_input.clear()
        self.name_input.clear()

    def add_connection_to_ui(self, name, host):
        conn_layout = QHBoxLayout()
        conn_layout.setContentsMargins(0, 0, 0, 0)
        conn_layout.setSpacing(5)

        conn_button = QPushButton(name)
        conn_button.setFixedSize(150, 40)
        conn_button.setStyleSheet("""
            QPushButton {
                border: 1px solid #d0d0d0; 
                border-radius: 5px; 
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
        """)
        conn_button.clicked.connect(lambda: self.connect_to_broker(name))

        edit_button = QPushButton()
        edit_button.setIcon(self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
        edit_button.setFixedSize(50, 50)
        edit_button.setToolTip('Edit Connection')
        edit_button.setStyleSheet("""
            QPushButton {
                border: 1px solid #d0d0d0; 
                border-radius: 5px; 
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
        """)
        edit_button.clicked.connect(lambda: self.edit_connection(name))

        delete_button = QPushButton()
        delete_button.setIcon(self.style().standardIcon(QStyle.SP_DialogCancelButton))
        delete_button.setFixedSize(50, 50)
        delete_button.setToolTip('Delete Connection')
        delete_button.setStyleSheet("""
            QPushButton {
                border: 1px solid #d0d0d0; 
                border-radius: 5px; 
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
        """)
        delete_button.clicked.connect(lambda: self.delete_connection(name))

        conn_layout.addWidget(conn_button, alignment=Qt.AlignLeft)
        conn_layout.addStretch()
        conn_layout.addWidget(edit_button, alignment=Qt.AlignRight)
        conn_layout.addWidget(delete_button, alignment=Qt.AlignRight)

        conn_frame = QFrame()
        conn_frame.setLayout(conn_layout)
        conn_frame.setFrameShape(QFrame.StyledPanel)
        conn_frame.setStyleSheet("""
            QFrame { 
                background-color: #ffffff; 
                margin: 2px;  
                padding: 5px;  
                border: 1px solid #d0d0d0; 
                border-radius: 5px;
            }
        """)

        self.connections_layout.addWidget(conn_frame)

    def perform_local_checks(self):
        local_ip = socket.gethostbyname(socket.gethostname())
        checks = {
            'Device connected to the network.': '✔' if self.ping(local_ip) else '✖',
            'Device connected to the internet.': '✔' if self.check_internet() else '✖',
            'Connection over TCP Ports established.': '✔' if self.check_port(local_ip, 4172, 'tcp') else '✖',
            'Connection over UDP Ports established.': '✔' if self.check_port(local_ip, 4172, 'udp') else '✖',
            'Round Trip Time': self.calculate_rtt(local_ip)
        }
        self.display_check_results(local_ip, "Local Machine", checks)

    def calculate_rtt(self, ip):
        try:
            start_time = time.time()
            if self.ping(ip):
                end_time = time.time()
                return f"{round((end_time - start_time) * 1000, 2)} ms"
            else:
                return "N/A"
        except Exception:
            return "N/A"

    def edit_connection(self, name):
        host, _ = self.connections[name]

        new_host, ok_host = QInputDialog.getText(self, 'Edit Connection', 'Edit Host Address:', text=host)
        if not ok_host or not new_host:
            return

        new_name, ok_name = QInputDialog.getText(self, 'Edit Connection', 'Edit Connection Name:', text=name)
        if not ok_name or not new_name:
            return

        del self.connections[name]
        self.connections[new_name] = (new_host, new_name)
        self.save_connections()
        self.refresh_connections_ui()

    def delete_connection(self, name):
        del self.connections[name]
        if name in self.connection_details:
            del self.connection_details[name]
            self.save_connection_details()
        self.save_connections()
        self.refresh_connections_ui()

    def refresh_connections_ui(self):
        for i in reversed(range(self.connections_layout.count())):
            layout_item = self.connections_layout.itemAt(i)
            widget = layout_item.widget()
            if widget is not None:
                widget.deleteLater()

        for name, (host, _) in self.connections.items():
            self.add_connection_to_ui(name, host)

    def save_connections(self):
        self.settings.setValue('connections', self.connections)

    def load_connections(self):
        self.connections = self.settings.value('connections', {}, type=dict)

    def save_connection_details(self):
        with open('connection_details.json', 'w') as file:
            json.dump(self.connection_details, file)

    def load_connection_details(self):
        if os.path.exists('connection_details.json'):
            with open('connection_details.json', 'r') as file:
                self.connection_details = json.load(file)

    def load_credentials(self):
        if os.path.exists('credentials.json'):
            with open('credentials.json', 'r') as file:
                return json.load(file)
        return []

    def connect_to_broker(self, name):
        host, _ = self.connections[name]

        login_dialog = LoginDialog(self)
        if login_dialog.exec() == QDialog.Accepted:
            username, password = login_dialog.get_credentials()
            if not username or not password:
                QMessageBox.warning(self, 'Input Error', 'Please provide both username and password.')
                return

            if not self.validate_credentials(username, password):
                QMessageBox.critical(self, 'Authentication Error', 'Username or password is incorrect.')
                return

            if not self.move_correct_entry_to_top(host, username, password):
                QMessageBox.critical(self, 'Connection Error', 'Unable to find a matching entry for connection details.')
                return

            self.set_all_buttons_enabled(False)

            broker_client_path = 'C:\\Users\\Administrator\\Desktop\\bin\\broker_client_example.exe'
            login_info_file = 'C:\\Users\\Administrator\\Desktop\\bin\\login_info.txt'
            pcoip_client_path = 'C:\\Program Files (x86)\\Teradici\\PCoIP Client\\bin\\pcoip_client.exe'

            try:
                result = subprocess.run(
                    [broker_client_path, '-i', login_info_file],
                    capture_output=True, text=True, check=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW
                )
                output = result.stdout

                ip = self.extract_value(output, 'IP')
                desktop = self.extract_value(output, 'SNI')
                port = self.extract_value(output, 'PORT')
                session_id = self.extract_value(output, 'SESSIONID')
                connect_tag = self.extract_value(output, 'CONNECT_TAG')

                if not all([ip, port, session_id, desktop, connect_tag]):
                    QMessageBox.critical(self, 'Extraction Error', 'Failed to extract necessary values. Please check your broker client output.')
                    self.set_all_buttons_enabled(True)
                    return

                connection_details = {
                    'ip': ip,
                    'sni': desktop,
                    'session_id': session_id,
                    'port': port,
                    'connect_tag': connect_tag
                }
                self.connection_details[name] = connection_details
                self.save_connection_details()

                pcoip_args = [
                    pcoip_client_path,
                    '--address', ip,
                    '--port', port,
                    '--sni', desktop,
                    '--session-id', session_id,
                    '--connect-tag', connect_tag
                ]

                self.connection_thread = ConnectionThread(pcoip_args)
                self.connection_thread.connection_finished.connect(self.on_connection_finished)
                self.connection_thread.start()

                self.active_connection = name

            except subprocess.CalledProcessError as e:
                QMessageBox.critical(self, 'Execution Error', f'Error running command: {e}')
                self.set_all_buttons_enabled(True)

            except FileNotFoundError:
                QMessageBox.critical(self, 'File Error', 'The specified file was not found. Please check the file paths.')
                self.set_all_buttons_enabled(True)

            except subprocess.TimeoutExpired:
                QMessageBox.critical(self, 'Timeout Error', 'Connection attempt timed out after 10 seconds.')
                self.set_all_buttons_enabled(True)

    def validate_credentials(self, username, password):
        login_info_path = 'C:\\Users\\Administrator\\Desktop\\bin\\login_info.txt'

        if os.path.exists(login_info_path):
            with open(login_info_path, 'r') as file:
                lines = file.readlines()
                for line in lines:
                    parts = line.strip().split()
                    if len(parts) == 4:
                        _, _, saved_username, saved_password = parts
                        if saved_username == username and saved_password == password:
                            return True
        return False

    def move_correct_entry_to_top(self, host, username, password):
        login_info_path = 'C:\\Users\\Administrator\\Desktop\\bin\\login_info.txt'

        if os.path.exists(login_info_path):
            with open(login_info_path, 'r') as file:
                lines = file.readlines()
                for i, line in enumerate(lines):
                    parts = line.strip().split()
                    if len(parts) == 4:
                        saved_ip, _, saved_username, saved_password = parts
                        if saved_ip == host and saved_username == username and saved_password == password:
                            entry = lines.pop(i)
                            lines.insert(0, entry)
                            with open(login_info_path, 'w') as file:
                                file.writelines(lines)
                            return True
        return False

    def set_all_buttons_enabled(self, enabled):
        for i in range(self.connections_layout.count()):
            layout_item = self.connections_layout.itemAt(i)
            if layout_item:
                conn_frame = layout_item.widget()
                if conn_frame:
                    buttons = conn_frame.findChildren(QPushButton)
                    for button in buttons:
                        button.setEnabled(enabled)
                        if not enabled:
                            button.setStyleSheet("background-color: #cccccc; color: #666666;")
                        else:
                            button.setStyleSheet("""
                                QPushButton {
                                    background-color: #0078d7; 
                                    color: #ffffff; 
                                    border: none; 
                                    border-radius: 5px; 
                                    padding: 5px;
                                }
                                QPushButton:hover {
                                    background-color: #005bb5;
                                }
                            """)

    def on_connection_finished(self, message, success):
        self.set_all_buttons_enabled(True)

        normalized_message = (message or "").strip().lower()

        if not success and ("closed" in normalized_message or "timed out" in normalized_message):
            QMessageBox.information(self, 'Connection Status', 'Connection closed successfully.')
        elif not success:
            QMessageBox.critical(self, 'Connection Error', message)

        self.active_connection = None
        self.refresh_connections_ui()

    def check_remote(self):
        try:
            broker_client_path = 'C:\\Users\\Administrator\\Desktop\\bin\\broker_client_example.exe'
            login_info_file = 'C:\\Users\\Administrator\\Desktop\\bin\\login_info.txt'

            result = subprocess.run(
                [broker_client_path, '-i', login_info_file],
                capture_output=True, text=True, check=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW
            )
            output = result.stdout

            ip = self.extract_value(output, 'IP')
            sni = self.extract_value(output, 'SNI')

            if not ip or not sni:
                raise ValueError('Failed to retrieve current connection details. IP or SNI not found within 10 seconds.')

            network_checks = self.perform_network_checks(ip)
            self.display_check_results(ip, sni, network_checks)

        except FileNotFoundError:
            QMessageBox.critical(self, 'Check Connection', 'File not found. Please ensure the required files are in place.')

        except subprocess.CalledProcessError as e:
            QMessageBox.warning(self, 'Check Connection', f'Error during re-check: {str(e)}. Falling back to cached details.')

        except subprocess.TimeoutExpired:
            QMessageBox.critical(self, 'Timeout Error', 'Failed to find IP within 10 seconds. The operation timed out.')

        except ValueError as e:
            QMessageBox.warning(self, 'Check Connection', f'Validation Error: {str(e)}.')

        except ConnectionError as e:
            QMessageBox.critical(self, 'Check Connection', f'{str(e)}')

        except Exception as e:
            QMessageBox.critical(self, 'Check Connection', f'Unexpected error: {str(e)}')

    def perform_network_checks(self, ip):
        if not self.ping(ip):
            QMessageBox.critical(self, 'Remote Check', 'IP not reachable.')
            return {}

        results = {
            'Device connected to the network.': '✔' if self.ping(ip) else '✖ (Unable to reach network)',
            'Device connected to the internet.': '✔' if self.check_internet() else '✖ (No internet access)',
            'Connection over TCP Ports established.': '✔' if self.check_port(ip, 4172, 'tcp') else '✖ (TCP Port blocked)',
            'Connection over UDP Ports established.': '✔' if self.check_port(ip, 4172, 'udp') else '✖ (UDP Port blocked)',
            'Round Trip Time': self.calculate_rtt(ip)
        }
        return results

    def ping(self, ip):
        try:
            subprocess.check_call(['ping', '-n', '1', ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
            return True
        except subprocess.CalledProcessError:
            return False

    def check_internet(self):
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=5)
            return True
        except OSError:
            return False

    def check_port(self, ip, port, protocol):
        try:
            if protocol == 'tcp':
                with socket.create_connection((ip, port), timeout=5) as sock:
                    return True
            elif protocol == 'udp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)
                try:
                    sock.sendto(b'Test', (ip, port))
                    return True
                except (socket.timeout, socket.error):
                    return False
                finally:
                    sock.close()
        except OSError:
            return False

    def display_check_results(self, ip, sni, checks):
        result_text = f"IP Address: {ip}\nDesktop: {sni}\n\nNetwork Check Results:\n"
        for check, result in checks.items():
            result_text += f"{check}: {result}\n"

        QMessageBox.information(self, 'Network Check Results', result_text)

    def extract_value(self, text, key):
        import re
        match = re.search(fr'{key}\s*:\s*(.+)', text)
        return match.group(1).strip() if match else None

if __name__ == '__main__':
    app = QApplication(sys.argv)
    clientApp = PCoIPClientApp()
    clientApp.show()
    sys.exit(app.exec_())
