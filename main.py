"""
VaultApp
Version 0.1.0

Author: Malaka D.Gunawardana.

Release Notes:
- Version 1.0.0 (Initial Release) (2023/11/25)

For Updates and Contributions:
    Visit the GitHub repository:
    - https://github.com/sdmdg/vaultapp

Report issues or contribute to the development. :)
"""

import sys, os, io, secrets, datetime
import cv2
import numpy as np
from PyQt5 import uic
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QFileDialog, QLineEdit, QDialog, QCheckBox
from PyQt5.QtGui import QPixmap, QImage, QIcon
from PyQt5.QtCore import Qt, QByteArray
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

# Main Window

class VaultApp(QMainWindow):
    def __init__(self):
        super(VaultApp, self).__init__()
        # Setup UI
        uic.loadUi(resource_path('ui/window_main.ui'), self)
        self.setWindowTitle("Vault " + App_version)
        self.setWindowIcon(QIcon(resource_path("./ui/icon.png")))
        self.btn_refresh.clicked.connect(lambda: self.SyS_refresh(ask_password=False))
        self.btn_import_files.clicked.connect(self.import_files)
        self.btn_about.clicked.connect(self.f_btn_about)
        self.btn_delete_files.clicked.connect(self.f_btn_delete_files)
        self.load_files()

    def load_files(self, ask_password=True, refresh=False):
        global directory_path_data, directory_path, directory_path_export, password, config_path
        global _encfileNames, _orfileNames, _selected_items

        config_path = os.path.join(directory_path, "data", "config.bin")
        _selected_items = []
        self.btn_delete_files.setEnabled(False)

        # Scan data folder and get a list of image files in the directory
        _files = [f for f in os.listdir(directory_path_data) if f.lower().endswith(('.enc'))]

        # Input password
        if ask_password:
            if os.path.exists(config_path): msg="Enter your password :"
            else: msg="Create a new password :"
            custom_input_dialog = SyS_InputDialog(title="Input Password", msg=msg, ispassword=True)
            result = custom_input_dialog.exec_()
            if result == QDialog.Accepted:
                if custom_input_dialog.input.text() != "":
                    password = custom_input_dialog.input.text()
                else:exit()
            else:exit()

        self.show()
        
        # Get orginal file names
        _encfileNames, _orfileNames = self.SyS_load_config()
        
        if first_run:
            custom_input_dialog = SyS_InfoDialog(title="Welcome", msg="  To remove this vault, please proceed by deleting\n  the associated data folder.").exec_()
            self.f_btn_about()

        # UI
        if not refresh: self.btn_decrypt_files.clicked.connect(lambda: self.export_files(_files=[], ask_permission=True, all_files=True))
        self.progress_bar.setVisible(True)

        # Clear existing widgets
        for i in reversed(range(self.image_grid_layout.count())):
            self.image_grid_layout.itemAt(i).widget().setParent(None)

        # Process files
        row,col,progress = 1,0,0
        if len(_files) != 0:
            for _file in _files:
                try: 
                    # Get file type and id
                    id = _encfileNames.index(_file)
                    _file_ext = _orfileNames[id].split(".")[-1]
                    _orfilename = _orfileNames[id]
                except ValueError:
                    # Exception : Encrypted file found at data folder but not present in the database
                    _file_ext = "file"
                    _orfilename = "Database Error"

                # UI
                self.progress_bar.setValue(progress)
                progress += int(100/len(_files))

                # Create a QLabel for each file
                image_label = QLabel(self)
                image_label.setAlignment(Qt.AlignCenter)

                # Get file path and type
                file_path = os.path.join(directory_path_data, _file)
                _file_type = self.SyS_filetype(_file_ext).lower()
                if (_file_type == "image") or (_file_type == "video"):
                    # Load and display the image in the QLabel
                    try:
                        data = self.decrypt_data(file_path+".dat", None, password, False)
                        qimage = QImage.fromData(QByteArray(data))
                        # Convert QImage to QPixmap
                        pixmap = QPixmap.fromImage(qimage)
                    except:
                        # Exception : Encrypted image file found at database but cannot read data thumbnail
                        pixmap = QPixmap(resource_path("./ui/error.png"))
                else:
                    # UI
                    if _orfilename == "Database Error":pixmap = QPixmap(resource_path("./ui/error.png"))
                    else:pixmap = QPixmap(resource_path("./ui/other.png"))

                # Fix width and height
                if pixmap.width() > pixmap.height():pixmap = pixmap.scaledToWidth(200, Qt.SmoothTransformation)
                else:pixmap = pixmap.scaledToHeight(200, Qt.SmoothTransformation)

                # Image label
                image_label.setPixmap(pixmap)
                image_label.setMinimumHeight(200)
                image_label.setStyleSheet("QLabel{background-color: rgb(25, 25, 25);border-radius: 8px;}")

                # File name
                name_label = QLabel(self)
                name_label.setAlignment(Qt.AlignmentFlag.AlignBottom)  # Align Bottom

                # Prepare the name label text
                if len(_orfilename) > 25: text_name_label = _orfilename[:15] + "...." + _orfilename.split(".")[0][-5:] + "." + _file_ext
                else: text_name_label = _orfilename
                name_label.setText("      " + text_name_label)
                name_label.setStyleSheet("""QLabel{color: rgb(200, 200, 200);
                                            background-color: qlineargradient(spread:pad, x1:1, y1:0, x2:1, y2:1, stop:0 rgba(255, 255, 255, 0), stop:0.823864 rgba(41, 41, 41, 0), stop:1 rgba(0, 0, 0, 255));}""")
                name_label.setMinimumHeight(200)
                name_label.setMinimumWidth(200)
                name_label.setToolTip("Open : " + str(_orfilename))

                # Checkbox
                image_chkbox = QCheckBox()
                image_chkbox.setStyleSheet("""background-color: rgba(0, 0, 0, 0);""")
                image_chkbox.setText("")

                # Connect the image label to the correct method
                name_label.mousePressEvent = lambda event, path=file_path, file=_file, name=_orfilename, type=_file_type: self.SyS_preview_window(path, file, name, type)
                image_chkbox.stateChanged.connect(lambda state, path=file_path, file=_file, name=_orfilename, :  self.f_checkbox_changed(path, file, name))

                # Add elements to the grid layout
                self.image_grid_layout.addWidget(image_label, row, col)
                self.image_grid_layout.addWidget(name_label, row, col)
                self.image_grid_layout.addWidget(image_chkbox, row, col, alignment=Qt.AlignmentFlag.AlignBottom)
                col += 1
                if col == 4:
                    col = 0
                    row += 1
        else:
            pass
        # Fix grid errors for low content
        if len(_files) <= 12:
            for i in range(12-len(_files)):
                dummy_label = QLabel(self)
                dummy_label.setMinimumHeight(200)
                dummy_label.setMinimumWidth(200)
                dummy_label.setStyleSheet("""background-color: rgba(0, 0, 0, 0);""")
                self.image_grid_layout.addWidget(dummy_label, row, col)
                col += 1
                if col == 4:
                    col = 0
                    row += 1
        # UI
        self.progress_bar.setVisible(False)
    
    def f_btn_delete_files(self):
        # function of btn_delete_files
        self.SyS_delete_files(_selected_items, ask_permission=True)

    def f_btn_about(self):
        # function of btn_about
        dialog = SyS_AboutDialog()
        _ = dialog.exec_()
        del dialog, _

    def f_checkbox_changed(self, path, file, name):
        # Handle selected files
        if file not in _selected_items:_selected_items.append(file)
        else:_selected_items.remove(file)
        if len(_selected_items) != 0: self.btn_delete_files.setEnabled(True)
        else: self.btn_delete_files.setEnabled(False)

    def SyS_preview_window(self, path, file, name, type):
        # Display the selected image in a new window
        self.preview_window = uic.loadUi(resource_path('ui/window_preview.ui'))
        self.preview_window.setWindowTitle("Vault " + App_version + " : " + name)
        self.preview_window.setWindowIcon(QIcon(resource_path("./ui/icon.png")))

        # Check the file catagory
        if (type == "image"):
            try:
                # Decrypt image data
                data = self.decrypt_data(path, None, password, False, progressbar=True)
                nparr = np.frombuffer(data, np.uint8)
                image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                image_rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
                h, w, ch = image_rgb.shape
                bytes_per_line = ch * w
                q_image = QImage(image_rgb.data, w, h, bytes_per_line, QImage.Format_RGB888)
                # Convert QImage to QPixmap
                pixmap = QPixmap.fromImage(q_image)
                self.preview_window.lb_dimensions_2.setText(": " + str(pixmap.width()) + " X "+ str(pixmap.height()))
                # Fix width and height
                if pixmap.width() > pixmap.height():pixmap = pixmap.scaledToWidth(800, Qt.SmoothTransformation)
                else:pixmap = pixmap.scaledToHeight(800, Qt.SmoothTransformation)
            except:
                # Exception : Encrypted image file found at data folder but cannot read
                pixmap = QPixmap(resource_path("./ui/error.png"))
        elif (type == "video"):
            try:
                # Decrypt image data
                data = self.decrypt_data(path+".dat", None, password, False, progressbar=True)
                nparr = np.frombuffer(data, np.uint8)
                image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                image_rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
                h, w, ch = image_rgb.shape
                bytes_per_line = ch * w
                q_image = QImage(image_rgb.data, w, h, bytes_per_line, QImage.Format_RGB888)
                # Convert QImage to QPixmap
                pixmap = QPixmap.fromImage(q_image)
                self.preview_window.lb_dimensions_2.setText(": " + str(pixmap.width()) + " X "+ str(pixmap.height()))
                if pixmap.width() > pixmap.height():pixmap = pixmap.scaledToWidth(800, Qt.SmoothTransformation)
                else:pixmap = pixmap.scaledToHeight(800, Qt.SmoothTransformation)
            except:
                # Exception : Encrypted image file found at data folder but cannot read thumbnail file
                pixmap = QPixmap(resource_path("./ui/error.png"))
        else:
            pixmap = QPixmap(resource_path("./ui/other.png"))
            self.preview_window.lb_dimensions_2.setText(": Unavailable")
        
        # UI
        self.preview_window.setGeometry(300, 100, pixmap.width()+60+230, (pixmap.height()+60))
        self.preview_window.image_label.setPixmap(pixmap)
        self.preview_window.image_label.setGeometry(30, 30, pixmap.width(), pixmap.height())
        self.preview_window.infoBox.setGeometry(pixmap.width()+60, 30, 200, 150)
        self.preview_window.btn_decrypt.setGeometry(pixmap.width()+90, 190, 70, 23)
        self.preview_window.btn_delete.setGeometry(pixmap.width()+170, 190, 60, 23)
        # self.preview_window.btn_play.setGeometry(pixmap.width()+130, 220, 60, 23)
        # if type == "video": self.preview_window.btn_play.setEnabled(True)
        self.preview_window.lb_name_2.setText(": " + name)
        self.preview_window.lb_type_2.setText(": " + name.split(".")[-1] + " / " +  type.title())
        self.preview_window.lb_date_2.setText(": " + str(datetime.datetime.fromtimestamp(os.path.getctime(path)).strftime("%Y-%m-%d")))
        self.preview_window.lb_size_2.setText(": " + str(os.path.getsize(path)/(1024*1024))[:6] + " MB")

        self.preview_window.btn_decrypt.clicked.connect(lambda: self.export_files([file]))
        self.preview_window.btn_delete.clicked.connect(lambda: self.SyS_delete_files([file], ask_permission=True))
        self.preview_window.show()

    def import_files(self):
        global config_data
        options = QFileDialog.Options()
        files, _ = QFileDialog.getOpenFileNames(self, "Select file(s)", "", "All Files (*);;Image Files (*.png *.jpg *.jpeg *.bmp);;Video Files (*.mp4 *.mkv *.webm *.mov)", options=options)
        if not files:pass
        else:
            self.progress_bar.setVisible(True)
            progress = 0
            for file in files:
                # Prepare configuration data
                orginal_file_name = os.path.basename(file)
                file_ext = file.split(".")[-1]
                file_type = self.SyS_filetype(file.split(".")[-1])
                
                # Generate secure file names
                while True:
                    # Fix same name
                    encrypted_file_name = secrets.token_urlsafe(16) + ".enc"
                    if encrypted_file_name not in _encfileNames:break
                i = 0
                tmp = "".join(orginal_file_name.split(".")[:-1])
                while True:
                    i += 1
                    if orginal_file_name in _orfileNames: orginal_file_name = tmp + "_" + str(i) + "." + file_ext
                    else: break
                del i, tmp

                # Update config
                config_data.append(encrypted_file_name + "<?/?>" + orginal_file_name)

                # UI
                self.progress_bar.setValue(progress)
                progress += int(100/len(files))

                # Module : Encrypt file
                try:
                    self.encrypt_data(file, (os.path.join(os.getcwd(), "data", encrypted_file_name)), password, progressbar=False)
                except:
                    dialog = SyS_InfoDialog(title="Error !!!", msg="  Encryption failed.\n")
                    _ = dialog.exec_()
                
                # Try to generate a thumbnail for images and videos
                try:
                    if file_type == "image":
                        frame = cv2.imread(file)
                        h, w, ch = frame.shape
                        ratio = w/h
                        if w > h:
                            w = 400
                            h = int(w/ratio)
                        else:
                            h = 400
                            w = int(h*ratio)
                        resized_image = cv2.resize(frame, (w, h))
                        thumbnail_bytes = cv2.imencode('.jpg', resized_image)[1].tobytes()
                        png_bytesio = io.BytesIO(bytes(thumbnail_bytes))
                        png_bytesio.seek(0)
                        self.encrypt_data(None, (os.path.join(os.getcwd(), "data", (encrypted_file_name + ".dat"))), password, file=False, data=png_bytesio)

                    elif file_type == "video":
                        cap = cv2.VideoCapture(file)
                        cap.set(cv2.CAP_PROP_POS_FRAMES, int(cap.get(cv2.CAP_PROP_FRAME_COUNT)/4))
                        ret, frame = cap.read()
                        if ret:
                            thumbnail_bytes = cv2.imencode('.jpg', frame)[1].tobytes()
                            png_bytesio = io.BytesIO(bytes(thumbnail_bytes))
                        cap.release()
                        png_bytesio.seek(0)
                        self.encrypt_data(None, (os.path.join(os.getcwd(), "data", (encrypted_file_name + ".dat"))), password, file=False, data=png_bytesio)
                        del png_bytesio
                except:
                    dialog = SyS_InfoDialog(title="Warning !!!", msg="  Encryption complete.\n  " + orginal_file_name + " is a " + file_type + ".\n  But unable to generate a thumbnail.")
                    _ = dialog.exec_()

            # UI
            self.progress_bar.setVisible(False)

            # Save configuration file
            data = str(password) + "<?n?>" + "<?n?>".join(config_data)
            config_file = io.BytesIO(bytes(data, 'utf-8'))
            self.encrypt_data(None, config_path, password, file=False, data=config_file)
            del data, config_file

            # UI
            self.SyS_refresh(ask_password=False)

    def export_files(self, _files, ask_permission=True, all_files=False):
        global _encfileNames, _orfileNames

        # Export checked files
        if all_files:
            _files = [f for f in os.listdir(directory_path_data) if f.lower().endswith(('.enc'))]

        # Export all files
        if len(_files) != 0:
            # UI
            if ask_permission:
                dialog = SyS_MsgBoxDialog(title="Warning !!!", msg="You're going to decrypt " + str(len(_files)) + " file(s) from this vault.\nAre you sure?")
                result = dialog.exec_()
                if result == QDialog.Accepted:
                    self.export_files(_files, ask_permission=False)
                else: pass
            else:
                progress = 0
                self.progress_bar.setVisible(True)
                for _file in _files:    
                    # get file type and id
                    try: 
                        _orfilename = _orfileNames[_encfileNames.index(_file)]
                    except ValueError:
                        # Exception : Export files that doesn't in database
                        _orfilename = "file.extension"

                    # UI
                    self.progress_bar.setValue(progress)
                    progress += int(100/len(_files))

                    # Path
                    file_path = os.path.join(directory_path_data, _file)
                    outfile_path = os.path.join(directory_path_export, _orfilename)

                    # Module : Decrypt file
                    data = self.decrypt_data(file_path, outfile_path, password, True)
                    del data
                
                # UI
                self.progress_bar.setVisible(False)
                dialog = SyS_MsgBoxDialog(title="Success", msg="Decryption complete, Check the export folder.\nDo you want to delete this file(s) from Vault?", clr_btn_yes=True)
                result = dialog.exec_()
                if result == QDialog.Accepted:
                    self.SyS_delete_files(_files, ask_permission=False)
                else:
                    pass
        return


    # System

    def SyS_filetype(self, ext=""):
        # Common file types
        if ext.lower() in ("jpg,png,bmp,jpeg"): return "image"
        elif ext.lower() in ("mp4,avi,mkv"): return "video"
        elif ext.lower() in ("exe,dll,py"): return "Application"
        elif ext.lower() in ("rar,zip,7zip"): return "Compressed"
        elif ext.lower() in ("mp3,ogg,wav"): return "Audio"
        elif ext.lower() in ("doc,docx,pdf,txt,ppt,xls,ppt,csv"): return "Document"
        elif ext.lower() in ("html,mhtml,css"): return "WebPage"
        else: return "other"

    def SyS_chkdirs(self, *paths):
        # Check dirs
        for path in paths:
            if not os.path.exists(path): os.mkdir(str(path))
            else: return

    def SyS_load_config(self):
        global config_data, first_run
        
        first_run = False
        # Generate config for the first time
        if not os.path.exists(config_path):
            config_data = str(password)
            config_file = io.BytesIO(bytes(config_data, 'utf-8'))
            # Module : Encrypt data to config file
            self.encrypt_data(None, config_path, password, file=False, data=config_file)
            first_run = True

        # Module : Decrypt config file and process data
        try:
            config_data = self.decrypt_data(config_path, None, password, save=False)
            config_data = config_data.decode()
            config_data = config_data.split("<?n?>")

            config_data.pop(0)
            _encfilenames = []
            _orfileNames = []
            for entry in config_data:
                try:
                    tmp = entry.split("<?/?>")
                    _encfilenames.append(tmp[0])
                    _orfileNames.append(tmp[1])
                    del tmp
                except:pass
            return _encfilenames, _orfileNames
        except:
            # Exception : Unable to read config file
            # UI
            dialog = SyS_InfoDialog(title="Error !", msg="  Incorrect password.\n  The app will exit now.")
            result = dialog.exec_()
            if result == QDialog.Accepted:exit()

    def SyS_delete_files(self, _files=[], ask_permission=True):
        global config_data
        if ask_permission:
            # UI
            dialog = SyS_MsgBoxDialog(title="Warning !!!", msg="You're going to delete " + str(len(_files)) + " file(s) from this vault.\nAre you sure?", clr_btn_yes=True)
            result = dialog.exec_()
            if result == QDialog.Accepted:
                self.SyS_delete_files(_files, ask_permission=False)
            else: return
        else:
            for _file in _files:
                try:
                    os.remove(os.path.join(directory_path_data, _file))
                    try:os.remove(os.path.join(directory_path_data, _file+".dat"))
                    except:pass
                    for id, entry in enumerate(config_data):
                        if _file in entry:
                            # Remove file from database and save
                            config_data.pop(id)
                            if len(config_data) !=0 : data = str(password) + "<?n?>" + "<?n?>".join(config_data)
                            else: data = str(password)
                            config_file = io.BytesIO(bytes(data, 'utf-8'))
                            # Module : Encrypt config file
                            self.encrypt_data(None, config_path, password, file=False, data=config_file)
                            del data, config_file
                except:return
            # UI
            self.SyS_refresh(ask_password=False)

    def SyS_refresh(self, ask_password=True):
        # UI
        try:self.preview_window.close()
        except:pass
        try:SyS_MsgBoxDialog.close()
        except:pass
        self.progress_bar.setVisible(True)
        # Reload files
        self.load_files(ask_password, refresh=True)


    # Cryptography

    def derive_key(self, password, salt, length=32):
        # Module
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,
            salt=salt,
            length=length,
            backend=default_backend()
        )
        return kdf.derive(password)

    def encrypt_data(self, input_file, output_file, password, file=True, progressbar=False, data=""):
        # Module
        if file:
            if not os.path.exists(input_file): return
        
        # Generate a random key using random salt
        salt = os.urandom(16)
        key = self.derive_key(password.encode('utf-8'), salt)
        # Generate a random (IV)
        content_iv = os.urandom(16)

        # Create an AES cipher object
        content_cipher = Cipher(algorithms.AES(key), modes.CFB(content_iv), backend=default_backend())
        content_encryptor = content_cipher.encryptor()

        if file:
            # If input is a file
            # Calc.s for progress
            file_size = os.stat(input_file).st_size
            val = 4096*100/file_size
            progress = 0
            # UI
            if progressbar:self.progress_bar.setVisible(True)

            with open(input_file, 'rb') as infile:
                # Write the salt and IV
                with open(output_file, 'wb') as outfile:
                    outfile.write(salt)
                    outfile.write(content_iv)
                    # Encrypt the file content and write
                    for chunk in iter(lambda: infile.read(4096), b''):
                        encrypted_chunk = content_encryptor.update(chunk)
                        outfile.write(encrypted_chunk)
                        # UI
                        if progressbar:
                            progress += val
                            self.progress_bar.setValue(int(progress))
                    # Finalize
                    outfile.write(content_encryptor.finalize())
                    if progressbar:self.progress_bar.setVisible(False)
        else:
            # If input is data
            with open(output_file, 'wb') as outfile:
                outfile.write(salt)
                outfile.write(content_iv)
                # Encrypt the file content and write
                for chunk in iter(lambda: data.read(4096), b''):
                    encrypted_chunk = content_encryptor.update(chunk)
                    outfile.write(encrypted_chunk)
                # Finalize
                outfile.write(content_encryptor.finalize())

    def decrypt_data(self, input_file, output_file, password, save, progressbar=False):
        if not os.path.exists(input_file):
            return
        
        with open(input_file, 'rb') as infile:
            # Read the salt and IV
            salt = infile.read(16)
            content_iv = infile.read(16)

            # Derive the key
            key = self.derive_key(password.encode('utf-8'), salt)

            # Create an AES cipher
            content_cipher = Cipher(algorithms.AES(key), modes.CFB(content_iv), backend=default_backend())
            content_decryptor = content_cipher.decryptor()

            # Calc.s for progress
            file_size = os.stat(input_file).st_size
            val = 4096*100/file_size
            progress = 0
            if progressbar:self.progress_bar.setVisible(True)
            
            if save:
                # If output is a file
                with open(output_file, 'wb') as outfile:
                # Decrypt the file content and write
                    for chunk in iter(lambda: infile.read(4096), b''):
                        decrypted_chunk = content_decryptor.update(chunk)
                        outfile.write(decrypted_chunk)
                        # UI
                        if progressbar:
                            progress += val
                            self.progress_bar.setValue(int(progress))
                    # Finalize
                    outfile.write(content_decryptor.finalize())
                if progressbar:self.progress_bar.setVisible(False)
            else:
                # If output is data
                chunks = []
                for chunk in iter(lambda: infile.read(4096), b''):
                    decrypted_chunk = content_decryptor.update(chunk)
                    chunks.append(decrypted_chunk)
                    # UI
                    if progressbar:
                        progress += val
                        self.progress_bar.setValue(int(progress))
                data = b''.join(chunks)
                del chunks
                # UI
                if progressbar:self.progress_bar.setVisible(False)
                return data


# System Dialogs

class SyS_InputDialog(QDialog):   
    def __init__(self, parent=None, title="title", msg="msg", ispassword=False):
        super(SyS_InputDialog, self).__init__(parent)
        # Display the password window
        self = uic.loadUi(resource_path('ui/dlg_input.ui'), self)
        self.setWindowModality(Qt.ApplicationModal)
        self.setWindowTitle(title)
        self.setWindowIcon(QIcon(resource_path("./ui/icon.png")))
        self.text.setText(msg)
        if ispassword:
            self.input.setEchoMode(QLineEdit.Password)
        self.btn_ok.clicked.connect(self.accept)
        self.btn_ok.setDefault(True)
        self.btn_cancel.clicked.connect(self.reject)
        self.show()

class SyS_MsgBoxDialog(QDialog):   
    def __init__(self, parent=None, title="title", msg="msg", clr_btn_yes=False, clr_btn_no=False, btn_no_default=True, btn_yes_default=False):
        super(SyS_MsgBoxDialog, self).__init__(parent)
        # Display the msg window
        self = uic.loadUi(resource_path('ui/dlg_msg.ui'), self)
        self.setWindowModality(Qt.ApplicationModal)
        self.setWindowTitle(title)
        self.setWindowIcon(QIcon(resource_path("./ui/icon.png")))
        style = """ QPushButton {
                    background-color:rgb(40, 40, 40);
                    color: rgb(200, 0, 10);
                    border: 2px solid rgb(200, 0, 10);
                    border-radius: 10px;
                    padding: 1px;
                    }
                    QPushButton:hover {
                    background-color:rgb(190, 0, 10);
                    color: rgb(200, 200, 200);
                    border: 1px solid rgb(190, 0, 10);
                    }
                    QPushButton:pressed {
                    background-color:rgb(170, 0, 10);
                    color: rgb(200, 200, 200);
                    border: 1px solid rgb(170, 0, 10);
                    }"""
        if clr_btn_yes: self.btn_yes.setStyleSheet(style)
        if clr_btn_no: self.btn_no.setStyleSheet(style)
        self.text.setText(msg)
        self.btn_yes.clicked.connect(self.accept)
        self.btn_no.clicked.connect(self.reject)
        self.btn_no.setDefault(btn_no_default)
        self.btn_yes.setDefault(btn_yes_default)
        self.show()

class SyS_InfoDialog(QDialog):   
    def __init__(self, parent=None, title="title", msg="msg", ispassword=False):
        super(SyS_InfoDialog, self).__init__(parent)
        # Display simple msg window
        self = uic.loadUi(resource_path('ui/dlg_info.ui'), self)
        self.setWindowModality(Qt.ApplicationModal)
        self.setWindowTitle(title)
        self.setWindowIcon(QIcon(resource_path("./ui/icon.png")))
        self.text.setText(msg)
        if ispassword:
            self.input.setEchoMode(QLineEdit.Password)
        self.btn_ok.clicked.connect(self.accept)
        self.btn_ok.setDefault(True)
        self.show()

class SyS_AboutDialog(QDialog):   
    def __init__(self, parent=None):
        super(SyS_AboutDialog, self).__init__(parent)
        # Display the about window
        self = uic.loadUi(resource_path('ui/dlg_about.ui'), self)
        self.setWindowModality(Qt.ApplicationModal)
        self.setWindowTitle("About")
        self.setWindowIcon(QIcon(resource_path("./ui/icon.png")))
        self.dummy_3.setText(''.join(chr(ord(char) - 1) for char in "Efwfmpqfe!cz;!Nbmblb!E/Hvobxbsebob/"))
        self.lbl_name_and_version.setText("Name : Vault\nVersion : " + App_version)
        pixmap = QPixmap(resource_path("./ui/icon.png"))
        pixmap = pixmap.scaledToWidth(200, Qt.SmoothTransformation)
        self.icon.setPixmap(pixmap)
        self.btn_ok.clicked.connect(self.accept)
        self.btn_ok.setDefault(True)
        self.show()


# Main

if __name__ == '__main__':
    app = QApplication(sys.argv)
    QApplication

    # Check for directories and fix
    directory_path = os.getcwd()
    directory_path_data = os.path.join(directory_path, "data")
    directory_path_export = os.path.join(directory_path, "export")
    VaultApp.SyS_chkdirs(None, directory_path_data, directory_path_export)

    # INFO
    App_version = "0.1.0"
    VaultApp()
    sys.exit(app.exec_())