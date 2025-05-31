import json
import shutil
import subprocess
import sys
import os
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import QMessageBox, QFileDialog
import os

from fat32.main import FAT32Manager
from ui_disk import Ui_MainWindow
from fat32 import main


class ConfigViewerDialog(QtWidgets.QDialog):
    def __init__(self, config_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("FAT32 Configuration")
        self.resize(600, 400)

        layout = QtWidgets.QVBoxLayout()
        self.text_edit = QtWidgets.QPlainTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setPlainText(config_data)
        layout.addWidget(self.text_edit)

        close_btn = QtWidgets.QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)

        self.setLayout(layout)

class MyApp(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # Setup log viewers
        self.setup_log_viewers()

        # Create and start log update timer
        self.log_timer = QtCore.QTimer()
        self.log_timer.timeout.connect(self.update_logs)
        self.log_timer.start(1000)  # Update every second

        # Connect config button
        if hasattr(self.ui, 'commandLinkButton'):
            self.ui.commandLinkButton.clicked.connect(self.show_config)
        else:
            print("Warning: 'commandLinkButton' not found in UI. Config viewer won't be accessible.")

        self.ui.pushButton_20.clicked.connect(self.create_disk_ui)
        self.ui.pushButton_25.clicked.connect(self.handle_delete_disk)
        self.ui.pushButton_27.clicked.connect(self.handle_format_disk)
        self.ui.pushButton_28.clicked.connect(self.clone_disk_ui)
        self.ui.listView.clicked.connect(self.on_listview_clicked)
        self.ui.pushButton_12.clicked.connect(self.create_new_file)

        # after your existing connections:
        self.ui.pushButton_10.clicked.connect(self.save_file_changes)
        self.ui.pushButton_11.clicked.connect(self.delete_selected_entry)

        # track the last-clicked entry
        self.selected_entry_path = None
        self.selected_entry_data = None

        # Connect the new button for disk selection and file listing
        self.ui.pushButton_13.clicked.connect(self.select_disk_and_list_files)

        # Connect checkbox to update file listing when toggled
        self.ui.checkBox.stateChanged.connect(self.update_file_listing)

        # Track mounted disk path and selected disk
        self.mounted_path = None
        self.selected_disk_path = None
        self.fat_manager = main.FAT32Manager()
        self.current_file_ops = None  # Store current file operations object

        # Fix window size
        self.setFixedSize(self.size())

        # Connect dashboard buttons
        self.ui.dashboard_1.clicked.connect(lambda: self.ui.stackedWidget.setCurrentIndex(0))
        self.ui.dashboard_2.clicked.connect(lambda: self.ui.stackedWidget.setCurrentIndex(0))

        self.ui.profile_1.clicked.connect(lambda: self.ui.stackedWidget.setCurrentIndex(1))
        self.ui.profile_2.clicked.connect(lambda: self.ui.stackedWidget.setCurrentIndex(1))
        self.ui.pushButton_15.clicked.connect(lambda: self.ui.stackedWidget.setCurrentIndex(1))

        self.ui.messages_1.clicked.connect(lambda: self.ui.stackedWidget.setCurrentIndex(2))
        self.ui.messages_2.clicked.connect(lambda: self.ui.stackedWidget.setCurrentIndex(2))

        self.ui.notifications_1.clicked.connect(lambda: self.ui.stackedWidget.setCurrentIndex(3))
        self.ui.notifications_2.clicked.connect(lambda: self.ui.stackedWidget.setCurrentIndex(3))

        self.ui.settings_1.clicked.connect(lambda: self.ui.stackedWidget.setCurrentIndex(4))
        self.ui.settings_2.clicked.connect(lambda: self.ui.stackedWidget.setCurrentIndex(4))

        # File selection
        self.ui.pushButton.clicked.connect(lambda: self.browse_file(self.ui.lineEdit_7))
        self.ui.pushButton_3.clicked.connect(lambda: self.browse_file(self.ui.lineEdit_8))
        self.ui.pushButton_4.clicked.connect(lambda: self.browse_file(self.ui.lineEdit_9))

        # Folder selection
        self.ui.pushButton_5.clicked.connect(lambda: self.browse_file_save(self.ui.lineEdit_10))

        # Mount disk
        self.ui.pushButton_26.clicked.connect(self.mount_disk_from_ui)

        # Health report
        self.ui.pushButton_2.clicked.connect(self.generate_health_report)

    def setup_log_viewers(self):
        """Add QPlainTextEdit widgets to log tabs"""
        # Tab 9 - Normal log
        self.ui.tab_9.layout = QtWidgets.QVBoxLayout(self.ui.tab_9)
        self.log_viewer_normal = QtWidgets.QPlainTextEdit()
        self.log_viewer_normal.setReadOnly(True)
        self.log_viewer_normal.setStyleSheet("font-family: Consolas, monospace;")
        self.ui.tab_9.layout.addWidget(self.log_viewer_normal)
        self.ui.tab_9.setLayout(self.ui.tab_9.layout)

        # Tab 10 - Error log
        self.ui.tab_10.layout = QtWidgets.QVBoxLayout(self.ui.tab_10)
        self.log_viewer_errors = QtWidgets.QPlainTextEdit()
        self.log_viewer_errors.setReadOnly(True)
        self.log_viewer_errors.setStyleSheet("""
            font-family: Consolas, monospace;
            color: #ff0000;
        """)
        self.ui.tab_10.layout.addWidget(self.log_viewer_errors)
        self.ui.tab_10.setLayout(self.ui.tab_10.layout)

    def update_logs(self):
        """Update log viewers with latest log content"""
        # Paths to log files
        log_normal = r"C:\Users\HP\Desktop\diskui\Cyball\logs\fat32manager.log"
        log_errors = r"C:\Users\HP\Desktop\diskui\Cyball\logs\fat32manager_errors.log"

        # Update normal log
        try:
            if os.path.exists(log_normal):
                with open(log_normal, 'r') as f:
                    content = f.read()
                    self.log_viewer_normal.setPlainText(content)
                    # Scroll to end
                    cursor = self.log_viewer_normal.textCursor()
                    cursor.movePosition(QtGui.QTextCursor.End)
                    self.log_viewer_normal.setTextCursor(cursor)
        except Exception as e:
            print(f"Error updating normal log: {e}")

        # Update error log
        try:
            if os.path.exists(log_errors):
                with open(log_errors, 'r') as f:
                    content = f.read()
                    self.log_viewer_errors.setPlainText(content)
                    # Scroll to end
                    cursor = self.log_viewer_errors.textCursor()
                    cursor.movePosition(QtGui.QTextCursor.End)
                    self.log_viewer_errors.setTextCursor(cursor)
        except Exception as e:
            print(f"Error updating error log: {e}")

    def show_config(self):
        """Display fat32_config.json content in a dialog"""
        config_path = r"C:\Users\HP\Desktop\diskui\Cyball\fat32_config.json"

        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config_data = json.load(f)
                    # Format JSON for better readability
                    formatted = json.dumps(config_data, indent=4)
                    dialog = ConfigViewerDialog(formatted, self)
                    dialog.exec_()
            else:
                QMessageBox.warning(self, "Config Missing",
                                    "fat32_config.json not found at:\n" + config_path)
        except Exception as e:
            QMessageBox.critical(self, "Config Error",
                                 f"Error loading configuration:\n{str(e)}")
    def select_disk_and_list_files(self):
        """Handle pushButton_13 click - select .img file and list its contents"""
        # Open file dialog to select .img files only
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Disk Image",
            "",
            "Disk Images (*.img)"
        )

        if file_path:
            # Store the selected disk path
            self.selected_disk_path = file_path

            # Update label_6 with the disk name (including .img extension)
            disk_name = os.path.basename(file_path)
            self.ui.label_6.setText(disk_name)

            # List files in the selected disk
            self.list_disk_files()

    def list_disk_files(self):
        """List files and directories from the selected disk image"""
        if not self.selected_disk_path or not os.path.exists(self.selected_disk_path):
            QMessageBox.warning(self, "Warning", "No valid disk selected.")
            return

        try:
            # Mount the disk to access its contents
            self.current_file_ops = self.fat_manager.mount_disk(self.selected_disk_path)
            if not self.current_file_ops:
                QMessageBox.critical(self, "Error", "Failed to mount the selected disk.")
                return

            # Check if recursive listing is enabled
            recursive = self.ui.checkBox.isChecked()

            # Get file listing
            if recursive:
                items = self.get_recursive_file_list(self.current_file_ops)
            else:
                items = self.get_root_file_list(self.current_file_ops)

            # Update the listView with QStandardItemModel
            self.update_list_view(items)
            self.update_space_labels()


        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to list disk contents:\n{str(e)}")

    def get_root_file_list(self, file_ops):
        """Get files and directories in root directory only - returns list of (display_text, full_path, entry_data)"""
        try:
            # Get root directory contents
            root_entries = file_ops.list_directory("/")
            items = []

            for entry in root_entries:
                if entry['name'] not in ('.', '..'):
                    display_text = f"[{'DIR' if entry['is_directory'] else 'FILE'}] {entry['name']}"
                    full_path = '/' + entry['name'] if entry['name'] != '/' else '/'
                    items.append((display_text, full_path, entry))

            return items

        except Exception as e:
            print(f"Error getting root file list: {e}")
            return []

    def get_recursive_file_list(self, file_ops):
        """Get all files and directories recursively - returns list of (display_text, full_path, entry_data)"""
        try:
            items = []

            def traverse_directory(path, level=0):
                try:
                    entries = file_ops.list_directory(path)
                    for entry in entries:
                        if entry['name'] not in ['.', '..']:
                            indent = "  " * level  # Indent based on directory level
                            entry_type = "DIR" if entry['is_directory'] else "FILE"
                            full_path = f"{path}/{entry['name']}" if path != "/" else f"/{entry['name']}"

                            display_text = f"{indent}[{entry_type}] {entry['name']}"
                            items.append((display_text, full_path, entry))

                            # If it's a directory, traverse it recursively
                            if entry['is_directory']:
                                traverse_directory(full_path, level + 1)

                except Exception as e:
                    print(f"Error traversing directory {path}: {e}")

            traverse_directory("/")
            return items

        except Exception as e:
            print(f"Error getting recursive file list: {e}")
            return []

    def update_file_listing(self):
        """Update file listing when checkbox state changes"""
        if self.selected_disk_path:
            self.list_disk_files()

    def update_list_view(self, items):
        """Update the listView with QStandardItemModel storing full paths in Qt.UserRole"""
        model = QtGui.QStandardItemModel()

        for display_text, full_path, entry_data in items:
            item = QtGui.QStandardItem(display_text)
            # Store the full path in Qt.UserRole for later retrieval
            item.setData(full_path, QtCore.Qt.UserRole)
            # Store additional entry data if needed
            item.setData(entry_data, QtCore.Qt.UserRole + 1)
            model.appendRow(item)

        self.ui.listView.setModel(model)

        # Clear previous table and content
        self.ui.tableView.setModel(None)
        self.ui.lineEdit_11.clear()

    def update_space_labels(self):
        """Fetch total and free space from the mounted disk and show on label_43 / label_44."""
        if not self.current_file_ops:
            # No disk mounted: clear labels
            self.ui.label_43.setText("–")
            self.ui.label_44.setText("–")
            return

        try:
            # file_ops.generate_health_report() returns a dict
            report = self.current_file_ops.generate_health_report()
            total_mb = report['total_size'] / (1024 * 1024)
            free_mb  = report['free_space'] / (1024 * 1024)

            self.ui.label_43.setText(f"{total_mb:.1f} MB")
            self.ui.label_44.setText(f"{free_mb:.1f} MB")
        except Exception:
            # Fallback: clear on error
            self.ui.label_43.setText("–")
            self.ui.label_44.setText("–")


    def on_listview_clicked(self, index: QtCore.QModelIndex):
        """Handles clicks on listView, populates tableView and lineEdit_11."""
        if not self.current_file_ops:
            QMessageBox.warning(self, "Warning", "No disk is currently mounted.")
            return

        # Get the full path from the clicked item
        full_path = index.data(QtCore.Qt.UserRole)
        entry_data = index.data(QtCore.Qt.UserRole + 1)

        # store for later
        self.selected_entry_path = full_path
        self.selected_entry_data = entry_data

        if not full_path or not entry_data:
            return

        try:
            # Create table model with 4 columns
            table_model = QtGui.QStandardItemModel(0, 4)
            table_model.setHorizontalHeaderLabels(["Name", "Type", "Size", "Modified"])

            # Get file/directory information
            name = entry_data['name']
            file_type = "DIR" if entry_data['is_directory'] else "FILE"

            # For FAT32, we need to get size from the entry data
            if entry_data['is_directory']:
                size = ""  # Directories don't have a meaningful size in FAT32
            else:
                size = str(entry_data.get('size', 0))

            # For modified date, try to get from entry data or use a placeholder
            modified = entry_data.get('modified_date', 'N/A')
            if modified == 'N/A':
                modified = entry_data.get('created_date', 'N/A')

            # Create table row
            row_items = []
            for col_text in [name, file_type, size, modified]:
                item = QtGui.QStandardItem(str(col_text))
                row_items.append(item)

            table_model.appendRow(row_items)

            # Set the model to tableView
            self.ui.tableView.setModel(table_model)
            self.ui.tableView.resizeColumnsToContents()

            # Handle file content display
            if not entry_data['is_directory']:
                # Try to read file content
                try:
                    file_content = self.current_file_ops.read_file(full_path)
                    if isinstance(file_content, bytes):
                        # Try to decode as text
                        try:
                            content_text = file_content.decode('utf-8')
                        except UnicodeDecodeError:
                            # If not text, show hex representation or indicate binary
                            if len(file_content) > 1000:
                                content_text = f"<Binary file, {len(file_content)} bytes>"
                            else:
                                content_text = file_content.hex()[:500] + "..." if len(
                                    file_content.hex()) > 500 else file_content.hex()
                    else:
                        content_text = str(file_content)

                    self.ui.lineEdit_11.setText(content_text)

                except Exception as e:
                    self.ui.lineEdit_11.setText(f"<Unable to read file: {str(e)}>")
            else:
                # Clear content for directories
                self.ui.lineEdit_11.clear()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to process file information:\n{str(e)}")
            print(f"Error in on_listview_clicked: {e}")

    def save_file_changes(self):
        """Replace a file by deleting then creating it via the CLI."""
        if not self.selected_disk_path or not self.selected_entry_path:
            QMessageBox.warning(self, "Save Error", "Please select a file first.")
            return
        if self.selected_entry_data.get('is_directory'):
            QMessageBox.warning(self, "Save Error", "Cannot write into a directory.")
            return

        img = self.selected_disk_path
        virt = self.selected_entry_path
        new_text = self.ui.lineEdit_11.text()

        main_py = r"C:\Users\HP\Desktop\diskui\fat32\main.py"
        py = sys.executable

        # 1) delete-file
        cmd_del = [py, main_py, "delete-file", img, virt]
        # 2) create-file
        cmd_create = [py, main_py, "create-file", img, virt, new_text]

        try:
            # run delete
            res1 = subprocess.run(cmd_del, capture_output=True, text=True)
            if res1.returncode != 0:
                raise RuntimeError(f"Delete failed:\n{res1.stderr or res1.stdout}")

            # run create
            res2 = subprocess.run(cmd_create, capture_output=True, text=True)
            if res2.returncode != 0:
                raise RuntimeError(f"Create failed:\n{res2.stderr or res2.stdout}")

            QMessageBox.information(self, "Saved", "File updated successfully")
            self.list_disk_files()

        except Exception as e:
            QMessageBox.critical(self, "Error Saving", str(e))
        self.update_space_labels()

    def delete_selected_entry(self):
        if not self.selected_disk_path or not self.selected_entry_path:
            QMessageBox.warning(self, "Delete Error", "Please select a file or folder first.")
            return

        name = self.selected_entry_data.get('name', self.selected_entry_path)
        confirm = QMessageBox.question(
            self, "Confirm Delete", f"Really delete '{name}'?",
            QMessageBox.Yes | QMessageBox.No
        )
        if confirm != QMessageBox.Yes:
            return

        try:
            # Pass full disk path
            if self.selected_entry_data.get('is_directory'):
                success = self.fat_manager.delete_directory(
                    self.selected_disk_path,
                    self.selected_entry_path
                )
            else:
                success = self.fat_manager.delete_file(
                    self.selected_disk_path,
                    self.selected_entry_path
                )

            if success:
                QMessageBox.information(self, "Deleted", f"'{name}' deleted.")
                self.ui.tableView.setModel(None)
                self.ui.lineEdit_11.clear()
                self.list_disk_files()
            else:
                QMessageBox.critical(self, "Error", "Delete operation failed.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error deleting entry:\n{e}")

        self.update_space_labels()

    def create_new_file(self):
        """Create a brand-new file in the mounted disk."""
        # 1) Basic validations
        fname = self.ui.lineEdit_12.text().strip()
        if not fname:
            QMessageBox.warning(self, "Input Error", "Please enter a file name.")
            return

        # Ensure leading slash for virtual path
        vpath = fname if fname.startswith("/") else "/" + fname

        # Encryption?
        encrypt = self.ui.checkBox_2.isChecked()
        pwd = self.ui.lineEdit_13.text()
        if encrypt and not pwd:
            QMessageBox.warning(self, "Input Error", "Please enter a password for encryption.")
            return

        content = self.ui.textEdit.toPlainText()

        # 2) Must have a mounted disk
        if not self.selected_disk_path or not self.current_file_ops:
            QMessageBox.warning(self, "Error", "No disk mounted.")
            return

        # 3) Check for existence
        #    list root entries and see if name matches
        root = self.current_file_ops.list_directory("/")
        names = [e["name"] for e in root if e["name"] not in (".", "..")]
        if fname in names:
            resp = QMessageBox.question(
                self, "Overwrite?",
                f"'{fname}' already exists. Overwrite?",
                QMessageBox.Yes | QMessageBox.No
            )
            if resp != QMessageBox.Yes:
                return
            # delete first
            self.current_file_ops.delete_file(self.selected_disk_path, vpath)

        # 4) Build CLI command
        main_py = r"C:\Users\HP\Desktop\diskui\fat32\main.py"
        cmd = [sys.executable, main_py, "create-file",
               self.selected_disk_path,
               vpath,
               content]
        if encrypt:
            cmd += ["--encrypt", "--password", pwd]

        # 5) Run it
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode == 0:
                QMessageBox.information(self, "Created", f"'{fname}' created successfully.")
                self.list_disk_files()  # refresh view
            else:
                QMessageBox.critical(self, "Error",
                                     f"CLI error:\n{proc.stderr or proc.stdout}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create file:\n{e}")

        self.update_space_labels()

    def browse_file(self, line_edit):
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            line_edit.setText(file_path)

    def browse_folder(self):
        folder_path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder_path:
            self.ui.lineEdit_10.setText(folder_path)

    def browse_file_save(self, line_edit):
        file_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Select Target File")
        if file_path:
            line_edit.setText(file_path)

    def mount_disk_from_ui(self):
        path = self.ui.lineEdit_7.text().strip()
        if not path or not os.path.exists(path):
            QMessageBox.critical(self, "Error", "Invalid disk/path")
            return

        result = self.fat_manager.mount_disk(path)
        if result:
            self.mounted_path = path
            QMessageBox.information(self, "Success", "Disk mounted successfully!")
        else:
            self.mounted_path = None
            QMessageBox.critical(self, "Error", "Failed to mount disk. Please check the log or path.")

    def generate_health_report(self):
        if not self.mounted_path:
            QMessageBox.critical(self, "Error", "No disk has been mounted.")
            return

        file_ops = self.fat_manager.mount_disk(self.mounted_path)
        if not file_ops:
            QMessageBox.critical(self, "Error", "Failed to access disk for report.")
            return

        try:
            report = file_ops.generate_health_report()

            report_text = f"{'=' * 60}\n"
            report_text += f"HEALTH REPORT FOR: {self.mounted_path}\n"
            report_text += f"{'=' * 60}\n\n"

            report_text += "Disk Geometry:\n"
            report_text += f"  Total Size: {report['total_size'] / (1024 * 1024):.1f} MB\n"
            report_text += f"  Sector Size: {report['sector_size']} bytes\n"
            report_text += f"  Cluster Size: {report['cluster_size']} bytes\n"
            report_text += f"  Total Clusters: {report['total_clusters']:,}\n\n"

            report_text += "FAT Statistics:\n"
            report_text += f"  Free Clusters: {report['free_clusters']:,}\n"
            report_text += f"  Used Clusters: {report['used_clusters']:,}\n"
            report_text += f"  Bad Clusters: {report['bad_clusters']:,}\n"
            report_text += f"  Free Space: {report['free_space'] / (1024 * 1024):.1f} MB\n\n"

            report_text += "Slack Space Analysis:\n"
            report_text += f"  Total Slack Space: {report['total_slack'] / 1024:.1f} KB\n"
            report_text += f"  Average Slack per File: {report['avg_slack_per_file']:.1f} bytes\n\n"

            report_text += "File System Health:\n"
            report_text += f"  Cross-linked Clusters: {report['cross_linked_clusters']}\n"
            report_text += f"  Lost Chains: {report['lost_chains']}\n"
            report_text += f"  Integrity Status: {report['integrity_status']}\n\n"

            if report['recommendations']:
                report_text += "Recommendations:\n"
                for rec in report['recommendations']:
                    report_text += f"  • {rec}\n"

            # Show in popup dialog
            self.show_report_dialog(report_text)

        except Exception as e:
            self.fat_manager.logger.error(f"Failed to generate health report: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to generate health report.\n{str(e)}")

    def show_report_dialog(self, report_text):
        dialog = QtWidgets.QDialog(self)
        dialog.setWindowTitle("Health Report")
        dialog.resize(600, 500)

        layout = QtWidgets.QVBoxLayout(dialog)
        text_edit = QtWidgets.QTextEdit(dialog)
        text_edit.setReadOnly(True)
        text_edit.setText(report_text)

        layout.addWidget(text_edit)
        dialog.setLayout(layout)
        dialog.exec_()

    def create_disk_ui(self):
        disk_name = self.ui.lineEdit_2.text().strip()
        if not disk_name:
            disk_name = "virtual_disk.img"
        elif not disk_name.endswith(".img"):
            disk_name += ".img"

        # Full path to main.py
        main_py_path = r"C:\Users\HP\Desktop\diskui\fat32\main.py"

        # Construct command
        # You might want to pass size & cluster if main.py supports it
        cmd = [sys.executable, main_py_path, "create-disk", disk_name]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                QMessageBox.information(self, "Success", f"Disk created successfully:\n{disk_name}")
            else:
                QMessageBox.critical(self, "Error", f"Disk creation failed:\n{result.stderr}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to run disk creation:\n{str(e)}")

    def handle_delete_disk(self):
        disk_name = self.ui.lineEdit_6.text().strip()  # Fixed: use self.ui.lineEdit_6

        if not disk_name:
            QMessageBox.warning(self, "Input Error", "Please enter a disk name.")
            return

        # Add .img extension if missing
        if not disk_name.endswith(".img"):
            disk_name += ".img"

        # First try to delete in the current working directory
        disk_path = os.path.join(os.getcwd(), disk_name)
        if os.path.exists(disk_path):
            try:
                os.remove(disk_path)
                QMessageBox.information(self, "Success", f"Disk deleted successfully: {disk_name}")
                return
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete disk: {str(e)}")
                return

        # Disk not found - ask user if they want to search elsewhere
        choice = QMessageBox.question(
            self,
            "Disk Not Found",
            f"{disk_name} not found in current directory.\nDo you want to search for it in another location?",
            QMessageBox.Yes | QMessageBox.No
        )

        if choice == QMessageBox.Yes:
            # Open file dialog to find .img file
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select Disk Image to Delete",
                "",
                "Disk Images (*.img)"
            )

            if file_path:
                try:
                    os.remove(file_path)
                    QMessageBox.information(self, "Success",
                                            f"Disk deleted successfully: {os.path.basename(file_path)}")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to delete disk: {str(e)}")

    def handle_format_disk(self):
        disk_name = self.ui.lineEdit_8.text().strip()

        if not disk_name:
            QMessageBox.warning(self, "Input Error", "Please enter a disk name to format.")
            return

        if not disk_name.endswith(".img"):
            disk_name += ".img"

        # Confirm formatting
        confirm = QMessageBox.question(
            self,
            "Confirm Format",
            f"Are you sure you want to format this disk?\nAll data will be lost: {disk_name}",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm != QMessageBox.Yes:
            return

        # Full path to main.py
        main_py_path = r"C:\Users\HP\Desktop\diskui\fat32\main.py"

        # Construct command (ensure 'format-disk' is handled in your CLI)
        cmd = [sys.executable, main_py_path, "format-disk", disk_name]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                QMessageBox.information(self, "Success", f"Disk formatted successfully:\n{disk_name}")
            else:
                QMessageBox.critical(self, "Error", f"Disk formatting failed:\n{result.stderr}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to format disk:\n{str(e)}")

    def clone_disk_ui(self):
        source_path = self.ui.lineEdit_9.text().strip()
        target_path = self.ui.lineEdit_10.text().strip()

        if not source_path or not os.path.exists(source_path):
            QMessageBox.critical(self, "Error", "Invalid or missing source path.")
            return

        if not target_path or os.path.isdir(target_path):
            QMessageBox.critical(self, "Error", "Invalid or missing target file path.")
            return

        try:
            # Assuming you have initialized FAT32Manager as self.fat_manager
            result = self.fat_manager.clone_disk(source_path, target_path)

            if result:
                QMessageBox.information(self, "Success", "Disk cloned successfully.")
            else:
                QMessageBox.critical(self, "Failure", "Disk cloning failed. Check logs.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred:\n{str(e)}")

        def select_disk_and_list_files(self):
            """Handle pushButton_13 click - select .img file and list its contents"""
            # Open file dialog to select .img files only
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select Disk Image",
                "",
                "Disk Images (*.img)"
            )

            if file_path:
                # Store the selected disk path
                self.selected_disk_path = file_path

                # Update label_6 with the disk name (including .img extension)
                disk_name = os.path.basename(file_path)
                self.ui.label_6.setText(disk_name)

                # List files in the selected disk
                self.list_disk_files()


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MyApp()
    window.show()
    sys.exit(app.exec_())