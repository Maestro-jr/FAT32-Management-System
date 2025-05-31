#!/usr/bin/env python3
"""
Main Window UI for FAT32 Virtual Disk Management System
Modern, responsive PyQt5 interface
"""

import sys
import os
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from pathlib import Path
import threading
from datetime import datetime

# Import our main manager and dialog classes
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from main import FAT32Manager
from ui.dialogs import *
from ui.widgets import *


class MainWindow(QMainWindow):
    """Main application window with modern design"""
    
    def __init__(self):
        super().__init__()
        self.fat32_manager = FAT32Manager()
        self.current_file_ops = None
        self.current_disk_path = None
        
        # Apply modern dark theme
        self.setStyleSheet(self.get_modern_stylesheet())
        
        self.init_ui()
        self.setup_connections()
        self.refresh_disk_list()
        
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("FAT32 Virtual Disk Manager")
        self.setGeometry(100, 100, 1400, 900)
        self.setMinimumSize(1200, 800)
        
        # Set window icon
        self.setWindowIcon(QIcon(self.get_icon_path('disc')))
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main horizontal splitter
        self.main_splitter = QSplitter(Qt.Horizontal)
        central_widget.setLayout(QHBoxLayout())
        central_widget.layout().addWidget(self.main_splitter)
        central_widget.layout().setContentsMargins(0, 0, 0, 0)
        
        # Setup UI components
        self.setup_menu_bar()
        self.setup_toolbar()
        self.setup_left_panel()
        self.setup_right_panel()
        self.setup_status_bar()
        
        # Set splitter proportions
        self.main_splitter.setSizes([350, 1050])
        self.main_splitter.setChildrenCollapsible(False)
        
    def setup_menu_bar(self):
        """Create menu bar with modern styling"""
        menubar = self.menuBar()
        
        # File Menu
        file_menu = menubar.addMenu('&File')
        
        new_disk_action = QAction(QIcon(self.get_icon_path('disc')), 'New Disk...', self)
        new_disk_action.setShortcut('Ctrl+N')
        new_disk_action.triggered.connect(self.new_disk_dialog)
        file_menu.addAction(new_disk_action)
        
        open_disk_action = QAction(QIcon(self.get_icon_path('folder-open')), 'Open Disk...', self)
        open_disk_action.setShortcut('Ctrl+O')
        open_disk_action.triggered.connect(self.open_disk_dialog)
        file_menu.addAction(open_disk_action)
        
        clone_disk_action = QAction(QIcon(self.get_icon_path('copy')), 'Clone Disk...', self)
        clone_disk_action.triggered.connect(self.clone_disk_dialog)
        file_menu.addAction(clone_disk_action)
        
        file_menu.addSeparator()
        
        close_disk_action = QAction(QIcon(self.get_icon_path('x-circle')), 'Close Disk', self)
        close_disk_action.triggered.connect(self.close_disk)
        file_menu.addAction(close_disk_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction(QIcon(self.get_icon_path('log-out')), 'Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Edit Menu
        edit_menu = menubar.addMenu('&Edit')
        
        new_file_action = QAction(QIcon(self.get_icon_path('file-plus')), 'New File...', self)
        new_file_action.setShortcut('Ctrl+Shift+N')
        new_file_action.triggered.connect(self.new_file_dialog)
        edit_menu.addAction(new_file_action)
        
        new_dir_action = QAction(QIcon(self.get_icon_path('folder-plus')), 'New Directory...', self)
        new_dir_action.setShortcut('Ctrl+Shift+D')
        new_dir_action.triggered.connect(self.new_directory_dialog)
        edit_menu.addAction(new_dir_action)
        
        edit_menu.addSeparator()
        
        delete_action = QAction(QIcon(self.get_icon_path('trash-2')), 'Delete', self)
        delete_action.setShortcut('Delete')
        delete_action.triggered.connect(self.delete_selected)
        edit_menu.addAction(delete_action)
        
        properties_action = QAction(QIcon(self.get_icon_path('info')), 'Properties...', self)
        properties_action.setShortcut('Alt+Return')
        properties_action.triggered.connect(self.show_properties)
        edit_menu.addAction(properties_action)
        
        # Tools Menu
        tools_menu = menubar.addMenu('&Tools')
        
        health_action = QAction(QIcon(self.get_icon_path('activity')), 'Health Report...', self)
        health_action.triggered.connect(self.show_health_report)
        tools_menu.addAction(health_action)
        
        search_action = QAction(QIcon(self.get_icon_path('search')), 'Search Files...', self)
        search_action.setShortcut('Ctrl+F')
        search_action.triggered.connect(self.show_search_dialog)
        tools_menu.addAction(search_action)
        
        # View Menu
        view_menu = menubar.addMenu('&View')
        
        refresh_action = QAction(QIcon(self.get_icon_path('refresh-cw')), 'Refresh', self)
        refresh_action.setShortcut('F5')
        refresh_action.triggered.connect(self.refresh_current_view)
        view_menu.addAction(refresh_action)
        
        # Help Menu
        help_menu = menubar.addMenu('&Help')
        
        about_action = QAction(QIcon(self.get_icon_path('info')), 'About...', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def setup_toolbar(self):
        """Create modern toolbar"""
        toolbar = self.addToolBar('Main')
        toolbar.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
        toolbar.setIconSize(QSize(24, 24))
        toolbar.setMovable(False)
        
        # Add actions to toolbar
        toolbar.addAction(QIcon(self.get_icon_path('disc')), 'New Disk', self.new_disk_dialog)
        toolbar.addAction(QIcon(self.get_icon_path('folder-open')), 'Open Disk', self.open_disk_dialog)
        toolbar.addSeparator()
        toolbar.addAction(QIcon(self.get_icon_path('file-plus')), 'New File', self.new_file_dialog)
        toolbar.addAction(QIcon(self.get_icon_path('folder-plus')), 'New Dir', self.new_directory_dialog)
        toolbar.addAction(QIcon(self.get_icon_path('trash-2')), 'Delete', self.delete_selected)
        toolbar.addSeparator()
        toolbar.addAction(QIcon(self.get_icon_path('activity')), 'Health', self.show_health_report)
        toolbar.addAction(QIcon(self.get_icon_path('refresh-cw')), 'Refresh', self.refresh_current_view)
        
    def setup_left_panel(self):
        """Create left panel with disk management"""
        left_widget = QWidget()
        left_widget.setMaximumWidth(350)
        left_widget.setMinimumWidth(300)
        
        layout = QVBoxLayout(left_widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # Virtual Disks section
        disks_label = QLabel("Virtual Disks")
        disks_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #4CAF50;")
        layout.addWidget(disks_label)
        
        self.disk_list = QListWidget()
        self.disk_list.setAlternatingRowColors(True)
        self.disk_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.disk_list.itemSelectionChanged.connect(self.on_disk_selected)
        self.disk_list.itemDoubleClicked.connect(self.mount_selected_disk)
        layout.addWidget(self.disk_list)
        
        # Disk Operations group
        ops_group = QGroupBox("Disk Operations")
        ops_layout = QVBoxLayout(ops_group)
        ops_layout.setSpacing(5)
        
        self.btn_create_disk = QPushButton("Create New Disk")
        self.btn_create_disk.setIcon(QIcon(self.get_icon_path('disc')))
        self.btn_create_disk.clicked.connect(self.new_disk_dialog)
        ops_layout.addWidget(self.btn_create_disk)
        
        self.btn_mount_disk = QPushButton("Mount Selected")
        self.btn_mount_disk.setIcon(QIcon(self.get_icon_path('hard-drive')))
        self.btn_mount_disk.clicked.connect(self.mount_selected_disk)
        self.btn_mount_disk.setEnabled(False)
        ops_layout.addWidget(self.btn_mount_disk)
        
        self.btn_clone_disk = QPushButton("Clone Disk")
        self.btn_clone_disk.setIcon(QIcon(self.get_icon_path('copy')))
        self.btn_clone_disk.clicked.connect(self.clone_disk_dialog)
        self.btn_clone_disk.setEnabled(False)
        ops_layout.addWidget(self.btn_clone_disk)
        
        self.btn_unmount_disk = QPushButton("Unmount")
        self.btn_unmount_disk.setIcon(QIcon(self.get_icon_path('eject')))
        self.btn_unmount_disk.clicked.connect(self.close_disk)
        self.btn_unmount_disk.setEnabled(False)
        ops_layout.addWidget(self.btn_unmount_disk)
        
        self.btn_delete_disk = QPushButton("Delete Disk")
        self.btn_delete_disk.setIcon(QIcon(self.get_icon_path('trash-2')))
        self.btn_delete_disk.clicked.connect(self.delete_selected_disk)
        self.btn_delete_disk.setEnabled(False)
        self.btn_delete_disk.setStyleSheet("QPushButton { color: #f44336; }")
        ops_layout.addWidget(self.btn_delete_disk)
        
        layout.addWidget(ops_group)
        
        # Disk Information group
        info_group = QGroupBox("Disk Information")
        info_layout = QFormLayout(info_group)
        
        self.size_line_edit = QLineEdit()
        self.size_line_edit.setReadOnly(True)
        info_layout.addRow("Size:", self.size_line_edit)
        
        self.free_space_line_edit = QLineEdit()
        self.free_space_line_edit.setReadOnly(True)
        info_layout.addRow("Free Space:", self.free_space_line_edit)
        
        self.file_system_line_edit = QLineEdit()
        self.file_system_line_edit.setReadOnly(True)
        info_layout.addRow("File System:", self.file_system_line_edit)
        
        self.status_line_edit = QLineEdit()
        self.status_line_edit.setReadOnly(True)
        info_layout.addRow("Status:", self.status_line_edit)
        
        layout.addWidget(info_group)
        layout.addStretch()
        
        self.main_splitter.addWidget(left_widget)
        
    def setup_right_panel(self):
        """Create right panel with file browser"""
        right_widget = QWidget()
        layout = QVBoxLayout(right_widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # Navigation bar
        nav_layout = QHBoxLayout()
        nav_layout.addWidget(QLabel("Path:"))
        
        self.path_line_edit = QLineEdit()
        self.path_line_edit.setReadOnly(True)
        self.path_line_edit.setText("/")
        nav_layout.addWidget(self.path_line_edit)
        
        self.btn_up = QPushButton("Up")
        self.btn_up.setIcon(QIcon(self.get_icon_path('arrow-up')))
        self.btn_up.clicked.connect(self.navigate_up)
        self.btn_up.setEnabled(False)
        nav_layout.addWidget(self.btn_up)
        
        self.btn_refresh = QPushButton("Refresh")
        self.btn_refresh.setIcon(QIcon(self.get_icon_path('refresh-cw')))
        self.btn_refresh.clicked.connect(self.refresh_file_view)
        self.btn_refresh.setEnabled(False)
        nav_layout.addWidget(self.btn_refresh)
        
        layout.addLayout(nav_layout)
        
        # File browser
        self.file_tree = QTreeWidget()
        self.file_tree.setAlternatingRowColors(True)
        self.file_tree.setSortingEnabled(True)
        self.file_tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.file_tree.setRootIsDecorated(False)
        
        headers = ["Name", "Type", "Size", "Modified"]
        self.file_tree.setHeaderLabels(headers)
        self.file_tree.setColumnWidth(0, 200)
        self.file_tree.setColumnWidth(1, 80)
        self.file_tree.setColumnWidth(2, 100)
        self.file_tree.setColumnWidth(3, 150)
        
        self.file_tree.itemDoubleClicked.connect(self.on_file_double_clicked)
        self.file_tree.itemSelectionChanged.connect(self.on_file_selection_changed)
        
        layout.addWidget(self.file_tree)
        
        # File operations
        ops_group = QGroupBox("File Operations")
        ops_layout = QHBoxLayout(ops_group)
        
        self.btn_new_file = QPushButton("New File")
        self.btn_new_file.setIcon(QIcon(self.get_icon_path('file-plus')))
        self.btn_new_file.clicked.connect(self.new_file_dialog)
        self.btn_new_file.setEnabled(False)
        ops_layout.addWidget(self.btn_new_file)
        
        self.btn_new_directory = QPushButton("New Directory")
        self.btn_new_directory.setIcon(QIcon(self.get_icon_path('folder-plus')))
        self.btn_new_directory.clicked.connect(self.new_directory_dialog)
        self.btn_new_directory.setEnabled(False)
        ops_layout.addWidget(self.btn_new_directory)
        
        self.btn_delete = QPushButton("Delete")
        self.btn_delete.setIcon(QIcon(self.get_icon_path('trash-2')))
        self.btn_delete.clicked.connect(self.delete_selected)
        self.btn_delete.setEnabled(False)
        ops_layout.addWidget(self.btn_delete)
        
        self.btn_properties = QPushButton("Properties")
        self.btn_properties.setIcon(QIcon(self.get_icon_path('info')))
        self.btn_properties.clicked.connect(self.show_properties)
        self.btn_properties.setEnabled(False)
        ops_layout.addWidget(self.btn_properties)
        
        layout.addWidget(ops_group)
        
        self.main_splitter.addWidget(right_widget)
        
    def setup_status_bar(self):
        """Create status bar with progress indicator"""
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")
        
        # Add permanent widgets
        self.current_disk_label = QLabel("No disk mounted")
        self.status_bar.addPermanentWidget(self.current_disk_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximumWidth(200)
        self.status_bar.addPermanentWidget(self.progress_bar)
        
    def setup_connections(self):
        """Setup signal connections"""
        pass  # Additional connections can be added here
        
    # Icon helper method
    def get_icon_path(self, icon_name):
        """Get path to icon file"""
        icons_dir = Path(__file__).parent / "icons"
        icon_path = icons_dir / f"{icon_name}.png"
        if icon_path.exists():
            return str(icon_path)
        # Fallback to a simple colored rectangle if icon doesn't exist
        return self.create_placeholder_icon(icon_name)
    
    def create_placeholder_icon(self, icon_name):
        """Create a simple placeholder icon"""
        pixmap = QPixmap(16, 16)
        colors = {
            'disc': '#2196F3',
            'folder-open': '#FF9800', 
            'copy': '#4CAF50',
            'trash-2': '#F44336',
            'info': '#9C27B0',
            'file-plus': '#00BCD4',
            'folder-plus': '#FF9800',
            'activity': '#8BC34A',
            'search': '#607D8B',
            'refresh-cw': '#3F51B5',
            'arrow-up': '#795548',
            'hard-drive': '#9E9E9E',
            'eject': '#FF5722'
        }
        color = colors.get(icon_name, '#757575')
        pixmap.fill(QColor(color))
        return pixmap
        
    # Event handlers and dialog methods
    def refresh_disk_list(self):
        """Refresh the list of available disk images"""
        self.disk_list.clear()
        
        # Look for .img files in current directory
        current_dir = Path.cwd()
        for img_file in current_dir.glob("*.img"):
            if img_file.is_file():
                item = QListWidgetItem(img_file.name)
                item.setData(Qt.UserRole, str(img_file))
                item.setIcon(QIcon(self.get_icon_path('disc')))
                self.disk_list.addItem(item)
    
    def on_disk_selected(self):
        """Handle disk selection"""
        selected_items = self.disk_list.selectedItems()
        has_selection = len(selected_items) > 0
        
        self.btn_mount_disk.setEnabled(has_selection)
        self.btn_clone_disk.setEnabled(has_selection)
        self.btn_delete_disk.setEnabled(has_selection)
        
        if has_selection:
            disk_path = selected_items[0].data(Qt.UserRole)
            self.update_disk_info(disk_path)
        else:
            self.clear_disk_info()
    
    def update_disk_info(self, disk_path):
        """Update disk information display"""
        try:
            if os.path.exists(disk_path):
                size = os.path.getsize(disk_path)
                self.size_line_edit.setText(f"{size / (1024*1024):.1f} MB")
                self.file_system_line_edit.setText("FAT32")
                self.status_line_edit.setText("Available")
                
                # Try to get free space info
                file_ops = self.fat32_manager.mount_disk(disk_path)
                if file_ops:
                    # This would require adding a method to get free space
                    self.free_space_line_edit.setText("N/A")
                else:
                    self.free_space_line_edit.setText("N/A")
            else:
                self.clear_disk_info()
        except Exception as e:
            self.clear_disk_info()
    
    def clear_disk_info(self):
        """Clear disk information display"""
        self.size_line_edit.clear()
        self.free_space_line_edit.clear()
        self.file_system_line_edit.clear()
        self.status_line_edit.clear()
    
    def mount_selected_disk(self):
        """Mount the selected disk"""
        selected_items = self.disk_list.selectedItems()
        if not selected_items:
            return
            
        disk_path = selected_items[0].data(Qt.UserRole)
        self.mount_disk(disk_path)
    
    def mount_disk(self, disk_path):
        """Mount a disk and update UI"""
        try:
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)  # Indeterminate
            self.status_bar.showMessage("Mounting disk...")
            
            self.current_file_ops = self.fat32_manager.mount_disk(disk_path)
            
            if self.current_file_ops:
                self.current_disk_path = disk_path
                self.current_disk_label.setText(f"Mounted: {Path(disk_path).name}")
                self.status_line_edit.setText("Mounted")
                
                # Enable file operations
                self.btn_new_file.setEnabled(True)
                self.btn_new_directory.setEnabled(True)
                self.btn_refresh.setEnabled(True)
                self.btn_unmount_disk.setEnabled(True)
                
                # Load root directory
                self.current_path = "/"
                self.refresh_file_view()
                
                self.status_bar.showMessage("Disk mounted successfully")
            else:
                QMessageBox.warning(self, "Mount Error", "Failed to mount disk. Check if it's a valid FAT32 image.")
                self.status_bar.showMessage("Mount failed")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to mount disk: {str(e)}")
            self.status_bar.showMessage("Mount error")
        finally:
            self.progress_bar.setVisible(False)
    
    def close_disk(self):
        """Unmount current disk"""
        self.current_file_ops = None
        self.current_disk_path = None
        self.current_path = "/"
        
        self.current_disk_label.setText("No disk mounted")
        self.status_line_edit.setText("Available")
        self.path_line_edit.setText("/")
        
        # Disable file operations
        self.btn_new_file.setEnabled(False)
        self.btn_new_directory.setEnabled(False)
        self.btn_delete.setEnabled(False)
        self.btn_properties.setEnabled(False)
        self.btn_refresh.setEnabled(False)
        self.btn_unmount_disk.setEnabled(False)
        self.btn_up.setEnabled(False)
        
        # Clear file tree
        self.file_tree.clear()
        
        self.status_bar.showMessage("Disk unmounted")
    
    def refresh_file_view(self):
        """Refresh the file view"""
        if not self.current_file_ops:
            return
            
        try:
            self.file_tree.clear()
            entries = self.current_file_ops.list_directory(self.current_path, recursive=False)
            
            for entry in entries:
                if entry['name'] in ['.', '..']:
                    continue
                    
                item = QTreeWidgetItem()
                item.setText(0, entry['name'])
                item.setText(1, "DIR" if entry['is_directory'] else "FILE")
                item.setText(2, "" if entry['is_directory'] else f"{entry['size']} bytes")
                item.setText(3, entry['modified'])
                
                if entry['is_directory']:
                    item.setIcon(0, QIcon(self.get_icon_path('folder-plus')))
                else:
                    item.setIcon(0, QIcon(self.get_icon_path('file-plus')))
                
                item.setData(0, Qt.UserRole, entry)
                self.file_tree.addTopLevelItem(item)
                
            self.path_line_edit.setText(self.current_path)
            self.btn_up.setEnabled(self.current_path != "/")
            
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to list directory: {str(e)}")
    
    def navigate_up(self):
        """Navigate to parent directory"""
        if self.current_path == "/":
            return
            
        parent_path = str(Path(self.current_path).parent)
        if parent_path == ".":
            parent_path = "/"
            
        self.current_path = parent_path
        self.refresh_file_view()
    
    def on_file_double_clicked(self, item):
        """Handle file double-click"""
        entry = item.data(0, Qt.UserRole)
        if entry and entry['is_directory']:
            # Navigate into directory
            if self.current_path.endswith('/'):
                self.current_path = self.current_path + entry['name']
            else:
                self.current_path = self.current_path + '/' + entry['name']
            self.refresh_file_view()
        else:
            # Open file properties or content
            self.show_properties()
    
    def on_file_selection_changed(self):
        """Handle file selection change"""
        selected_items = self.file_tree.selectedItems()
        has_selection = len(selected_items) > 0
        
        self.btn_delete.setEnabled(has_selection and self.current_file_ops)
        self.btn_properties.setEnabled(has_selection and self.current_file_ops)
    
    def refresh_current_view(self):
        """Refresh current view"""
        if self.current_file_ops:
            self.refresh_file_view()
        else:
            self.refresh_disk_list()
    
    # Dialog methods
    def new_disk_dialog(self):
        """Show new disk creation dialog"""
        dialog = NewDiskDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            self.refresh_disk_list()
    
    def open_disk_dialog(self):
        """Show open disk dialog"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Disk Image", "", "Disk Images (*.img);;All Files (*)"
        )
        if file_path:
            self.mount_disk(file_path)
    
    def clone_disk_dialog(self):
        """Show clone disk dialog"""
        selected_items = self.disk_list.selectedItems()
        if not selected_items:
            QMessageBox.information(self, "Clone Disk", "Please select a disk to clone.")
            return
            
        source_path = selected_items[0].data(Qt.UserRole)
        dialog = CloneDiskDialog(self, source_path)
        if dialog.exec_() == QDialog.Accepted:
            self.refresh_disk_list()
    
    def new_file_dialog(self):
        """Show new file dialog"""
        if not self.current_file_ops:
            QMessageBox.information(self, "New File", "Please mount a disk first.")
            return
            
        dialog = NewFileDialog(self, self.current_path)
        if dialog.exec_() == QDialog.Accepted:
            self.refresh_file_view()
    
    def new_directory_dialog(self):
        """Show new directory dialog"""
        if not self.current_file_ops:
            QMessageBox.information(self, "New Directory", "Please mount a disk first.")
            return
            
        dialog = NewDirectoryDialog(self, self.current_path)
        if dialog.exec_() == QDialog.Accepted:
            self.refresh_file_view()
    
    def delete_selected(self):
        """Delete selected files/directories"""
        if not self.current_file_ops:
            return
            
        selected_items = self.file_tree.selectedItems()
        if not selected_items:
            return
            
        # Confirm deletion
        names = [item.text(0) for item in selected_items]
        reply = QMessageBox.question(
            self, "Confirm Deletion",
            f"Are you sure you want to delete {len(names)} item(s)?\n\n" + "\n".join(names[:5]) + 
            ("..." if len(names) > 5 else ""),
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                for item in selected_items:
                    entry = item.data(0, Qt.UserRole)
                    file_path = self.current_path.rstrip('/') + '/' + entry['name']
                    
                    if entry['is_directory']:
                        self.fat32_manager.delete_directory(self.current_disk_path, file_path)
                    else:
                        self.fat32_manager.delete_file(self.current_disk_path, file_path)
                
                self.refresh_file_view()
                self.status_bar.showMessage("Items deleted successfully")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete items: {str(e)}")

        def delete_selected_disk(self):
            """Delete the selected disk"""
            selected_items = self.disk_list.selectedItems()
            if not selected_items:
                return

            disk_name = selected_items[0].text()
            disk_path = selected_items[0].data(Qt.UserRole)

            reply = QMessageBox.question(
                self, "Confirm Deletion",
                f"Are you sure you want to permanently delete the disk '{disk_name}'?\n\n"
                f"This action cannot be undone!",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                try:
                    # If the disk is currently mounted, unmount it first
                    if self.current_disk_path == disk_path:
                        self.close_disk()

                    success = self.fat32_manager.delete_disk(disk_path)

                    if success:
                        self.refresh_disk_list()
                        self.status_bar.showMessage(f"Disk '{disk_name}' deleted successfully")
                        QMessageBox.information(self, "Success", f"Disk '{disk_name}' has been deleted.")
                    else:
                        QMessageBox.warning(self, "Error", f"Failed to delete disk '{disk_name}'.")

                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to delete disk: {str(e)}")

        def show_properties(self):
            """Show properties of selected file/directory"""
            if not self.current_file_ops:
                return

            selected_items = self.file_tree.selectedItems()
            if not selected_items:
                return

            item = selected_items[0]
            entry = item.data(0, Qt.UserRole)

            if entry:
                dialog = PropertiesDialog(self, entry, self.current_path)
                dialog.exec_()

        def show_health_report(self):
            """Show health report dialog"""
            if not self.current_disk_path:
                QMessageBox.information(self, "Health Report", "Please mount a disk first.")
                return

            dialog = HealthReportDialog(self, self.current_disk_path)
            dialog.exec_()

        def show_search_dialog(self):
            """Show file search dialog"""
            if not self.current_file_ops:
                QMessageBox.information(self, "Search Files", "Please mount a disk first.")
                return

            dialog = SearchDialog(self, self.current_disk_path)
            dialog.exec_()

        def show_about(self):
            """Show about dialog"""
            about_text = """
            <h2>FAT32 Virtual Disk Manager</h2>
            <p><b>Version:</b> 1.0.0</p>
            <p><b>Description:</b> A comprehensive tool for creating, managing, and manipulating FAT32 virtual disk images.</p>

            <h3>Features:</h3>
            <ul>
            <li>Create and format FAT32 virtual disks</li>
            <li>Mount and browse virtual disk contents</li>
            <li>Create, read, update, and delete files and directories</li>
            <li>File encryption support</li>
            <li>Disk health monitoring and reporting</li>
            <li>Advanced file search capabilities</li>
            <li>Disk cloning functionality</li>
            </ul>

            <h3>Technology Stack:</h3>
            <ul>
            <li>Python 3.x</li>
            <li>PyQt5 for modern GUI</li>
            <li>Custom FAT32 implementation</li>
            <li>AES encryption for file security</li>
            </ul>

            <p><b>Developer:</b> FAT32 Development Team</p>
            <p><b>License:</b> MIT License</p>

            <hr>
            <p><i>For support and documentation, visit our GitHub repository.</i></p>
            """

            QMessageBox.about(self, "About FAT32 Virtual Disk Manager", about_text)

        def get_modern_stylesheet(self):
            """Return modern dark theme stylesheet"""
            return """
            QMainWindow {
                background-color: #2b2b2b;
                color: #ffffff;
            }

            QMenuBar {
                background-color: #3c3c3c;
                color: #ffffff;
                border-bottom: 1px solid #555555;
            }

            QMenuBar::item {
                background-color: transparent;
                padding: 5px 10px;
            }

            QMenuBar::item:selected {
                background-color: #4CAF50;
            }

            QMenu {
                background-color: #3c3c3c;
                color: #ffffff;
                border: 1px solid #555555;
            }

            QMenu::item {
                padding: 5px 25px;
            }

            QMenu::item:selected {
                background-color: #4CAF50;
            }

            QToolBar {
                background-color: #3c3c3c;
                border: none;
                spacing: 3px;
            }

            QToolButton {
                background-color: transparent;
                border: none;
                padding: 5px;
                margin: 2px;
            }

            QToolButton:hover {
                background-color: #4CAF50;
                border-radius: 3px;
            }

            QListWidget {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #555555;
                selection-background-color: #4CAF50;
            }

            QListWidget::item {
                padding: 5px;
                border-bottom: 1px solid #333333;
            }

            QListWidget::item:hover {
                background-color: #333333;
            }

            QTreeWidget {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #555555;
                selection-background-color: #4CAF50;
                alternate-background-color: #252525;
            }

            QTreeWidget::item {
                padding: 3px;
            }

            QTreeWidget::item:hover {
                background-color: #333333;
            }

            QHeaderView::section {
                background-color: #3c3c3c;
                color: #ffffff;
                padding: 5px;
                border: 1px solid #555555;
            }

            QPushButton {
                background-color: #4CAF50;
                color: #ffffff;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }

            QPushButton:hover {
                background-color: #45a049;
            }

            QPushButton:pressed {
                background-color: #3d8b40;
            }

            QPushButton:disabled {
                background-color: #666666;
                color: #999999;
            }

            QGroupBox {
                color: #ffffff;
                border: 2px solid #555555;
                border-radius: 5px;
                margin-top: 10px;
                font-weight: bold;
            }

            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }

            QLineEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #555555;
                padding: 5px;
                border-radius: 3px;
            }

            QLineEdit:focus {
                border: 2px solid #4CAF50;
            }

            QLabel {
                color: #ffffff;
            }

            QStatusBar {
                background-color: #3c3c3c;
                color: #ffffff;
                border-top: 1px solid #555555;
            }

            QProgressBar {
                border: 1px solid #555555;
                border-radius: 3px;
                text-align: center;
                background-color: #1e1e1e;
            }

            QProgressBar::chunk {
                background-color: #4CAF50;
                border-radius: 2px;
            }

            QSplitter::handle {
                background-color: #555555;
            }

            QSplitter::handle:horizontal {
                width: 3px;
            }

            QSplitter::handle:vertical {
                height: 3px;
            }

            QTabWidget::pane {
                border: 1px solid #555555;
                background-color: #2b2b2b;
            }

            QTabBar::tab {
                background-color: #3c3c3c;
                color: #ffffff;
                padding: 8px 12px;
                margin-right: 2px;
            }

            QTabBar::tab:selected {
                background-color: #4CAF50;
            }

            QTabBar::tab:hover {
                background-color: #555555;
            }

            QScrollBar:vertical {
                background-color: #2b2b2b;
                width: 12px;
                border-radius: 6px;
            }

            QScrollBar::handle:vertical {
                background-color: #555555;
                border-radius: 6px;
                min-height: 20px;
            }

            QScrollBar::handle:vertical:hover {
                background-color: #777777;
            }

            QScrollBar:horizontal {
                background-color: #2b2b2b;
                height: 12px;
                border-radius: 6px;
            }

            QScrollBar::handle:horizontal {
                background-color: #555555;
                border-radius: 6px;
                min-width: 20px;
            }

            QScrollBar::handle:horizontal:hover {
                background-color: #777777;
            }

            QScrollBar::add-line, QScrollBar::sub-line {
                border: none;
                background: none;
            }
            """

    def main():
        """Main function to run the application"""
        app = QApplication(sys.argv)

        # Set application properties
        app.setApplicationName("FAT32 Virtual Disk Manager")
        app.setApplicationVersion("1.0.0")
        app.setOrganizationName("FAT32 Development Team")

        # Create and show main window
        window = MainWindow()
        window.show()

        # Start event loop
        sys.exit(app.exec_())

    if __name__ == "__main__":
        main()