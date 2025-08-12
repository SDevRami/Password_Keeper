import tkinter as tk
from tkinter import filedialog, messagebox
import json
from cryptography.fernet import Fernet
import tkinter.simpledialog as simpledialog
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class PasswordKeeperApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Keeper")
        self.root.geometry("800x600")

        # Encryption key setup
        self.key = None
        self.cipher = None
        self.salt = None 

        # Data storage
        self.data_file = None
        self.password_data = []

        # Currently focused entry
        self.current_entry = None

        # Create UI frames
        self.start_frame = tk.Frame(root)
        self.main_frame = tk.Frame(root)

        # Initialize UI
        self.create_start_page()
        self.create_main_page()

        # Show start page initially
        self.show_start_page()

    def create_start_page(self):
        # Clear frame
        for widget in self.start_frame.winfo_children():
            widget.destroy()

        # App title
        title_label = tk.Label(self.start_frame, text="Password Keeper", font=("Helvetica", 24))
        title_label.pack(pady=20)

        # Button frame
        button_frame = tk.Frame(self.start_frame)
        button_frame.pack(pady=20)

        # Open existing file button
        open_btn = tk.Button(button_frame, text="Open Existing File",
                             command=self.open_existing_file,
                             width=20, height=2)
        open_btn.pack(pady=10)

        # Create new file button
        new_btn = tk.Button(button_frame, text="Create New Password List",
                            command=self.create_new_file,
                            width=20, height=2)
        new_btn.pack(pady=10)

        # Pack the start frame
        self.start_frame.pack(expand=True, fill=tk.BOTH)

    def create_main_page(self):
        # Clear frame
        for widget in self.main_frame.winfo_children():
            widget.destroy()

        # Split into sidebar and main content
        sidebar = tk.Frame(self.main_frame, width=200, bg="#f0f0f0")
        sidebar.pack(side=tk.LEFT, fill=tk.Y)

        # Main content area with white background
        main_content = tk.Frame(self.main_frame)
        main_content.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH)

        # Sidebar widgets
        sidebar_title = tk.Label(sidebar, text="Add New Item", bg="#f0f0f0", font=("Helvetica", 12, "bold"))
        sidebar_title.pack(pady=10)

        # Form fields
        fields = [
            ("Title", "entry_title"),
            ("Description", "entry_description"),
            ("Email", "entry_email"),
            ("Password", "entry_password")
        ]

        self.form_entries = {}

        for field_text, field_name in fields:
            frame = tk.Frame(sidebar)
            frame.pack(pady=5, padx=10, fill=tk.X)

            label = tk.Label(frame, text=field_text + ":", bg="#f0f0f0")
            label.pack(side=tk.LEFT)

            entry = tk.Entry(frame)
            entry.pack(side=tk.RIGHT, expand=True, fill=tk.X)

            entry.bind("<FocusIn>", lambda e, name=field_name: self.set_current_entry(name))

            self.form_entries[field_name] = entry

        # Add button
        add_btn = tk.Button(sidebar, text="Add", command=self.add_password_item)
        add_btn.pack(pady=10)

        # Search bar
        self.search_var = tk.StringVar()
        search_frame = tk.Frame(main_content)
        search_frame.pack(pady=10)

        search_label = tk.Label(search_frame, text="Search:")
        search_label.pack(side=tk.LEFT)

        search_entry = tk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
        search_entry.bind("<KeyRelease>", self.update_search)

        # Keyboard button
        keyboard_btn = tk.Button(search_frame, text="Keyboard", command=self.open_virtual_keyboard)
        keyboard_btn.pack(side=tk.LEFT, padx=5)

        # Back button
        back_btn = tk.Button(search_frame, text="Back to Start", command=self.show_start_page)
        back_btn.pack(padx=20)

        # Main content area
        self.list_canvas = tk.Canvas(main_content, bg="white")
        scrollbar = tk.Scrollbar(main_content, orient="vertical", command=self.list_canvas.yview)
        self.list_canvas.configure(yscrollcommand=scrollbar.set)

        # Create a frame to hold the list items
        self.list_frame = tk.Frame(self.list_canvas, bg="white")

        # Configure the scrollable frame to update the scroll region of the canvas
        self.list_frame.bind(
            "<Configure>",
            lambda e: self.list_canvas.configure(scrollregion=self.list_canvas.bbox("all"))
        )

        # Create a window in the canvas
        self.list_canvas.create_window((0, 0), window=self.list_frame, anchor="nw")

        # Pack the canvas and scrollbar
        self.list_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.main_frame.pack_forget()

    def set_current_entry(self, entry_name):
        if entry_name == "search":
            self.current_entry = self.search_var
        else:
            self.current_entry = self.form_entries[entry_name]

    def open_virtual_keyboard(self):
        keyboard_window = tk.Toplevel(self.root)
        keyboard_window.title("Virtual Keyboard")
        keyboard_window.geometry("1000x600")

        # Create the virtual keyboard buttons
        keys = [
            '`', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '←-',
            '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', 'Q', 'q', 'W', 'w',
            'E', 'e', 'R', 'r', 'T', 't', 'Y', 'y', 'U', 'u', 'I','i', 'O', 'o', 'P', 'p',
            '[', '{', ']', '}', '\\', '|','A', 'a','S', 's', 'D', 'd', 'F', 'f', 'G', 'g',
            'H', 'h', 'J', 'j', 'K', 'k', 'L', 'l', ';', ':', "'", '"',
            'Z', 'z', 'X', 'x', 'C', 'c', 'V', 'v', 'B', 'b', 'N', 'n', 'M', 'm', ',',
            '<', '.', '>', '/', '?','Space',
        ]

        row = 0
        col = 0
        for key in keys:
            button = tk.Button(keyboard_window, text=key, font=('Arial', 18), width=4, height=2,
                               command=lambda k=key: self.on_key_press(k))
            button.grid(row=row, column=col)

            col += 1
            if col > 13:
                col = 0
                row += 1

    def on_key_press(self, key):
        if self.current_entry is not None:
            if key == 'Space':
                self.current_entry.insert(tk.END, ' ')
            elif key == '←-':
                current_text = self.current_entry.get()
                self.current_entry.delete(len(current_text) - 1)
            else:
                self.current_entry.insert(tk.END, key)

    def show_start_page(self):
        self.main_frame.pack_forget()
        self.start_frame.pack(expand=True, fill=tk.BOTH)

    def show_main_page(self):
        self.start_frame.pack_forget()
        self.main_frame.pack(expand=True, fill=tk.BOTH)
        self.display_password_list()

    def open_existing_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Password File",
            filetypes=[("Password Keeper Files", "*.paskep"), ("All Files", "*.*")]
        )

        if file_path:
            # Ask for password
            password = tk.simpledialog.askstring("Password", "Enter password for the file:", show='*')
            if not password or len(password) < 8:
                messagebox.showerror("Error", "Password must be at least 8 characters long.")
                return

            try:
                with open(file_path, "r") as f:
                    data = json.load(f)

                # Extract salt and encrypted data
                self.salt = base64.b64decode(data['salt'])
                encrypted_data = base64.b64decode(data['encrypted_data'])

                # Derive encryption key from password using KDF
                self.key = self.derive_key(password, self.salt)
                self.cipher = Fernet(self.key)

                try:
                    decrypted_data = self.cipher.decrypt(encrypted_data)
                    self.password_data = json.loads(decrypted_data.decode())
                    self.data_file = file_path
                    self.show_main_page()
                except:
                    messagebox.showerror("Error", "Failed to decrypt file. Incorrect password?")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open file: {str(e)}")

    def create_new_file(self):
        file_path = filedialog.asksaveasfilename(
            title="Create New Password File",
            defaultextension=".paskep",
            filetypes=[("Password Keeper Files", "*.paskep"), ("All Files", "*.*")]
        )

        if file_path:
            # Ask for password
            password = tk.simpledialog.askstring("Password", "Enter a password for the new file:", show='*')
            if not password or len(password) < 8:
                messagebox.showerror("Error", "Password must be at least 8 characters long.")
                return

            # Generate a random salt
            self.salt = os.urandom(16)

            # Derive encryption key from password using KDF
            self.key = self.derive_key(password, self.salt)
            self.cipher = Fernet(self.key)

            # Create empty password list
            self.password_data = []
            self.data_file = file_path

            # Save empty encrypted file
            self.save_data(self.salt)

            messagebox.showinfo("Key Generated", "Your encryption key has been derived from the password.")

            self.show_main_page()

    def derive_key(self, password, salt):
        """Derive a key from the password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def save_data(self, salt):
        if not self.data_file:
            return

        try:
            json_data = json.dumps(self.password_data).encode()
            encrypted_data = self.cipher.encrypt(json_data)

            # Save salt and encrypted data to JSON
            with open(self.data_file, "w") as f:
                json.dump({
                    'salt': base64.b64encode(salt).decode(),
                    'encrypted_data': base64.b64encode(encrypted_data).decode()
                }, f)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {str(e)}")

    def add_password_item(self):
        title = self.form_entries["entry_title"].get()
        description = self.form_entries["entry_description"].get()
        email = self.form_entries["entry_email"].get()
        password = self.form_entries["entry_password"].get()

        if not all([title, email, password]):
            messagebox.showwarning("Warning", "Title, Email and Password are required")
            return

        new_item = {
            "title": title,
            "description": description,
            "email": email,
            "password": password
        }

        self.password_data.append(new_item)

        # Sort by email
        self.password_data.sort(key=lambda x: x["email"].lower())

        # Clear form fields
        for entry in self.form_entries.values():
            entry.delete(0, tk.END)

        self.save_data(self.salt) 
        self.display_password_list()
        # Update the scroll region after adding items
        self.list_canvas.configure(scrollregion=self.list_canvas.bbox("all"))

    def display_password_list(self):
        # Clear current list
        for widget in self.list_frame.winfo_children():
            widget.destroy()

        if not self.password_data:
            empty_label = tk.Label(self.list_frame, text="No password items found", bg="white")
            empty_label.pack(pady=20)
            return

        search_text = self.search_var.get().lower()
        filtered_data = [item for item in self.password_data if search_text in item["title"].lower() or search_text in item["email"].lower() or search_text in item["description"].lower()]

        if not filtered_data:
            empty_label = tk.Label(self.list_frame, text="No matching items found", bg="white")
            empty_label.pack(pady=20)
            return

        for idx, item in enumerate(filtered_data):
            item_frame = tk.Frame(self.list_frame, bd=2, relief=tk.GROOVE, padx=5, pady=5)
            item_frame.pack(fill=tk.X, expand=True, pady=2, padx=5)

            # Title and description
            title_label = tk.Label(item_frame, text=item["title"], font=("Helvetica", 12, "bold"))
            title_label.grid(row=0, column=2, sticky=tk.W)

            desc_label = tk.Label(item_frame, text=item["description"], wraplength=500)
            desc_label.grid(row=1, column=2, sticky=tk.W)

            # Email info (hidden initially)
            email_label = tk.Label(item_frame, text=f"Email: {item['email']}")
            password_label = tk.Label(item_frame, text=f"Password: {item['password']}")

            # Button frame
            button_frame = tk.Frame(item_frame)
            button_frame.grid(row=0, column=0, rowspan=2, sticky=tk.E)

            # View button (to show email and password)
            view_btn = tk.Button(button_frame, text="view",
                                 command=lambda i=idx, e=email_label, p=password_label: self.toggle_item_details(e, p))
            view_btn.pack(side=tk.LEFT, padx=2)

            # Edit button
            edit_btn = tk.Button(button_frame, text="edit",
                                 command=lambda i=idx: self.edit_item(i))
            edit_btn.pack(side=tk.LEFT, padx=2)

            # Delete button
            delete_btn = tk.Button(button_frame, text="Delete",
                                   command=lambda i=idx: self.delete_item(i))
            delete_btn.pack(pady=10)

        self.list_canvas.configure(scrollregion=self.list_canvas.bbox("all"))

    def update_search(self, event):
        self.display_password_list()

    def toggle_item_details(self, email_label, password_label):
        if email_label.winfo_ismapped():
            email_label.grid_forget()
            password_label.grid_forget()
        else:
            email_label.grid(row=0, column=3, sticky=tk.W)
            password_label.grid(row=1, column=3, sticky=tk.W)

    def edit_item(self, item_index):
        item = self.password_data[item_index]

        # Create editing window
        edit_window = tk.Toplevel(self.root)
        edit_window.title("Edit Password Item")

        # Form fields
        fields = [
            ("Title", "entry_title"),
            ("Description", "entry_description"),
            ("Email", "entry_email"),
            ("Password", "entry_password")
        ]

        edit_entries = {}

        for idx, (field_text, field_name) in enumerate(fields):
            frame = tk.Frame(edit_window)
            frame.pack(pady=5, padx=10, fill=tk.X)

            label = tk.Label(frame, text=field_text + ":")
            label.pack(side=tk.LEFT)

            entry = tk.Entry(frame)
            entry.pack(side=tk.RIGHT, expand=True, fill=tk.X)
            entry.insert(0, item[field_name.split('_')[1]])

            # Bind focus event to update current entry
            entry.bind("<FocusIn>", lambda e, name=field_name: self.set_current_entry(name))

            edit_entries[field_name] = entry

        # Save button
        save_btn = tk.Button(edit_window, text="Save",
                             command=lambda: self.save_edit(item_index, edit_entries, edit_window))
        save_btn.pack(pady=10)

    def delete_item(self, item_index):
        # Confirm deletion
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this item?"):
            del self.password_data[item_index]
            self.save_data(self.salt)
            self.display_password_list()

    def save_edit(self, item_index, entries, window):
        title = entries["entry_title"].get()
        description = entries["entry_description"].get()
        email = entries["entry_email"].get()
        password = entries["entry_password"].get()

        if not all([title, email, password]):
            messagebox.showwarning("Warning", "Title, Email and Password are required")
            return

        self.password_data[item_index] = {
            "title": title,
            "description": description,
            "email": email,
            "password": password
        }

        # Sort by email
        self.password_data.sort(key=lambda x: x["email"].lower())

        self.save_data(self.salt)
        self.display_password_list()
        window.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordKeeperApp(root)
    root.mainloop()

