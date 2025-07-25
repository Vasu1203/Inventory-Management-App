import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sqlite3
import hashlib
import csv
from datetime import datetime, timedelta

# Hash password function
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Database setup
conn = sqlite3.connect("inventory.db")
cursor = conn.cursor()

# Create user table
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'user'))
)''')

# Create inventory table
cursor.execute('''CREATE TABLE IF NOT EXISTS inventory (
    id INTEGER PRIMARY KEY,
    item_name TEXT NOT NULL,
    quantity INTEGER NOT NULL,
    price REAL NOT NULL,
    username TEXT NOT NULL
)''')

# Insert default admin if not exists
cursor.execute("SELECT * FROM users WHERE username = 'admin'")
if cursor.fetchone() is None:
    cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                   ('admin', hash_password('admin123'), 'admin'))
conn.commit()

# Insert more default users if needed
default_users = [
    ('manager', hash_password('manager123'), 'admin'),
    ('staff', hash_password('staff123'), 'user'),
]

for username, pwd_hash, role in default_users:
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    if cursor.fetchone() is None:
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                       (username, pwd_hash, role))
conn.commit()

class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Login - Inventory System")
        self.attempts = 0
        self.locked_until = None
        self.login_button = tk.Button(root, text="Login", command=self.login)
        self.login_button.grid(row=2, column=1)

        tk.Label(root, text="Username").grid(row=0, column=0)
        tk.Label(root, text="Password").grid(row=1, column=0)

        self.username_entry = tk.Entry(root)
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(root, textvariable=self.password_var, show="*")

        def toggle_password():
            self.password_entry.config(show="" if self.show_pass_var.get() else "*")

        self.show_pass_var = tk.BooleanVar()
        tk.Checkbutton(root, text="Show Password", variable=self.show_pass_var, command=toggle_password).grid(row=1, column=2)

        self.username_entry.grid(row=0, column=1)
        self.password_entry.grid(row=1, column=1)

        self.username_entry.bind("<Return>", lambda e: self.password_entry.focus())
        self.password_entry.bind("<Return>", lambda e: self.login())

        tk.Button(root, text="Login", command=self.login).grid(row=2, column=1)
        tk.Button(root, text="Register", command=self.register_window).grid(row=3, column=1)

    def login(self):
        # If locked, check if time has passed
        if self.locked_until:
            if datetime.now() < self.locked_until:
                remaining = (self.locked_until - datetime.now()).seconds
                minutes = remaining // 60
                seconds = remaining % 60
                messagebox.showerror("Locked", f"Too many failed attempts. Try again in {minutes:02d}:{seconds:02d}.")
                return
            else:
                self.locked_until = None
                self.attempts = 0
                self.login_button.config(state=tk.NORMAL)

        username = self.username_entry.get()
        password = hash_password(self.password_entry.get())

        cursor.execute("SELECT role FROM users WHERE username=? AND password_hash=?", (username, password))
        result = cursor.fetchone()
        if result:
            self.attempts = 0
            self.locked_until = None
            self.root.destroy()
            root = tk.Tk()
            InventoryApp(root, username, result[0])
            root.mainloop()
        else:
            self.attempts += 1
            remaining = 3 - self.attempts
            if remaining > 0:
                messagebox.showerror("Login Failed", f"Invalid credentials. {remaining} attempts left.")
            else:
                self.locked_until = datetime.now() + timedelta(minutes=5)
                self.login_button.config(state=tk.DISABLED)
                messagebox.showerror("Account Locked", "Too many failed attempts.\nLogin disabled for 5 minutes.")


    def register_window(self):
        reg = tk.Toplevel(self.root)
        reg.title("Register New User (Admin Only)")

        admin_pass_var = tk.StringVar()
        new_pass_var = tk.StringVar()

        def toggle_admin_pass():
            admin_pass.config(show="" if admin_show_var.get() else "*")

        def toggle_new_pass():
            new_pass.config(show="" if new_show_var.get() else "*")

        tk.Label(reg, text="Admin Username").grid(row=0, column=0)
        tk.Label(reg, text="Admin Password").grid(row=1, column=0)
        tk.Label(reg, text="New Username").grid(row=2, column=0)
        tk.Label(reg, text="New Password").grid(row=3, column=0)
        tk.Label(reg, text="Role (admin/user)").grid(row=4, column=0)

        admin_user = tk.Entry(reg)
        admin_pass = tk.Entry(reg, textvariable=admin_pass_var, show="*")
        new_user = tk.Entry(reg)
        new_pass = tk.Entry(reg, textvariable=new_pass_var, show="*")
        role_entry = tk.Entry(reg)

        admin_show_var = tk.BooleanVar()
        tk.Checkbutton(reg, text="Show Password", variable=admin_show_var, command=toggle_admin_pass).grid(row=1, column=2)

        new_show_var = tk.BooleanVar()
        tk.Checkbutton(reg, text="Show Password", variable=new_show_var, command=toggle_new_pass).grid(row=3, column=2)

        admin_user.grid(row=0, column=1)
        admin_pass.grid(row=1, column=1)
        new_user.grid(row=2, column=1)
        new_pass.grid(row=3, column=1)
        role_entry.grid(row=4, column=1)

        admin_user.bind("<Return>", lambda e: admin_pass.focus())
        admin_pass.bind("<Return>", lambda e: new_user.focus())
        new_user.bind("<Return>", lambda e: new_pass.focus())
        new_pass.bind("<Return>", lambda e: role_entry.focus())
        role_entry.bind("<Return>", lambda e: register())

        def register():
            a_user = admin_user.get()
            a_pass = hash_password(admin_pass.get())
            cursor.execute("SELECT role FROM users WHERE username=? AND password_hash=?", (a_user, a_pass))
            result = cursor.fetchone()
            if result and result[0] == 'admin':
                try:
                    cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                                   (new_user.get(), hash_password(new_pass.get()), role_entry.get()))
                    conn.commit()
                    messagebox.showinfo("Success", "User registered")
                    reg.destroy()
                except sqlite3.IntegrityError:
                    messagebox.showerror("Error", "Username already exists")
            else:
                messagebox.showerror("Access Denied", "Only admins can register new users")

        tk.Button(reg, text="Register", command=register).grid(row=5, column=1)

class InventoryApp:
    def __init__(self, root, username, role):
        self.root = root
        self.username = username
        self.role = role
        self.root.title(f"Inventory Management - Logged in as {username} ({role})")
        self.conn = sqlite3.connect("inventory.db")

        # Input Fields
        self.id_entry = tk.Entry(root)
        self.name_entry = tk.Entry(root)
        self.qty_entry = tk.Entry(root)
        self.price_entry = tk.Entry(root)

        tk.Label(root, text="ID").grid(row=0, column=1)
        tk.Label(root, text="Item Name").grid(row=0, column=4)
        tk.Label(root, text="Quantity").grid(row=0, column=6)
        tk.Label(root, text="Price").grid(row=0, column=9)

        self.id_entry.grid(row=0, column=2)
        self.name_entry.grid(row=0, column=5)
        self.qty_entry.grid(row=0, column=7)
        self.price_entry.grid(row=0, column=10)

        self.id_entry.bind("<Return>", lambda e: self.name_entry.focus())
        self.name_entry.bind("<Return>", lambda e: self.qty_entry.focus())
        self.qty_entry.bind("<Return>", lambda e: self.price_entry.focus())
        self.price_entry.bind("<Return>", lambda e: self.add_item())

        tk.Button(root, text="Add", command=self.add_item).grid(row=0, column=11)

        tk.Label(root, text="").grid(row=1,rowspan=3)

        tk.Button(root, text="Update", command=self.update_item).grid(row=7, column=13)
        tk.Button(root, text="Delete", command=self.delete_item).grid(row=10, column=13)

        tk.Button(root, text="Export to CSV", command=self.export_csv).grid(row=14, column=5)

        tk.Label(root, text="").grid(row=5)

        self.tree = ttk.Treeview(root, columns=("ID", "Name", "Qty", "Price", "User"), show="headings", selectmode="extended")
        self.tree.heading("ID", text="ID")
        self.tree.heading("Name", text="Item Name")
        self.tree.heading("Qty", text="Quantity")
        self.tree.heading("Price", text="Price")
        self.tree.heading("User", text="User")
        self.tree.grid(row=6, column=1, rowspan=7, columnspan=11)
        self.tree.bind("<ButtonRelease-1>", self.load_selected)

        tk.Label(root, text="").grid(row=13)
        tk.Label(root, text="").grid(column=12)
        tk.Label(root, text="").grid(column=14)

        tk.Button(root, text="Logout", command=self.logout, bg="red", fg="white").grid(row=14, column=13)
        if self.role == "admin":
            tk.Button(root, text="Reset Inventory", bg="red", fg="white", command=self.reset_inventory).grid(row=14, column=10)
        tk.Label(root, text="Search").grid(row=14, column=1)
        self.search_entry = tk.Entry(root)
        self.search_entry.grid(row=14, column=2)
        self.search_entry.bind("<Return>", lambda e: self.search_items())
        self.search_entry.bind("<KeyRelease>", lambda e: self.on_search_keyrelease())
        tk.Button(root, text="Search", command=self.search_items).grid(row=14, column=1)

        tk.Label(root, text="").grid(row=15)

        self.load_data()

    def reload_inventory_table(self):
        self.tree.delete(*self.tree.get_children())
        if self.role == 'admin':
            query = "SELECT id, item_name, quantity, price, username FROM inventory"
            cursor.execute(query)
        else:
            query = "SELECT id, item_name, quantity, price, username FROM inventory WHERE username = ?"
            cursor.execute(query, (self.username,))
    
        for row in cursor.fetchall():
            self.tree.insert("", "end", values=row)

    def on_search_keyrelease(self):
        search_text = self.search_entry.get().strip()
        if search_text == "":
            self.reload_inventory_table()  # or whatever method reloads the full table

    def load_data(self):
        self.tree.delete(*self.tree.get_children())
        if self.role == 'admin':
            for row in cursor.execute("SELECT id, item_name, quantity, price, username FROM inventory"):
                self.tree.insert("", "end", values=row)
        else:
            for row in cursor.execute("SELECT id, item_name, quantity, price, username FROM inventory WHERE username = ?", (self.username,)):
                self.tree.insert("", "end", values=row)

    def load_selected(self, event):
        selected = self.tree.focus()
        values = self.tree.item(selected, 'values')
        if values:
            self.id_entry.delete(0, tk.END)
            self.id_entry.insert(0, values[0])
            self.name_entry.delete(0, tk.END)
            self.name_entry.insert(0, values[1])
            self.qty_entry.delete(0, tk.END)
            self.qty_entry.insert(0, values[2])
            self.price_entry.delete(0, tk.END)
            self.price_entry.insert(0, values[3])

    def add_item(self):
        try:
            cursor.execute("INSERT INTO inventory (id, item_name, quantity, price, username) VALUES (?, ?, ?, ?, ?)",
               (self.id_entry.get(), self.name_entry.get(), self.qty_entry.get(), self.price_entry.get(), self.username))
            conn.commit()
            self.load_data()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "ID already exists or invalid input.")

    def update_item(self):
        selected = self.tree.focus()
        values = self.tree.item(selected, 'values')
        if values:
            cursor.execute("UPDATE inventory SET id=?, item_name=?, quantity=?, price=? WHERE id=?",
                           (self.id_entry.get(), self.name_entry.get(), self.qty_entry.get(), self.price_entry.get(), values[0]))
            conn.commit()
            self.load_data()

    def delete_item(self):
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showerror("Error", "No items selected to delete")
            return

        confirm = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete {len(selected_items)} item(s)?")
        if not confirm:
            return

        for item in selected_items:
            values = self.tree.item(item, 'values')
            if values:
                if self.role == 'admin' or values[4] == self.username:
                    cursor.execute("DELETE FROM inventory WHERE id=?", (values[0],))
            else:
                messagebox.showwarning("Permission Denied", f"You can't delete item ID {values[0]} owned by another user.")

        conn.commit()
        self.load_data()

    def search_items(self):
        search_text = self.search_entry.get()
        self.tree.delete(*self.tree.get_children())

        query = (
            "SELECT id, item_name, quantity, price, username FROM inventory "
            "WHERE (id LIKE ? OR item_name LIKE ? OR quantity LIKE ? OR price LIKE ?)"
        )
        params = [f"%{search_text}%"] * 4

        # Add user filter if not admin
        if self.role != 'admin':
            query += " AND username = ?"
            params.append(self.username)

        for row in cursor.execute(query, params):
            self.tree.insert("", "end", values=row)


    def export_csv(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if file_path:
            with open(file_path, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["ID", "Item Name", "Quantity", "Price"])
                for row in cursor.execute("SELECT id, item_name, quantity, price, username FROM inventory" +("" if self.role == 'admin' else " WHERE username = ?"),(self.username,) if self.role != 'admin' else ()):
                    writer.writerow(row)
            messagebox.showinfo("Exported", "Inventory exported successfully!")

    def logout(self):
        self.root.destroy()
        root = tk.Tk()
        LoginApp(root)
        root.mainloop()

    def reset_inventory(self):
        confirm = messagebox.askyesno("Confirm Reset", "This will delete all inventory items.\nDo you want to continue?")
        if confirm:
            cursor.execute("DELETE FROM inventory")
            self.conn.commit()
            self.load_data()
            messagebox.showinfo("Reset Complete", "Inventory has been cleared.")

if __name__ == "__main__":
    root = tk.Tk()
    app = LoginApp(root)
    root.mainloop()
