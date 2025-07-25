# 📦 Inventory Management System

A fully functional desktop-based **Inventory Management System** built with **Python Tkinter** and **SQLite**. Designed with an intuitive interface and robust backend, this app lets you manage products seamlessly — including **add, update, delete, search, filter, export**, and even secure access via **login-based user roles**.

---

## 🔧 Features

### ✅ Inventory Operations
- **Add Items**: Input item ID, name, quantity, price, category, etc.
- **Update Items**: Edit details of any selected inventory item.
- **Delete Items**: Remove unwanted entries with a click.
- **Search & Filter**: Dynamic search as you type; filters by name, ID, or category.
- **Reset Inventory**: Delete all the entries (only for Admin)

### 👥 Login System
- **Role-based Access**:  
  - `admin`: Full control (CRUD + User management)  
  - `user`: Can only do entries but can't see other user entries
- **Password Hashing**: Secure login with encrypted credentials.
- **Login Validation**: Wrong credentials? You're blocked for 5 mins.

### 📊 Export to CSV
- Export the current inventory table to a clean, formatted CSV for reports or backup.

### Login with:

-Username: admin

-Password: admin123 (Default credentials; change inside DB)

-After login, the dashboard opens up with full access to inventory management.

## Steps

### 1️⃣ Clone the Repository
**git clone https://github.com/Vasu1203/Inventory-Management-App.git**

### 2️⃣ Create a virtual environment (only once)
**python -m venv venv**

### 3️⃣ Install Dependencies
**pip install -r requirements.txt**

### 4️⃣Activate the virtual environment
**venv\Scripts\activate**

### 5️⃣Now install dependencies
**pip install -r requirements.txt**
