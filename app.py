import streamlit as st
from PIL import Image
import pytesseract
from transformers import pipeline
from datetime import datetime, timedelta
import sqlite3
import os
import re
import hashlib
import matplotlib.pyplot as plt

# --- SETUP ---
if not os.path.exists("data"):
    os.makedirs("data")

conn = sqlite3.connect("data/users.db", check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                email TEXT,
                password TEXT
            )''')
c.execute('''CREATE TABLE IF NOT EXISTS food (
                user TEXT,
                item TEXT,
                expiry TEXT,
                manufacture TEXT,
                days_left INTEGER
            )''')
conn.commit()

# --- MODELS ---
ocr_model = pytesseract
llm_model = pipeline("text2text-generation", model="google/flan-t5-base")

# --- FUNCTIONS ---
def extract_text(image: Image.Image):
    return ocr_model.image_to_string(image)

def extract_food_info(text):
    prompt = f"Extract food name, expiry date and manufacture date from: {text}"
    result = llm_model(prompt, max_length=50, do_sample=False)
    return result[0]['generated_text']

def parse_dates(info_text):
    name = re.findall(r"(?i)food[:\-\s]*([A-Za-z0-9 ]+)", info_text)
    mfg = re.findall(r"(?i)mfg[:\-\s]*(\d{2}/\d{2}/\d{4}|\d{4}-\d{2}-\d{2})", info_text)
    exp = re.findall(r"(?i)exp[:\-\s]*(\d{2}/\d{2}/\d{4}|\d{4}-\d{2}-\d{2})", info_text)
    return name[0] if name else "Unknown", mfg[0] if mfg else "", exp[0] if exp else ""

def calculate_days_left(expiry_str):
    for fmt in ("%d/%m/%Y", "%Y-%m-%d"):
        try:
            expiry = datetime.strptime(expiry_str, fmt)
            return (expiry - datetime.now()).days
        except:
            continue
    return -1

def insert_food(user, item, expiry, manufacture):
    days = calculate_days_left(expiry)
    c.execute("SELECT * FROM food WHERE user=? AND item=? AND expiry=?", (user, item, expiry))
    if not c.fetchone():
        c.execute("INSERT INTO food (user, item, expiry, manufacture, days_left) VALUES (?, ?, ?, ?, ?)",
                  (user, item, expiry, manufacture, days))
        conn.commit()

def get_user_food(user):
    c.execute("SELECT item, expiry, days_left FROM food WHERE user=? ORDER BY days_left ASC", (user,))
    return c.fetchall()

def delete_expired_items(user):
    c.execute("DELETE FROM food WHERE user=? AND days_left < 0", (user,))
    conn.commit()

def add_manual_item(user, item, category):
    today = datetime.now()
    if category == "vegetable":
        expiry = today + timedelta(days=10)
    elif category == "fruit":
        expiry = today + timedelta(days=14)
    elif item.lower() in ["potato", "onion"]:
        expiry = today + timedelta(days=20)
    else:
        expiry = today + timedelta(days=7)
    insert_food(user, item, expiry.strftime("%d/%m/%Y"), today.strftime("%d/%m/%Y"))

def get_recipe_suggestions(available_items):
    joined = ", ".join(available_items)
    prompt = f"Suggest 5 simple recipes using: {joined}"
    result = llm_model(prompt, max_length=250, do_sample=False)
    return result[0]['generated_text']

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def is_strong_password(password):
    return (len(password) >= 8 and
            re.search(r"[A-Z]", password) and
            re.search(r"[a-z]", password) and
            re.search(r"[0-9]", password) and
            re.search(r"[@#$%^&+=]", password))

def register_user(username, email, password):
    if not is_valid_email(email):
        return "Invalid email format. Please enter a valid email address."
    if not is_strong_password(password):
        return "Password must be at least 8 characters with uppercase, lowercase, number, and special character."
    hashed_pw = hash_password(password)
    try:
        c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, hashed_pw))
        conn.commit()
        return "Success"
    except:
        return "Username already exists."

def login_user(username, password):
    hashed_pw = hash_password(password)
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_pw))
    return c.fetchone()

# --- APP CONFIG ---
st.set_page_config(page_title="Food Expiry Reminder", layout="wide")

# --- HOMEPAGE / INTRO ---
st.markdown("""
## 🏠 Welcome to the Food Expiry Reminder App

This app helps you stay on top of your food inventory by:
- 📅 Reminding you of upcoming food expiry dates.
- 📸 Scanning food labels using image recognition to auto-extract expiry info.
- 🥕 Manually adding fresh produce like vegetables and fruits with preset shelf lives.
- 🍳 Generating personalized **recipe suggestions** using your current ingredients.

### 👤 Features:
- **Login/Register**: Securely create an account and manage your food list.
- **Dashboard**: View and manage your food items, sorted by urgency.
- **Recipe Generator**: Get meal ideas using what you already have.

Login or register to get started below 👇
""")

# --- AUTH ---
if 'user' not in st.session_state:
    mode = st.radio("Login or Register", ["Login", "Register"])
    if mode == "Register":
        new_user = st.text_input("Username")
        new_email = st.text_input("Email")
        new_pass = st.text_input("Password", type="password")
        st.markdown("""
        <ul>
        <li>Email should be valid (e.g., user@example.com)</li>
        <li>Password must include at least 8 characters, 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character (@#$%^&+=)</li>
        </ul>
        """, unsafe_allow_html=True)
        if st.button("Register"):
            result = register_user(new_user, new_email, new_pass)
            if result == "Success":
                st.success("Registered successfully. Please log in.")
            else:
                st.error(result)
        st.stop()
    else:
        user = st.text_input("Username")
        pw = st.text_input("Password", type="password")
        if st.button("Login"):
            if login_user(user, pw):
                st.session_state.user = user
                st.rerun()
            else:
                st.error("Invalid username or password")
        st.stop()

# --- MAIN APP ---
user = st.session_state.user

# Tabs for navigation
page = st.radio("Go to", ["Dashboard", "Recipe Generator", "List of Items"])

if page == "Dashboard":
    st.sidebar.header("Upload Food Image")
    uploaded_file = st.sidebar.file_uploader("Upload Image", type=['png', 'jpg', 'jpeg'])
    if uploaded_file:
        image = Image.open(uploaded_file)
        text = extract_text(image)
        info = extract_food_info(text)
        item, mfg, exp = parse_dates(info)
        insert_food(user, item, exp, mfg)
        st.sidebar.success(f"Added: {item} | EXP: {exp}")

    st.sidebar.header("Add Item Manually")
    manual_item = st.sidebar.text_input("Food Name")
    category = st.sidebar.selectbox("Category", ["vegetable", "fruit", "other"])
    if st.sidebar.button("Add Food"):
        add_manual_item(user, manual_item, category)
        st.sidebar.success(f"Added {manual_item} as {category}")

    st.subheader("📦 Your Food Inventory")
    foods = get_user_food(user)
    if foods:
        for item, exp, days in foods:
            if days < 0:
                color = "⚫ EXPIRED"
            elif days < 7:
                color = "🔴 URGENT"
            elif days < 14:
                color = "🟠 Soon"
            else:
                color = "🟢 Fresh"
            st.write(f"**{item}** - Expires on: {exp} | Days left: {days} {color}")
        if st.button("Delete Expired Items"):
            delete_expired_items(user)
            st.success("Expired items deleted.")

        st.subheader("📊 Expiry Stats")
        labels = ["Expired", "<7 Days", "<14 Days", "Fresh"]
        counts = [
            sum(1 for f in foods if f[2] < 0),
            sum(1 for f in foods if 0 <= f[2] < 7),
            sum(1 for f in foods if 7 <= f[2] < 14),
            sum(1 for f in foods if f[2] >= 14)
        ]
        fig1, ax1 = plt.subplots()
        ax1.pie(counts, labels=labels, autopct='%1.1f%%', startangle=90)
        ax1.axis('equal')
        st.pyplot(fig1)

        fig2, ax2 = plt.subplots()
        ax2.bar(labels, counts, color=['black', 'red', 'orange', 'green'])
        ax2.set_title("Items by Expiry Status")
        st.pyplot(fig2)
    else:
        st.info("No items found. Upload an image or add manually.")

elif page == "Recipe Generator":
    st.subheader("🍳 Get Recipe Ideas")
    foods = get_user_food(user)
    if st.button("Suggest Recipes with My Items"):
        my_items = [i[0] for i in foods if i[2] > 0]
        if my_items:
            suggestions = get_recipe_suggestions(my_items)
            st.success(suggestions)
        else:
            st.warning("Add at least one unexpired item to get recipe suggestions.")

elif page == "List of Items":
    st.subheader("📋 List of All Food Items (by Expiry Date)")
    foods = get_user_food(user)
    if foods:
        for item, exp, days in foods:
            st.write(f"**{item}** - Expires on: {exp} | Days left: {days}")
    else:
        st.info("No food items available to list.")
