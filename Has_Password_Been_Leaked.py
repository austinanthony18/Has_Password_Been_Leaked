import tkinter as tk
from tkinter import ttk
import string
import hashlib
import requests
import math
import time

def check_password_leak(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5, tail = sha1_password[:5], sha1_password[5:]
    response = requests.get(f'https://api.pwnedpasswords.com/range/{first5}')
    hashes = (line.split(':') for line in response.text.splitlines())
    for hash, count in hashes:
        if tail == hash:
            return True, count
    return False, 0

def get_breach_info(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    response = requests.get(f'https://api.pwnedpasswords.com/pwnedpassword/{sha1_password}')
    if response.status_code == 200:
        return response.json()
    return []

def calculate_entropy(password):
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26  # lowercase letters
    if any(c.isupper() for c in password):
        charset_size += 26  # uppercase letters
    if any(c.isdigit() for c in password):
        charset_size += 10  # digits
    if any(c in string.punctuation for c in password):
        charset_size += len(string.punctuation)  # special characters

    if charset_size == 0:
        return 0  # No valid characters in password

    entropy = len(password) * math.log2(charset_size)
    return entropy

def evaluate_password_strength(password):
    entropy = calculate_entropy(password)
    if entropy < 28:
        return 'Very Weak', 20
    elif entropy < 36:
        return 'Weak', 40
    elif entropy < 60:
        return 'Moderate', 60
    elif entropy < 128:
        return 'Strong', 80
    else:
        return 'Very Strong', 100

def calculate_brute_force_time(password, method):
    guesses_per_second = {
        'SHA-1 (1 billion guesses/sec)': 10**9,
        'SHA-256 (100 million guesses/sec)': 10**8,
        'MD5 (10 billion guesses/sec)': 10**10,
        'bcrypt (10 thousand guesses/sec)': 10**4,
        'GPU-based attack (100 billion guesses/sec)': 10**11,
        'Specialized hardware attack (1 trillion guesses/sec)': 10**12,
    }.get(method, 10**9)  # Default to 1 billion guesses per second if method not found

    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26  # lowercase letters
    if any(c.isupper() for c in password):
        charset_size += 26  # uppercase letters
    if any(c.isdigit() for c in password):
        charset_size += 10  # digits
    if any(c in string.punctuation for c in password):
        charset_size += len(string.punctuation)  # special characters
    total_combinations = charset_size ** len(password)
    seconds = total_combinations / guesses_per_second
    return seconds, total_combinations

def format_time(seconds):
    if seconds < 1:
        return "less than 1 second"
    intervals = (
        ('years', 31536000),  # 60 * 60 * 24 * 365
        ('months', 2592000),  # 60 * 60 * 24 * 30
        ('days', 86400),      # 60 * 60 * 24
        ('hours', 3600),      # 60 * 60
        ('minutes', 60),
        ('seconds', 1),
    )
    result = []
    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            if name == 'years' and value >= 1000000:
                result.append(f"{value / 1000000:.1f} million {name}")
            elif name == 'years' and value >= 1000:
                result.append(f"{value / 1000:.1f} thousand {name}")
            else:
                result.append(f"{value} {name}")
    return ', '.join(result)

def check_password():
    password = entry.get()
    method = method_var.get()
    leaked, count = check_password_leak(password)
    strength, value = evaluate_password_strength(password)
    progress['value'] = value

    if value <= 40:
        progress['style'] = 'Red.Horizontal.TProgressbar'
    elif value <= 80:
        progress['style'] = 'Yellow.Horizontal.TProgressbar'
    else:
        progress['style'] = 'Green.Horizontal.TProgressbar'

    result_text = f'Password strength: {strength}\n'
    if leaked:
        result_text += f'This password has been found in a data leak {count} times. Please choose a different password.'
        breaches = get_breach_info(password)
        if breaches:
            result_text += '\nBreaches:\n'
            for breach in breaches:
                result_text += f"- {breach['Name']}: {breach['Description']}\n"
        formatted_time = "almost immediately"  # Password is already known
        total_combinations = 0  # Not applicable since the password is already known
    else:
        result_text += 'This password has not been found in any data leaks.'
        brute_force_time, total_combinations = calculate_brute_force_time(password, method)
        formatted_time = format_time(brute_force_time)

    # Display brute force time and total combinations
    result_text += f'\n\nBrute-Force checker assumes the following:\n- {method}\n- All possible combinations are tried\n'
    result_text += f'\nEstimated time to brute-force the password:\n{formatted_time}'
    if total_combinations > 0:
        result_text += f'\nTotal combinations to crack the password: {total_combinations:.0f}'

    result_label.config(text=result_text)

def toggle_password():
    if show_password_var.get():
        entry.config(show='')
    else:
        entry.config(show='*')

# Set up the GUI
root = tk.Tk()
root.title('Password Strength Checker')

# Configure styles for the progress bar
style = ttk.Style()
style.theme_use('default')
style.configure('Red.Horizontal.TProgressbar', foreground='red', background='red')
style.configure('Yellow.Horizontal.TProgressbar', foreground='yellow', background='yellow')
style.configure('Green.Horizontal.TProgressbar', foreground='green', background='green')

# Create widgets
entry_label = tk.Label(root, text='Enter your password:')
entry_label.pack(pady=5)

entry = tk.Entry(root, show='*', width=40)
entry.pack(pady=5)

show_password_var = tk.BooleanVar()
show_password_check = tk.Checkbutton(root, text='Show Password', variable=show_password_var, command=toggle_password)
show_password_check.pack()

method_label = tk.Label(root, text='Select cracking method:')
method_label.pack(pady=5)

method_var = tk.StringVar(value='SHA-1 (1 billion guesses/sec)')
method_dropdown = ttk.Combobox(root, textvariable=method_var, values=[
    'SHA-1 (1 billion guesses/sec)',
    'SHA-256 (100 million guesses/sec)',
    'MD5 (10 billion guesses/sec)',
    'bcrypt (10 thousand guesses/sec)',
    'GPU-based attack (100 billion guesses/sec)',
    'Specialized hardware attack (1 trillion guesses/sec)'
])
method_dropdown.pack(pady=5)

check_button = tk.Button(root, text='Check Password', command=check_password)
check_button.pack(pady=5)

progress = ttk.Progressbar(root, orient='horizontal', length=300, mode='determinate')
progress.pack(pady=5)

result_label = tk.Label(root, text='', wraplength=300)
result_label.pack(pady=10)

root.mainloop()
