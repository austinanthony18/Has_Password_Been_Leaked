# Has_Password_Been_Leaked
This Python application provides a graphical user interface (GUI) to check the strength of a password and determine if it has been leaked in any known data breaches. The application uses the tkinter library for the GUI and integrates with the Have I Been Pwned API to check for password leaks.

# Features

Password Strength Evaluation: 
  Calculates the entropy of the password to determine its strength, categorizing it as Very Weak, Weak, Moderate, Strong, or Very   Strong.

Password Leak Check: 
  Uses the Have I Been Pwned API to check if the password has been exposed in any known data breaches.

Brute Force Time Estimation: 
  Estimates the time required to brute-force the password using various cracking methods.

User-Friendly GUI: 
  Provides an easy-to-use graphical interface for entering passwords and viewing results.

  # How To Use

  1. Clone the Repository: https://github.com/austinanthony18/Has_Password_Been_Leaked.git

  2. Install Dependencies: pip install requests

  3. Run: python hasPasswordBeenLeaked.py

