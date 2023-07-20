from dotenv import load_dotenv
import os

load_dotenv()

my_password = os.getenv("Password")
print(f"Password:{my_password}")