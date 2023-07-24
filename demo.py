# from dotenv import load_dotenv
# import os

# load_dotenv()

# my_password = os.getenv("Password")
# print(f"Password:{my_password}")

import bcrypt

password = "$2b$10$1W30Pdp2K5RHTVu1vj2FnOm/GJkZ8je/Nxi4mNmW.0RZ1kBFuPs6a"

# Generate a salt and hash the password
hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Print the hashed password
print(hashed_password.decode('utf-8'))