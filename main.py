import string
import random
import pyperclip
from colorama import Fore, Style
lowercase = string.ascii_lowercase
uppercase = string.ascii_uppercase
numbers = string.digits
i = 0
password = ""
arr = lowercase + uppercase + numbers
while i < 20:
     password += random.choice(arr)
     i+= 1

print(Fore.GREEN + password)
print(Style.RESET_ALL)
str = input("Copy Password (Y/N): ")
if str == "Y":
     pyperclip.copy(password)
     print("Copyed")
else: 
     print("Ok")