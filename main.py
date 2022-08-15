import string
import random
import pyperclip
from colorama import Fore,Back, Style
q = input("Read Password (Y/N): ").lower()
if q == "y":
     f = open("PASSWORDS", "r")
     print(Back.WHITE + Fore.BLACK + f.read())
     print(Style.RESET_ALL)
     f.close()
else:
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
     str = input("Copy Password (Y/N): ").lower()
     if str == "y":
          pyperclip.copy(password)
          print("Copyed")
     else:
          print("OK")
     str = "" 
     str = input("Saved This Password (Y/N): ").lower()
     if str == "y":
          answer = input("What Is Your Platform: ")
          if answer == "":
               answer = "No Platform"
          file = open("PASSWORDS","a")
          file.write("\n\n"+answer + ": \n"+password)
          file.close()
