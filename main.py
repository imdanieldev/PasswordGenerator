import subprocess

choice = input("Cli or Gui? (1/2): ").strip()

if choice == "1":
    subprocess.run(["python", "clipass.py"])
elif choice == "2":
    subprocess.run(["python", "guipass.py"])
else:
    print("error")
