import json
import random
import time
import bcrypt
from getpass import getpass 
import os 
import cryptography 
from cryptography.fernet import Fernet

# Define constants for file storage
Password_File = "Passwordfile.json" # JSON file to store encrypted passwords
LOGIN_PASSWORD_FILE ="login_password.txt"
Max_ATTEMPTS = 3 # Maximum failed login attempts before lockout
LOCKOUT_TIME = 30 # Lockout time in seconds after too many failed attempts


# Function to generate an encryption key
def gen_key(): 
    key = Fernet.generate_key() # Generates a new key
    with open ("key.key","wb") as key_file: #Creates/opens a file name key.key and then writes binary
        key_file.write(key) # Writes the genersted "key" into the "key.key"
        
# Function to load the encryption key from file
def load_key():
    if not os.path.exists("key.key"): # Check if "key.key" exists
        gen_key() # Generate a new encryption key if missing
        


    with open("key.key","rb") as key_file:   # Open the key file in binary read mode
        return key_file.read()   # Return the encryption key for use
    
# Load the encryption key and create an encryption object
key = load_key() # calls the function load_key and then stores it to a varaible "key"
locker = Fernet(key)  # Initialize the Fernet encryption system

# Function to encrypt a password before storing it
def encrypt_password (password): 
    encrypted_password = locker.encrypt(password.encode())  # Encrypt the password
    return encrypted_password.decode() # Convert encrypted bytes to string for storage

# Function to decrypt a stored encrypted password
def decrypt_password(encrypted_password):  # Decrypt the password
    decrypted_password = locker.decrypt(encrypted_password)
    return decrypted_password.decode() # Convert decrypted bytes back to a string


# Function to store a password securely in the password file
def save_password(service,password):

    #Creates in json file if it doeant exists
    if not os.path.exists(Password_File):
        with open (Password_File,"w") as file:
            json.dump({},file)  # Initialize the file with an empty dictionary

    #Load passords from file into a vairable 
    with open(Password_File,"r") as file:
        Passwords = json.load(file)  # Read existing stored passwords
    
    #Encrypt and store the new password
    Passwords[service]=encrypt_password(password)

    # This now saves the updated encrypted data back to the file 
    with open (Password_File,"w") as file:
        json.dump(Passwords,file,indent=4)  # Save encrypted passwords in JSON format
    
    print(f"Password for {service} saved securely!")


# Function to retrieve a stored password   
def get_pass(service):
    if not os.path.exists(Password_File): # Check if password file exists
        return print("No Stored Password found")
    
 # Load passwords from the JSON file
    with open (Password_File,"r") as file :
        passwords = json.load(file )
# Retrieve the encrypted password for the given service    
    encrypted_password = passwords.get(service)

    if encrypted_password:
        decrypted = decrypt_password(encrypted_password) # Decrypt the password
        return print(f"Here is the Password to {service}: {decrypted}")
    
    else:
        return print(f"Password not found for {service}")
# Function to set and store a new login password securely
def set_password ():
    login_password= getpass("\nSet your new login password: ").encode() # Prompt user to enter a new password
    hashed_password =  bcrypt.hashpw(login_password, bcrypt.gensalt()) # Hash the password using bcrypt

    # Store the hashed password in a file
    with open (LOGIN_PASSWORD_FILE,"wb") as file:
        file.write(hashed_password)

    print("Login password set successfully!")
    
# Function to authenticate the user with the login password
def checking_login_pass():
    if not os.path.exists(LOGIN_PASSWORD_FILE): # Check if the login password file exists
        print(" No login password set. Please create one first.")
        set_password() # Prompt user to set a new password
        return True
    attempts = 0  # Track the number of failed login attempts
    while attempts < Max_ATTEMPTS :

        inputpass = getpass("\nEnter Login Password: ").encode()  # Prompt user for password
    
        with open (LOGIN_PASSWORD_FILE,"rb") as file:
            stored_pass = file.read()  # Read the stored hashed password
    
        if bcrypt.checkpw(inputpass,stored_pass):  # Compare entered password with stored hash
            print("Authentication successful! Access granted.")
            return True
        else :
            attempts += 1
            Remaing_Attempts = Max_ATTEMPTS - attempts
            print(f"Incorrect password. {Remaing_Attempts} attempts remaining.")
    Lock_out_duration= LOCKOUT_TIME * random.uniform(1, 2)# Randomize lockout duration
    print(f"\nToo many failed attempts. Locking out for {Lock_out_duration:.2f} seconds...")  # Lock user out for a period of time
    time.sleep(Lock_out_duration)   # Return False to indicate authentication failure
    return False
        
    

# Function to display the menu and manage user choices        
    
def main():
    while True:
        print("\n   Secure Password Manager\n")

        print("1. Store a new Password")
        print("2. Retrieve a password")
        print("3. Reset login password")
        print("4. Exit")

        choice =  input("Enter Choice 1,2,3 or 4: ")

        while not choice.isdigit():# Ensure user input is a number
            print("Invalid input. Please enter a number.")
            choice =  input("Enter Choice 1,2,3 or 4: ")
        choice = int (choice)

        if choice == 1 :
            service = input("Enter service name. Eg gmail.com: ")
            password = getpass(f"Enter Password for {service}: ")
            save_password(service,password)  # Save encrypted password
        
        elif choice == 2:
            service = input("Enter service name. Eg gmail.com: ")
            get_pass(service)   # Retrieve and decrypt password
            

        elif choice == 3:
            confirm = input("Are you sure you want to reset your login password? (yes/no): " )
            if confirm.lower() == "yes":  # Ensure confirmation is case-insensitive
                set_password()  # Reset the login password
            else : 
                print("Login password reset canceled.")

        elif choice == 4:
            print (f"Exiting Password Manager...") # Exit the program
            break

        else :
            print ("Invalid Choice. (Try 1,2,3 or 4) ")



# Program execution starts here
if __name__ =="__main__":  # Authenticate the user before granting access
    if checking_login_pass():
          main()
    else:
        exit() # Exit the program if authentication fails


