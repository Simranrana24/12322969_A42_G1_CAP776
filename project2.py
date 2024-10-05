import csv
import bcrypt
import re
import requests
import sys
import logging

max_login_attempts = 5
csv_file = "credentials.csv"  
log_file = "application.log"  
My_API_key = "G25WS5RCBIPIP3MW" 
Base_URL = "https://www.alphavantage.co/query"

logging.basicConfig(filename=log_file, level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode(), hashed_password)

def validate_email(email):
    email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    return re.match(email_regex, email) is not None

def validate_password(password):
    if (len(password) < 8 or
        not re.search(r"[A-Z]", password) or
        not re.search(r"[a-z]", password) or
        not re.search(r"[0-9]", password) or
        not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
        return False
    return True

def read_user_data():
    users = []
    try:
        with open(csv_file, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                users.append(row)
    except FileNotFoundError:
        logging.error("User data file not found.")
    return users

def write_user_data(users):
    with open(csv_file, mode='w', newline='') as csvfile:
        fieldnames = ['email', 'password', 'security_question', 'security_answer']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for user in users:
            writer.writerow(user)

def check_email_exists(email):
    users = read_user_data()
    for user in users:
        if user['email'] == email:
            return True
    return False

def sign_up():
    users = read_user_data()
    
    email = input("Enter your email: ")
    if not validate_email(email):
        logging.warning(f"Failed to sign up: {email}.")
        print("Invalid email format.")
        return
    
    if check_email_exists(email):
        logging.warning(f"Sign-up failed: Email {email} already exists.")
        print("This email is already registered.")
        return

    password = input("Create a password: ")
    if not validate_password(password):
        logging.warning(f"Sign-up failed for {email} due to invalid password format.")
        print("Password must be at least 8 characters, contain an uppercase letter, a lowercase letter, a number, and a special character.")
        return
    
    security_question = input("Enter a security question (for password recovery): ")
    security_answer = input("Enter the answer to your security question: ")
    
    new_user = {
        'email': email,
        'password': hash_password(password).decode(),
        'security_question': security_question,
        'security_answer': security_answer
    }
    users.append(new_user)
    write_user_data(users)
    
    logging.info(f"User {email} signed up successfully.")
    print("Signed-up successfully! You can now log in.")

def login():
    users = read_user_data()
    attempts = 0

    while attempts < max_login_attempts:
        email = input("Enter your email: ")
        password = input("Enter your password: ")

        for user in users:
            if user['email'] == email and check_password(user['password'].encode(), password):
                logging.info(f"User {email} logged in successfully.")
                print("Login successful!")
                return True, user

        attempts += 1
        remaining_attempts = max_login_attempts - attempts
        print(f"Incorrect credentials. {remaining_attempts} attempts remaining.")
        logging.warning(f"Failed login attempt for {email}. {remaining_attempts} attempts remaining.")

    logging.error(f"Max login attempts exceeded for {email}.")
    print("Max login attempts exceeded.")
    sys.exit()

def forgot_password():
    users = read_user_data()
    email = input("Enter your registered email: ")

    for user in users:
        if user['email'] == email:
            answer = input(f"Answer security question: {user['security_question']} ")
            if answer == user['security_answer']:
                new_password = input("Enter your new password: ")
                if validate_password(new_password):
                    user['password'] = hash_password(new_password).decode()  
                    write_user_data(users)
                    logging.info(f"Password reset successfully for {email}.")
                    print("Password reset successfully.")
                else:
                    logging.warning(f"Password reset failed for {email} due to invalid password format.")
                    print("Password does not meet criteria.")
                return
            else:
                logging.warning(f"Incorrect security answer for {email}.")
                print("Incorrect security answer.")
                return

    logging.error(f"Password reset failed. Email not found: {email}.")
    print("Email not found.")

def fetch_stock_data(ticker_symbol):
    """Fetch daily stock data using Alpha Vantage API."""
    url = f"{Base_URL}?function=TIME_SERIES_DAILY&symbol={ticker_symbol}&apikey={My_API_key}"
    response = requests.get(url)

    if response.status_code != 200:
        logging.error(f"Failed to retrieve stock data for {ticker_symbol}. Status Code: {response.status_code}.")
        print("Failed to retrieve data. Check your network connection.")
        return None

    data = response.json()

    if "Error Message" in data:
        logging.warning(f"Invalid ticker symbol: {ticker_symbol}.")
        print("Invalid ticker symbol.")
        return None

    try:
        
        latest_date = next(iter(data['Time Series (Daily)']))
        latest_data = data['Time Series (Daily)'][latest_date]
        stock_info = {
            'current_price': latest_data['4. close'],
            'open_price': latest_data['1. open'],
            'high_price': latest_data['2. high'],
            'low_price': latest_data['3. low'],
            'volume': latest_data['5. volume'],
        }
        logging.info(f"Stock data retrieved for {ticker_symbol}.")
        return stock_info
    except KeyError:
        logging.error(f"Data not available for {ticker_symbol}.")
        print("Data not available.")
        return None

def main():
    while True:
        print("\n Hey this is my stock market application project")
        print("Sign Up")
        print("Login")
        print("Forgot Password")
        print("Exit")

        option = input("Choose an option: ")

        if option == '1':
            sign_up()
        elif option == '2':
            success, user = login()
            if success:
                ticker = input("Enter the ticker symbol: ")
                stock_data = fetch_stock_data(ticker)
                if stock_data:
                    print(f"\nStock Data for {ticker}:")
                    print(f"Current Price: {stock_data['current_price']}")
                    print(f"Open Price: {stock_data['open_price']}")
                    print(f"High Price: {stock_data['high_price']}")
                    print(f"Low Price: {stock_data['low_price']}")
                    print(f"Volume: {stock_data['volume']}")
        elif option == '3':
            forgot_password()
        elif option == '4':
            logging.info("Application exited.")
            print("Goodbye!")
            sys.exit()
        else:
            logging.warning(f"Invalid option selected: {option}.")
            print("Invalid option. Please choose again.")

if __name__ == "__main__":
    main()
