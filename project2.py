import csv
import bcrypt
import re
import requests
import sys
import logging

# Constants
MAX_LOGIN_ATTEMPTS = 5
USER_DATA_FILE = "cridentials.csv"
LOG_FILE = "application.log"  # Log file name
ALPHA_VANTAGE_API_KEY = "3M42QWJEAKCTCHUP"  # Use your own API key here
ALPHA_VANTAGE_BASE_URL = "https://www.alphavantage.co/query"

# --- Setup Logging ---
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- Helper Functions ---

def hash_password(password):
    """Hash the password using bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(hashed_password, user_password):
    """Check the password entered by the user."""
    return bcrypt.checkpw(user_password.encode(), hashed_password)

def validate_email(email):
    """Validate the email format."""
    email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    return re.match(email_regex, email) is not None

def validate_password(password):
    """Ensure password meets the required criteria."""
    if (len(password) < 8 or
        not re.search(r"[A-Z]", password) or
        not re.search(r"[a-z]", password) or
        not re.search(r"[0-9]", password) or
        not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
        return False
    return True

def read_user_data():
    """Load user data from CSV."""
    users = []
    try:
        with open(USER_DATA_FILE, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                users.append(row)
    except FileNotFoundError:
        logging.error("User data file not found.")
    return users

def write_user_data(users):
    """Write user data to CSV."""
    with open(USER_DATA_FILE, mode='w', newline='') as csvfile:
        fieldnames = ['email', 'password', 'security_question', 'security_answer']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for user in users:
            writer.writerow(user)

# --- Login System ---

def login():
    """Handle user login with limited attempts."""
    users = read_user_data()
    attempts = 0

    while attempts < MAX_LOGIN_ATTEMPTS:
        email = input("Enter your email: ")
        password = input("Enter your password: ")

        for user in users:
            if user['email'] == email and check_password(user['password'].encode(), password):
                logging.info(f"User {email} logged in successfully.")
                print("Login successful!")
                return True, user

        attempts += 1
        remaining_attempts = MAX_LOGIN_ATTEMPTS - attempts
        print(f"Incorrect credentials. {remaining_attempts} attempts remaining.")
        logging.warning(f"Failed login attempt for {email}. {remaining_attempts} attempts remaining.")

    logging.error(f"Max login attempts exceeded for {email}.")
    print("Max login attempts exceeded.")
    sys.exit()

# --- Forgot Password ---

def forgot_password():
    """Handle password recovery."""
    users = read_user_data()
    email = input("Enter your registered email: ")

    for user in users:
        if user['email'] == email:
            answer = input(f"Answer security question: {user['security_question']} ")
            if answer == user['security_answer']:
                new_password = input("Enter your new password: ")
                if validate_password(new_password):
                    user['password'] = hash_password(new_password).decode()  # Update hashed password
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

# --- Stock Market API Integration ---

def fetch_stock_data(ticker_symbol):
    """Fetch stock data using Alpha Vantage API."""
    url = f"{ALPHA_VANTAGE_BASE_URL}?function=TIME_SERIES_INTRADAY&symbol={ticker_symbol}&interval=1min&apikey={ALPHA_VANTAGE_API_KEY}"
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
        latest_data = next(iter(data['Time Series (1min)'].values()))
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

# --- Main Application Flow ---

def main():
    while True:
        print("\n--- Welcome to Stock Market Console ---")
        print("1. Login")
        print("2. Forgot Password")
        print("3. Exit")

        choice = input("Choose an option: ")

        if choice == '1':
            success, user = login()
            if success:
                ticker = input("Enter the ticker symbol (e.g., AAPL for Apple): ")
                stock_data = fetch_stock_data(ticker)
                if stock_data:
                    print(f"\nStock Data for {ticker}:")
                    print(f"Current Price: {stock_data['current_price']}")
                    print(f"Open Price: {stock_data['open_price']}")
                    print(f"High Price: {stock_data['high_price']}")
                    print(f"Low Price: {stock_data['low_price']}")
                    print(f"Volume: {stock_data['volume']}")
        elif choice == '2':
            forgot_password()
        elif choice == '3':
            logging.info("Application exited.")
            print("Goodbye!")
            sys.exit()
        else:
            logging.warning(f"Invalid option selected: {choice}.")
            print("Invalid option. Please choose again.")

if __name__ == "__main__":
    main()
