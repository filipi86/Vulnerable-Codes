# Example of vulnerable Python code with secrets in clear text

api_key = "12345-abcde-SECRET-54321"
db_password = "password123"

def get_secret():
    return api_key

def connect_to_db():
    return f"Connecting to database with password: {db_password}"

if __name__ == "__main__":
    print(get_secret())
    print(connect_to_db())