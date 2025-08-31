# Secure Vault

A clean and simple password manager that creates unique email aliases for each service you sign up for.

## What it does

- Generates strong passwords automatically
- Creates email aliases using the `+` notation (like `youremail+netflix123@gmail.com`)
- Stores everything locally on your device
- Clean, modern web interface

## Getting started

1. Install the requirements:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python run.py
```

3. Open your browser and go to `http://localhost:5001`

4. Set up your master email and password on first run

## How it works

When you add a new service (like Netflix), Secure Vault will:
- Create a unique email alias based on your master email
- Generate a strong random password
- Save both securely to your local database

This way, each service gets its own unique email and password, making your accounts more secure and easier to manage.

## Features

- **Email aliases**: Each service gets a unique email like `yourname+service123@gmail.com`
- **Strong passwords**: Auto-generated passwords with mixed characters
- **Local storage**: Everything stays on your device
- **Search**: Quickly find saved credentials
- **Clean UI**: Modern, easy-to-use interface

## Security

- Master password protects your vault
- All data stored locally (SQLite database)
- Passwords are hashed for storage
- No data leaves your device

That's it! Simple password management with email privacy built in.
