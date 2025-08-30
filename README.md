Title: Automated Python File Organizer

Description:
A Python-based automation tool for organizing files into folders based on type or custom rules. This project also includes logging, email notifications for virus detection, and secure configuration using
environment variables.

Features:

1. Automated File Organization: Automatically sorts files into folders based on type, name, or custom rules.
2. Logging: Keeps detailed logs of all actions performed for tracking and debugging.
3. Email Notifications: Sends email alerts if a virus or suspicious file is detected, and can also confirm when the organization process is completed successfully.
4. Secure Configuration: Uses .env files to safely store sensitive data like passwords and email credentials.

Setup Instructions:

Copy the example .env file:
Either run cp .env.example .env or create a new .env and copy contents from .env.example.

Fill in your own values in .env:

APP_PASSWORD=your_app_password_here
EMAIL_SENDER=your_email@example.com
EMAIL_RECEIVER=receiver_email@example.com
AUTH_PASSWORD=your_auth_password_here

Install any dependencies if needed:

pip install -r requirements.txt
Run the project:
python automation.py

Important Notes:

Do NOT commit your actual .env file to GitHub. Only .env.example should be pushed.
Adjust the rules in the script according to your file organization needs.

Example in Action:
Suppose you have a folder with these files:
report1.pdf
photo1.jpg
notes.txt
presentation.pptx

When you run the Automated Python File Organizer, it will automatically create folders like PDFs, Images, Text Files, and Presentations, and move the files into the correct folders:

PDFs → report1.pdf
Images → photo1.jpg
Text Files → notes.txt
Presentations → presentation.pptx

If a virus or suspicious file is detected during scanning, an email notification will be sent to alert you immediately. Otherwise, an email may also confirm that the file organization process was completed 
successfully.
