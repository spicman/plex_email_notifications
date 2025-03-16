Google AI Studio helped create the following Plex Email Notification system.  It has the following structure and files.  It has been containerized in Docker.

```
################################################################
Project Structure:
################################################################

plex_email_notifications/
├── static/
│   ├── quill
│   │   ├── quill.js
│   │   └── quill.snow.css
│   ├── apple-touch-icon.png
│   ├── favicon-96x96.png
│   ├── favicon.ico
│   ├── favicon.svg
│   ├── plex_header.png
│   ├── script.js
│   ├── site.webmanifest
│   ├── style.css
│   ├── web-app-manifest-192x192.png
│   └── web-app-manifest-512x512.png
├── templates/
│   ├── base.html
│   ├── edit_template.html
│   ├── edit_header.html
│   ├── edit_setting.html
│   ├── error.html
│   ├── forgot_password.html
│   ├── index.html
│   ├── login.html
│   ├── notification_history.html
│   ├── notification_management.html
│   ├── notification.html
│   ├── options.html
│   ├── register.html
│   ├── reset_password.html
│   ├── send_notification.html
│   ├── subscribe.html
│   ├── success.html
│   ├── template_notifications.html
│   └── user_management.html
├── .dockerignore
├── .env
├── app.py
├── config.py
├── database.db
├── docker-compose.yml
├── Dockerfile
└── requirements.txt
```
