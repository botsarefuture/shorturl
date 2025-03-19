# URL Shortener

Welcome to the URL Shortener application—a professional web solution for transforming long URLs into concise, shareable links while tracking user engagement. This application is built with Flask for web routing and MongoDB for robust data management.

## Overview

The URL Shortener integrates several key components to ensure efficiency, security, and analytical insight:

- **Main Application**: Operates from `app.py` and manages URL shortening, Flask route configuration, user authentication, and event tracking.
- **Database Management**: Utilizes MongoDB with a custom `DatabaseManager` that implements a singleton pattern to maintain a single client instance.
- **User Authentication & Security**: 
    - Implements security features using `flask_autosec` to sanitize inputs.
    - Manages user sessions and role validations via `flask_lac`.
- **Analytics and Tracking**: Integrates Matomo API (found in `matomo.py`) to monitor events such as URL creation and redirection.

## File Structure

The project is organized as follows:

- **`app.py`**  
    Main flask application with API endpoints and dashboard functionalities.

- **`utils.py`**  
    Contains utility functions for processing data (e.g., process_object_ids).

- **`config.py`** & **`example.config.py`**  
    Configuration files for setting up MongoDB connection parameters.

- **`README.md`**  
    This documentation file.

- **`requirements.txt`**  
    Lists the necessary Python packages for installation.

- **`templates/`**  
    Directory holding HTML templates such as `base.html`, `index.html`, `dashboard.html`, and `home.html`.

- **`matomo.py`**  
    Client integration for the Matomo analytics platform.

## Installation

Follow these simple steps to set up your environment:

1. **Clone the Repository**  
     Navigate to the workspace directory via terminal.
     
2. **Set Up a Virtual Environment (Recommended)**
     ```
     python3 -m venv venv
     source venv/bin/activate
     ```

3. **Install Dependencies**
     ```
     pip install -r requirements.txt
     ```

## Configuration

Establish your environment by updating the configuration parameters:

- **`config.py`**: Modify the file to reflect your MongoDB connection settings.
- **Environment Variables**: Ensure the following variables are properly set:
    - `SECRET_KEY`
    - `MONGO_URI`
    - `MATOMO_URL`
    - `MATOMO_SITE_ID`

## Running the Application

Launch the application with the following command:

```
python app.py
```

Access the application via `http://0.0.0.0:5000/`.

## API Endpoints

Detailed API endpoints include:

- **Create Short URL** (`/api/create`):  
    Accepts a field: `_long_url`. This endpoint requires user authentication.
    
- **Dashboard** (`/dashboard`):  
    Displays a summary of user-specific URLs along with click counts.
    
- **Redirect URL** (`/<short_hash>`):  
    Redirects to the corresponding long URL and logs the click event.
    
- **User URLs** (`/api/my-urls`):  
    Retrieves URLs created by the authenticated user.
    
- **Admin URLs** (`/admin/urls`):  
    Accessible only by users with elevated privileges.

## Authentication & Security

This application uses a token-based authentication system with a signed serializer. Routes are protected using:
- `@login_required` for basic authentication.
- `@role_required` for role-based access control.

## Additional Information

- **Singleton Database Manager**:  
    Uses a singleton pattern to maintain a single MongoDB client instance.
    
- **Comprehensive Event Tracking**:  
    Leveraging Matomo for detailed analytics on URL creation, redirection, and other administrative events.

For further details or assistance, please refer to the documentation within each module.

