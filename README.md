## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/louisheal/quiz-backend.git
    cd quiz-backend
    ```

2. Create and activate a virtual environment:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3. Install the dependencies:
    ```bash
    pip install -r requirements.txt
    ```

4. Copy the `example.env` file to `.env` and add the required environment variables:
    ```bash
    cp example.env .env
    ```
    ```env
    CLIENT_ID=your_client_id
    CLIENT_SECRET=your_client_secret
    JWT_SECRET=your_jwt_secret_key
    REDIRECT_URI=http://localhost:8000/auth
    ACCESS_TOKEN_EXPIRE_MINUTES=60
    ```

## Running the Application

Start the FastAPI server:
```bash
uvicorn app.main:app --reload