from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from .models import Account, Transaction
from django.db import connection, models
from django.views.decorators.csrf import csrf_exempt
import random
from datetime import datetime
from decimal import Decimal


def home(request):
    return render(request, 'home.html')

# vulnerable login
@csrf_exempt
def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        # SQL Injection vulnerability
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT * FROM auth_user WHERE username = '{username}' AND password = '{password}'")
            user_data = cursor.fetchone()
        
        if user_data:
            user = User.objects.get(id=user_data[0])
            login(request, user)
            return redirect('dashboard')
    
    return render(request, 'login.html')

# Vulnerable registration
@csrf_exempt
def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        email = request.POST.get('email')
        
        # SQL Injection vulnerability and weak password handling
        with connection.cursor() as cursor:
            cursor.execute(
                f"INSERT INTO auth_user (username, password, email, is_active, is_superuser, is_staff, first_name, last_name, date_joined) "
                f"VALUES ('{username}', '{password}', '{email}', 1, 0, 0, '', '', '{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}')"
            )
        
        # Create user without validation
        user = User.objects.get(username=username)
        account_number = str(random.randint(100000, 999999))
        
        # Insecure account creation
        Account.objects.create(
            user=user,
            account_number=account_number,
            balance=100000.00
        )
        
        return redirect('login')
    
    return render(request, 'register.html')

# Vulnerable logout
@csrf_exempt
def user_logout(request):
    if request.method == 'POST':
        logout(request)
        return redirect('login')
    return render(request, 'logout.html')

# XSS vulnerable dashboard
@login_required
@csrf_exempt
def dashboard(request):
    user = request.user
    account = Account.objects.get(user=user)
    
    # Display user-supplied data without escaping
    message = request.GET.get('message', '')
    messag = request.GET.get('messag', '')
    
    return render(request, 'dashboard.html', {
        'account': account,
        'message': message,
        'user': user
    })

# CSRF vulnerable transfer
@csrf_exempt
@login_required
def transfer(request):
    if request.method == 'POST':
        from_account = Account.objects.get(user=request.user)
        to_account_number = request.POST.get('to_account')
        amount = request.POST.get('amount')
        description = request.POST.get('description')
        
        # Broken Access Control - No proper validation
        to_account = Account.objects.get(account_number=to_account_number)
        
        # Business logic flaw - No negative balance check
        amount_decimal = Decimal(amount)
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
    
    return render(request, 'transfer.html')

# Sensitive data exposure
@login_required
def transactions(request):
    account_id = request.GET.get('account_id')
    if not account_id or not account_id.isdigit():
        return redirect('dashboard', message='Please select a valid account')
    
    try:
        account = Account.objects.get(id=account_id)
    except Account.DoesNotExist:
        return redirect('dashboard', message='Account not found')
    
    # Insecure direct object reference
    transactions = Transaction.objects.filter(
        models.Q(from_account=account) | models.Q(to_account=account))
    
    return render(request, 'transactions.html', {
        'transactions': transactions,
        'account': account,
        'user': request.user
    })