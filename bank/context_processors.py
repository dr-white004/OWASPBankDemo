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