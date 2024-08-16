from django.urls import path
from account.views import *

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register_user'),
    path('login/', UserLoginView.as_view(), name='login_user'),
]