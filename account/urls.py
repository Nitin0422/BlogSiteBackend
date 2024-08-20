from django.urls import path
from account.views import *

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register_user'),
    path('login/', UserLoginView.as_view(), name='login_user'),
    path('profile/', UserProfileView.as_view(), name='profile_view'),
    path('change/password/', UserChangePassword.as_view(), name='change_password_view'),
    path('send/password/reset/email/', SendPasswordResetEmailView.as_view(), name='send_reset_password'),
    path('reset/password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset_password_view' ),
]