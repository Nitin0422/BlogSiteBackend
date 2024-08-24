from django.urls import path
from account.views import *

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register_user'),
    path('login/', UserLoginView.as_view(), name='login_user'),
    path('profile/', UserProfileView.as_view(), name='profile_view'),
    path('change/password/', UserChangePassword.as_view(), name='change_password_view'),
    path('send/password/reset/email/', SendPasswordResetEmailView.as_view(), name='send_reset_password'),
    path('reset/password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset_password_view' ),
    path('send/verification/email/', SendActivationEmailView.as_view(), name='send_verification_email'),
    path('activate/account/<uid>/<token>/', ActivateAccountView.as_view(), name='activate_account'),
    path('refresh/token/', CustomTokenRefreshView.as_view(), name='refresh_token'),
    path('get/token/', CheckTokenView.as_view(), name='access_token')
]