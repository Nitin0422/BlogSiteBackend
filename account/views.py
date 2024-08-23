from django.contrib.auth import authenticate
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import *
from .renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import IsAuthenticated

import os
# Generate token manually


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    refresh["user"] = UserSerializer(user).data

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        # Retrieve the refresh token from the cookie
        refresh_token = request.COOKIES.get('refresh_token')

        if not refresh_token:
            raise AuthenticationFailed('No refresh token found.')

        # Add the refresh token to the request data
        request.data['refresh'] = refresh_token

        # Call the parent class method to process the refresh
        response = super().post(request, *args, **kwargs)

        # If the response status is 200 OK, update the refresh token cookie
        if response.status_code == 200:
            new_refresh_token = response.data.get('refresh')

            if new_refresh_token:
                # Set the new refresh token in the cookie
                response.set_cookie(
                    key=settings.REFRESH_TOKEN_COOKIE_NAME,
                    value=new_refresh_token,
                    httponly=True,
                    secure=True,
                    samesite='Lax',
                    max_age=3600 * 24 * 7  # Match your refresh token lifetime
                )

        return response
#         refresh_token = request.COOKIES.get('refresh_token')

#         if not refresh_token:
#             return Response({'detail': 'Refresh token not provided'}, status=status.HTTP_401_UNAUTHORIZED)

#         # Forward the refresh token in the request data
#         data = {'refresh': refresh_token}
#         request._request.POST = data
#         original_response = super().post(request, *args, **kwargs)

#         if original_response.status_code == 200:
#             # Return the new access token with a 401 status to indicate re-authentication is needed
#             return Response({'token': original_response.data['access']}, status=status.HTTP_401_UNAUTHORIZED)
#         return original_response


'''
    Endpoint for registration of users
    Uses renderer for better representation of errors
    Takes email, country, name, password and password2 as valid data
    Returns 201 if registration successful 
    else
    Returns 400 as bad request 
'''


class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserRegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token = get_tokens_for_user(user)
        return Response({'message': 'Registration Successful', 'token': token}, status=status.HTTP_201_CREATED)


'''
    Endpoint for login 
    Takes email and password as valid data
    Returns 200 if login is successful
    else
    Returns 400 if data is invalid
    else
    Returns 404 if user with invalid credentials is provided
'''


class UserLoginView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email')
        password = serializer.data.get('password')
        if not User.objects.filter(email=email).exists():
            return Response({'message': 'This email is not registered in the server!'}, status=status.HTTP_404_NOT_FOUND)
        
        if not User.objects.get(email=email).is_active:
            return Response({'message': 'Please activate your account!'}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(email=email, password=password)

        if user is not None:        
            token = get_tokens_for_user(user)["access"]
            refresh_token = get_tokens_for_user(user)["refresh"]
            response = Response(
                {'token': token, 'message': 'Login Successful!'}, status=status.HTTP_200_OK)
            response.set_cookie(
                key='refresh_token',
                value=str(refresh_token),
                httponly=True,
                secure=True,
                samesite='Lax',
                max_age=3600 * 24 * 7,
            )
            return response
        return Response({'message': 'User credentials does not match'}, status=status.HTTP_404_NOT_FOUND)


'''
    Endpoint for User profile view
'''


class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        serilaizer = UserSerializer(request.user)
        return Response(serilaizer.data, status=status.HTTP_200_OK)


class UserChangePassword(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(
            data=request.data, context={'user': request.user})
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Password changed successfully!'}, status=status.HTTP_200_OK)


class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Password reset link has been sent to your email'}, status=status.HTTP_200_OK)


class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(
            data=request.data, context={'uid': uid, 'token': token})
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Password Reset Successfully'}, status=status.HTTP_200_OK)


class SendActivationEmailView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = SendActivationEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'message': 'Activation Link has been sent to your email!'}, status=status.HTTP_200_OK)


class ActivateAccountView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, uid, token):
        serializer = ActivateAccountSerializer(data=request.data, context={
                                               'uid': uid, 'token': token})
        serializer.is_valid(raise_exception=True)
        return Response({"message": "Your account has been activated successfully"}, status=status.HTTP_200_OK)
