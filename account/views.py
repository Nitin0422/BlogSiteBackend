from django.contrib.auth import authenticate  # Import the authenticate function to verify user credentials
from rest_framework.response import Response  # Import Response to send HTTP responses
from rest_framework import status  # Import status to use HTTP status codes
from rest_framework.views import APIView  # Import APIView as the base view class for handling HTTP requests
from .serializers import *  # Import all serializers from the serializers module
from .renderers import UserRenderer  # Import custom renderer for handling errors in a better format
from rest_framework_simplejwt.tokens import RefreshToken  # Import RefreshToken to manually generate JWT tokens
from rest_framework_simplejwt.views import TokenRefreshView  # Import TokenRefreshView to handle token refresh requests
from rest_framework.exceptions import AuthenticationFailed  # Import AuthenticationFailed exception for handling auth failures
from rest_framework.permissions import IsAuthenticated  # Import IsAuthenticated to restrict access to authenticated users

import os  # Import os module, although not used here

# Generate JWT tokens (access and refresh) manually for a user


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)  # Create a refresh token for the given user

    refresh["user"] = UserSerializer(user).data  # Add serialized user data to the refresh token

    return {
        'refresh': str(refresh),  # Return the refresh token as a string
        'access': str(refresh.access_token),  # Return the access token derived from the refresh token
    }

# Custom view to refresh JWT tokens using a token stored in cookies


class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        # Retrieve the refresh token from the cookie
        refresh_token = request.COOKIES.get('refresh_token')

        if not refresh_token:
            raise AuthenticationFailed('No refresh token found.')  # Raise an error if no token is found

        # Add the refresh token to the request data for processing
        request.data['refresh'] = refresh_token

        # Call the parent class method to handle the token refresh process
        response = super().post(request, *args, **kwargs)

        # If the token refresh is successful, update the refresh token in the cookie
        if response.status_code == 200:
            new_refresh_token = response.data.get('refresh')

            if new_refresh_token:
                # Set the new refresh token in the cookie with appropriate settings
                response.set_cookie(
                    key=settings.REFRESH_TOKEN_COOKIE_NAME,
                    value=new_refresh_token,
                    httponly=True,
                    secure=True,
                    samesite='Lax',
                    max_age=3600 * 24 * 7  # Set cookie duration to match the token lifetime
                )

        return response

'''
    API view to handle user registration
    - Uses custom renderer for better error representation
    - Accepts email, country, name, password, and password2 as required data
    - Returns a 201 status if registration is successful
    - Returns a 400 status if there is an error with the data
'''


class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]  # Use custom renderer for error formatting

    def post(self, request, format=None):
        serializer = UserRegisterSerializer(data=request.data)  # Serialize the incoming data
        serializer.is_valid(raise_exception=True)  # Validate the data and raise an error if invalid
        user = serializer.save()  # Save the user if the data is valid
        token = get_tokens_for_user(user)["access"]  # Generate an access token for the user
        refresh_token = get_tokens_for_user(user)["refresh"]  # Generate a refresh token for the user
        response = Response(
            {'token': token, 'message': 'Registration Successful!'}, status=status.HTTP_201_CREATED)  # Create a response with the tokens
        # Set the refresh token in a secure, HTTP-only cookie
        response.set_cookie(
            key='refresh_token',
            value=str(refresh_token),
            httponly=True,
            secure=True,
            samesite='Lax',
            max_age=3600 * 24 * 7,
        )
        # Set the access token in a secure, HTTP-only cookie
        response.set_cookie(
            key='access_token',
            value=str(token),
            httponly=True,
            secure=True,
            samesite='Lax',
            max_age=3600 * 24 * 7,
        )
        return response

'''
    API view to handle user login
    - Accepts email and password as required data
    - Returns a 200 status if login is successful
    - Returns a 400 status if data is invalid
    - Returns a 404 status if the user credentials are incorrect or the email is not registered
'''


class UserLoginView(APIView):
    renderer_classes = [UserRenderer]  # Use custom renderer for error formatting

    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)  # Serialize the incoming data
        serializer.is_valid(raise_exception=True)  # Validate the data and raise an error if invalid
        email = serializer.data.get('email')  # Extract the email from the validated data
        password = serializer.data.get('password')  # Extract the password from the validated data

        # Check if the email is registered in the system
        if not User.objects.filter(email=email).exists():
            return Response({'message': 'This email is not registered in the server!'}, status=status.HTTP_404_NOT_FOUND)

        # Check if the user account is active
        if not User.objects.get(email=email).is_active:
            return Response({'message': 'Please activate your account!'}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(email=email, password=password)  # Authenticate the user with the provided credentials

        if user is not None:
            token = get_tokens_for_user(user)["access"]  # Generate an access token for the user
            refresh_token = get_tokens_for_user(user)["refresh"]  # Generate a refresh token for the user
            response = Response(
                {'token': token, 'message': 'Login Successful!'}, status=status.HTTP_200_OK)  # Create a response with the tokens
            # Set the refresh token in a secure, HTTP-only cookie
            response.set_cookie(
                key='refresh_token',
                value=str(refresh_token),
                httponly=True,
                secure=True,
                samesite='Lax',
                max_age=3600 * 24 * 7,
            )
            # Set the access token in a secure, HTTP-only cookie
            response.set_cookie(
                key='access_token',
                value=str(token),
                httponly=True,
                secure=True,
                samesite='Lax',
                max_age=3600 * 24 * 7,
            )
            return response

        # Return a 404 error if the credentials do not match any user
        return Response({'message': 'User credentials do not match'}, status=status.HTTP_404_NOT_FOUND)

'''
    API view to handle viewing the user's profile
    - Restricted to authenticated users only
'''


class UserProfileView(APIView):
    renderer_classes = [UserRenderer]  # Use custom renderer for error formatting
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access this view

    def get(self, request, format=None):
        serializer = UserSerializer(request.user)  # Serialize the currently authenticated user's data
        return Response(serializer.data, status=status.HTTP_200_OK)  # Return the serialized user data

'''
    API view to handle user password change
    - Restricted to authenticated users only
    - Accepts old password, new password, and new password confirmation as required data
    - Returns a 200 status if password is changed successfully
'''


class UserChangePassword(APIView):
    renderer_classes = [UserRenderer]  # Use custom renderer for error formatting
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access this view

    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(
            data=request.data, context={'user': request.user})  # Serialize the incoming data with the current user context
        serializer.is_valid(raise_exception=True)  # Validate the data and raise an error if invalid
        return Response({'message': 'Password changed successfully!'}, status=status.HTTP_200_OK)  # Return success message

'''
    API view to send a password reset email
    - Accepts email as required data
    - Returns a 200 status if the email is sent successfully
'''


class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]  # Use custom renderer for error formatting

    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)  # Serialize the incoming data
        serializer.is_valid(raise_exception=True)  # Validate the data and raise an error if invalid
        return Response({'message': 'Password reset link has been sent to your email'}, status=status.HTTP_200_OK)  # Return success message

'''
    API view to reset the user's password using a token sent via email
    - Accepts the new password and confirmation as required data
    - Also requires the user's UID and the reset token for validation
    - Returns a 200 status if the password is reset successfully
'''


class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]  # Use custom renderer for error formatting

    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(
            data=request.data, context={'uid': uid, 'token': token})  # Serialize the incoming data with the UID and token context
        serializer.is_valid(raise_exception=True)  # Validate the data and raise an error if invalid
        return Response({'message': 'Password Reset Successfully'}, status=status.HTTP_200_OK)  # Return success message

'''
    API view to send an account activation email
    - Accepts email as required data
    - Returns a 200 status if the email is sent successfully
'''


class SendActivationEmailView(APIView):
    renderer_classes = [UserRenderer]  # Use custom renderer for error formatting

    def post(self, request, format=None):
        serializer = SendActivationEmailSerializer(data=request.data)  # Serialize the incoming data
        serializer.is_valid(raise_exception=True)  # Validate the data and raise an error if invalid
        return Response({'message': 'Activation Link has been sent to your email!'}, status=status.HTTP_200_OK)  # Return success message

'''
    API view to activate a user's account using a token sent via email
    - Accepts the user's UID and activation token as required data
    - Returns a 200 status if the account is activated successfully
'''


class ActivateAccountView(APIView):
    renderer_classes = [UserRenderer]  # Use custom renderer for error formatting

    def post(self, request, uid, token):
        serializer = ActivateAccountSerializer(data=request.data, context={
                                               'uid': uid, 'token': token})  # Serialize the incoming data with the UID and token context
        serializer.is_valid(raise_exception=True)  # Validate the data and raise an error if invalid
        return Response({"message": "Your account has been activated successfully"}, status=status.HTTP_200_OK)  # Return success message

'''
    API view to check the validity of the JWT token stored in cookies
    - Returns a 404 status if no token is found
    - Returns a 200 status if a valid token is found
'''


class CheckTokenView(APIView):
    renderer_classes = [UserRenderer]  # Use custom renderer for error formatting

    def get(self, request, format=None):
        access_token = request.COOKIES.get('refresh_token')  # Retrieve the refresh token from cookies
        if not access_token:
            return Response({'message': 'You are not logged in!'}, status=status.HTTP_404_NOT_FOUND)  # Return error if no token found
        return Response({'message': 'Token found!', 'token': access_token}, status=status.HTTP_200_OK)  # Return success if token is found
