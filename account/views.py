# Import the authenticate function to verify user credentials
from django.contrib.auth import authenticate
# Import Response to send HTTP responses
from rest_framework.response import Response
from rest_framework import status  # Import status to use HTTP status codes
# Import APIView as the base view class for handling HTTP requests
from rest_framework.views import APIView
from .serializers import *  # Import all serializers from the serializers module
# Import custom renderer for handling errors in a better format
from .renderers import UserRenderer
# Import RefreshToken to manually generate JWT tokens
from rest_framework_simplejwt.tokens import RefreshToken
# Import TokenRefreshView to handle token refresh requests
from rest_framework_simplejwt.views import TokenRefreshView
# Import AuthenticationFailed exception for handling auth failures
from rest_framework.exceptions import NotFound
# Import IsAuthenticated to restrict access to authenticated users
from rest_framework.permissions import IsAuthenticated

import os  # Import os module, although not used here

# Generate JWT tokens (access and refresh) manually for a user


def get_tokens_for_user(user):
    # Create a refresh token for the given user
    refresh = RefreshToken.for_user(user)

    # Add serialized user data to the refresh token
    refresh["user"] = UserSerializer(user).data

    return {
        'refresh': str(refresh),  # Return the refresh token as a string
        # Return the access token derived from the refresh token
        'access': str(refresh.access_token),
    }

# Custom view to refresh JWT tokens using a token stored in cookies


class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        # Retrieve the refresh token from the cookie
        refresh_token = request.COOKIES.get('refresh_token')

        if refresh_token is None:
            # Raise an error if no token is found
            raise NotFound('No refresh token found.')

        # Add the refresh token to the request data for processing
        request.data['refresh'] = refresh_token

        try:
            # Call the parent class method to handle the token refresh process
            response = super().post(request, *args, **kwargs)

            # If the token refresh is successful, update the refresh token in the cookie
            if response.status_code == 200:
                new_refresh_token = response.data.get('refresh')

                if new_refresh_token:
                    # Set the new refresh token in the cookie with appropriate settings
                    response.set_cookie(
                        key='refresh_token',
                        value=new_refresh_token,
                        httponly=True,
                        secure=True,
                        samesite='None',
                        max_age=3600 * 24 * 7  # Set cookie duration to match the token lifetime
                    )

            return response
        except Exception as e:
            # Raise a 400 Bad Request error with a custom error message
            raise NotFound(
                {'error': 'An error occurred during the token refresh process.', 'details': str(e)})


'''
    API view to handle user registration
    - Uses custom renderer for better error representation
    - Accepts email, country, name, password, and password2 as required data
    - Returns a 201 status if registration is successful
    - Returns a 400 status if there is an error with the data
'''


class UserRegistrationView(APIView):
    # Use custom renderer for error formatting
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserRegisterSerializer(
            data=request.data)  # Serialize the incoming data
        # Validate the data and raise an error if invalid
        serializer.is_valid(raise_exception=True)
        user = serializer.save()  # Save the user if the data is valid

        activation_data = {'email': user.email}
        activation_serializer = SendActivationEmailSerializer(
            data=activation_data)
        activation_serializer.is_valid(raise_exception=True)

        # token = get_tokens_for_user(user)["access"]  # Generate an access token for the user
        # refresh_token = get_tokens_for_user(user)["refresh"]  # Generate a refresh token for the user
        # response = Response(
        #     {'token': token, 'message': 'Registration Successful!'}, status=status.HTTP_201_CREATED)  # Create a response with the tokens
        # # Set the refresh token in a secure, HTTP-only cookie
        # response.set_cookie(
        #     key='refresh_token',
        #     value=str(refresh_token),
        #     httponly=True,
        #     secure=True,
        #     samesite='None',
        #     max_age=3600 * 24 * 7,
        # )

        # return response

        return Response({"message": "Registration Succesful! Please check your email to activate your account"}, status=status.HTTP_201_CREATED)


'''
    API view to handle user login
    - Accepts email and password as required data
    - Returns a 200 status if login is successful
    - Returns a 400 status if data is invalid
    - Returns a 404 status if the user credentials are incorrect or the email is not registered
'''


class UserLoginView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email')
        password = serializer.data.get('password')

        # Check email existence and account activation
        if not User.objects.filter(email=email).exists():
            return Response({'message': 'This email is not registered!'}, status=status.HTTP_404_NOT_FOUND)

        if not User.objects.get(email=email).is_active:
            return Response({'message': 'Please activate your account!'}, status=status.HTTP_400_BAD_REQUEST)

        # Authenticate the user
        user = authenticate(email=email, password=password)

        if user is not None:
            # Generate tokens
            token = get_tokens_for_user(user)["access"]
            refresh_token = get_tokens_for_user(user)["refresh"]

            response = Response(
                {'token': token, 'message': 'Login Successful!'}, status=status.HTTP_200_OK)

            # Set secure cookies
            response.set_cookie(
                key='refresh_token',
                value=str(refresh_token),
                domain="127.0.0.1",
                httponly=True,  # Ensures it's not accessible via JavaScript
                secure=True,  # Only sent over HTTPS
                # For cross-site requests, especially for frontend-backend on different domains
                samesite="None",
                max_age=3600 * 24 * 7,  # 1 week
            )
            response.set_cookie(
                key='access_token',
                value=str(token),
                domain="127.0.0.1",
                httponly=True,
                secure=True,
                samesite="None",
                max_age=3600 * 24 * 7,
            )

            return response

        return Response({'message': 'User credentials do not match'}, status=status.HTTP_404_NOT_FOUND)


'''
    API view to handle viewing the user's profile
    - Restricted to authenticated users only
'''


class UserProfileView(APIView):
    # Use custom renderer for error formatting
    renderer_classes = [UserRenderer]
    # Ensure only authenticated users can access this view
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        # Serialize the currently authenticated user's data
        serializer = UserSerializer(request.user)
        # Return the serialized user data
        return Response(serializer.data, status=status.HTTP_200_OK)


'''
    API view to handle user password change
    - Restricted to authenticated users only
    - Accepts old password, new password, and new password confirmation as required data
    - Returns a 200 status if password is changed successfully
'''


class UserChangePassword(APIView):
    # Use custom renderer for error formatting
    renderer_classes = [UserRenderer]
    # Ensure only authenticated users can access this view
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(
            data=request.data, context={'user': request.user})  # Serialize the incoming data with the current user context
        # Validate the data and raise an error if invalid
        serializer.is_valid(raise_exception=True)
        # Return success message
        return Response({'message': 'Password changed successfully!'}, status=status.HTTP_200_OK)


'''
    API view to send a password reset email
    - Accepts email as required data
    - Returns a 200 status if the email is sent successfully
'''


class SendPasswordResetEmailView(APIView):
    # Use custom renderer for error formatting
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(
            data=request.data)  # Serialize the incoming data
        # Validate the data and raise an error if invalid
        serializer.is_valid(raise_exception=True)
        # Return success message
        return Response({'message': 'Password reset link has been sent to your email'}, status=status.HTTP_200_OK)


'''
    API view to reset the user's password using a token sent via email
    - Accepts the new password and confirmation as required data
    - Also requires the user's UID and the reset token for validation
    - Returns a 200 status if the password is reset successfully
'''


class UserPasswordResetView(APIView):
    # Use custom renderer for error formatting
    renderer_classes = [UserRenderer]

    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(
            data=request.data, context={'uid': uid, 'token': token})  # Serialize the incoming data with the UID and token context
        # Validate the data and raise an error if invalid
        serializer.is_valid(raise_exception=True)
        # Return success message
        return Response({'message': 'Password Reset Successfully'}, status=status.HTTP_200_OK)


'''
    API view to send an account activation email
    - Accepts email as required data
    - Returns a 200 status if the email is sent successfully
'''


class SendActivationEmailView(APIView):
    # Use custom renderer for error formatting
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = SendActivationEmailSerializer(
            data=request.data)  # Serialize the incoming data
        # Validate the data and raise an error if invalid
        serializer.is_valid(raise_exception=True)
        # Return success message
        return Response({'message': 'Activation Link has been sent to your email!'}, status=status.HTTP_200_OK)


'''
    API view to activate a user's account using a token sent via email
    - Accepts the user's UID and activation token as required data
    - Returns a 200 status if the account is activated successfully
'''


class ActivateAccountView(APIView):
    # Use custom renderer for error formatting
    renderer_classes = [UserRenderer]

    def post(self, request, uid, token):
        serializer = ActivateAccountSerializer(data=request.data, context={
                                               'uid': uid, 'token': token})  # Serialize the incoming data with the UID and token context
        # Validate the data and raise an error if invalid
        serializer.is_valid(raise_exception=True)
        # Return success message
        return Response({"message": "Your account has been activated successfully"}, status=status.HTTP_200_OK)


class LogoutView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request):
        access_token = request.COOKIES.get('access_token')
        refresh_token = request.COOKIES.get('refresh_token')

        if not refresh_token or not access_token:
            raise ValueError('User is not logged in!')

        r_token = RefreshToken(refresh_token)

        try:
            r_token.blacklist()

            response = Response(
                {'message': 'Logged out successfully!'}, status=status.HTTP_200_OK)

            # Delete the cookies with the same parameters used during login
            response.delete_cookie(
                key='refresh_token',
                path='/',
                domain="127.0.0.1",
                samesite="None",  # Ensure same SameSite policy
            )
            response.delete_cookie(
                key='access_token',
                path='/',
                domain="127.0.0.1",
                samesite="None",
            )

            return response
        except Exception as e:
            print("Error: ", e)
            return Response({'message': 'An unknown error has occurred!'}, status=status.HTTP_400_BAD_REQUEST)


class CheckAccessToken(APIView):
    renderer_classes = [UserRenderer]

    def get(self, request):
        access_token = request.COOKIES.get('access_token')

        if not access_token:
            raise ValueError('User is not logged in!')

        return Response({"message": "Token found", "token": access_token}, status=status.HTTP_200_OK)
