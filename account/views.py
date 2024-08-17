from django.contrib.auth import authenticate
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import *
from .renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

# Generate token manually


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    refresh["user"] = UserSerializer(user).data

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


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
        user = authenticate(email=email, password=password)
        if user is not None:
            token = get_tokens_for_user(user)
            return Response({'message': 'Login Successful', 'token': token}, status=status.HTTP_200_OK)
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
