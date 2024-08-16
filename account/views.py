from django.contrib.auth import authenticate
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import *

'''
    Endpoint for registration of users
    Uses renderer for better representation of errors
    Takes email, country, name, password and password2 as valid data
    Returns 201 if registration successful 
    else
    Returns 400 as bad request 
'''
class UserRegistrationView(APIView):
    def post(self, request, format=None):
        serializer = UserRegisterSerializer(data = request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({'message': 'Registration Successful'}, status=status.HTTP_201_CREATED)
    
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
    def post(self, request, format=None):
        serializer = UserLoginSerializer(data = request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email')
        password = serializer.data.get('password')
        user = authenticate(email=email, password= password)
        if user is not None:
            return Response({'message':'Login Successful'}, status=status.HTTP_200_OK)
        return Response({'message': 'User credentials does not match'}, status=status.HTTP_404_NOT_FOUND)