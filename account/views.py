from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import *

'''
    Endpoint for registration of users
'''
class UserRegistrationView(APIView):
    def post(self, request, format=None):
        serializer = UserRegisterSerializer(data = request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({'message': 'Registration Successful'}, status=status.HTTP_201_CREATED)