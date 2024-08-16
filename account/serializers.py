from rest_framework import serializers
from account.models import User

class UserRegisterSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style= {'input_type' : 'password'}, write_only=True)
    class Meta:
        model = User
        fields = ["email", "country", "name", "password", "password2"]
        extra_kwargs = {
            'password':{'write_only': True}
        }
    
    #Validate the received data is correct or not 
    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError('Password and Confirm Password must match')
         
        return attrs
    
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
