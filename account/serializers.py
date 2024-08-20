from rest_framework import serializers
from account.models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
import requests
import os

# User Serializer for extracting all user data for tokem claim


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        exclude = ('password',)


class UserRegisterSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(
        style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ["email", "country", "name", "password", "password2"]
        extra_kwargs = {
            'password': {'write_only': True}
        }

    # Validate the received data is correct or not
    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        email = attrs.get('email')
        api_key = os.environ.get('EMAIL_VALIDATION_API_KEY')

        if password != password2:
            raise serializers.ValidationError(
                'Password and Confirm Password must match')
        if not self.validate_email_availability(email, api_key):
            raise serializers.ValidationError(
                'Invalid email! Please provide a valid email address!')

        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

    def validate_email_availability(self, email, api_key):
        request_link = "https://emailvalidation.abstractapi.com/v1/?" + \
            "api_key=" + api_key + "&email=" + email
        response = requests.get(request_link)
        # Parse the JSON response
        response_json = response.json()

        # Extract the value of 'deliverability'
        deliverability = response_json.get('deliverability')

        return True if deliverability == "DELIVERABLE" else False


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        max_length=255,
    )

    class Meta:
        model = User
        fields = ['email', 'password']


class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(
        max_length=255, style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')

        if password != password2:
            raise serializers.ValidationError(
                "Password and Confirm password does not match!")

        user.set_password(password)
        user.save()
        return attrs


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            # Encoding the userid. force_bytes is used because the encoder function does not take integer
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = default_token_generator.make_token(user=user)
            link = 'http://127.0.0.1:8000/api/user/reset/password' + uid+'/' + token

            send_mail(
                'Reset Password | VERTEX',
                'Follow the given link to reset your password' + link,
                "vertex.blog.site@gmail.com",
                [user.email]
            )

        else:
            raise serializers.ValidationError('This email is not registered!')
        return attrs


class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(
        max_length=255, style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')

            if password != password2:
                raise serializers.ValidationError(
                    "Password and Confirm password does not match!")

            user_id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=user_id)
            if not default_token_generator.check_token(user=user, token=token):
                raise serializers.ValidationError(
                    'Invalid token! Please re-generate token!')

            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError:
            raise serializers.ValidationError(
                'Invalid token! Please re-generate token!')


class SendActivationEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(
        max_length=255,
    )

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)

            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = default_token_generator.make_token(user)

            link = "http://127.0.0.1:8000/api/user/activate/account/" + uid + '/' + token + '/'

            send_mail(
                subject='Vertex | Email Verification',
                message='You have registered into the Vertex server. Click the link to verify your email: ' + link,
                from_email=os.environ.get('EMAIL_FROM'),
                recipient_list=[user.email],
                fail_silently=False
            )
        else:
            raise serializers.ValidationError(
                'This email is not registerd in the Vertex server!')

        return attrs


class ActivateAccountSerializer(serializers.Serializer):
    def validate(self, attrs):
        try:
            uid = self.context.get('uid')
            token = self.context.get('token')
            user_id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=user_id)
            if not default_token_generator.check_token(user=user, token=token):
                raise serializers.ValidationError(
                    'Invalid token! Please re-generate token!')

            user.is_active = True
            user.save()
        except DjangoUnicodeDecodeError:
            raise serializers.DjangoValidationError(
                'The activation link is not valid or expired! Please try again ')
        return attrs
