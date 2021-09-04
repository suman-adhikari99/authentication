from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework import exceptions
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib import auth
from rest_framework.response import Response
from rest_framework import status

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=65, min_length=8, write_only=True)
    email = serializers.EmailField(max_length=255, min_length=4),
    first_name = serializers.CharField(max_length=255, min_length=2)
    last_name = serializers.CharField(max_length=255, min_length=2)
    username = serializers.CharField(required=True, error_messages={'required': 'Custom error message'})

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email','password'
                  ]

    def __init__(self, *args, **kwargs):
        super(UserSerializer, self).__init__(*args, **kwargs)

        self.fields['username'].error_messages['required'] = u'My custom required msg'
        self.fields['first_name'].error_messages['required'] = u'My custom required msg'
        self.fields['last_name'].error_messages['required'] = u'My custom required msg'
        self.fields['email'].error_messages['required'] = u'My custom required msg'
        self.fields['password'].error_messages['required'] = u'My custom required msg'

    #def validate(self, attrs):
    #    email = attrs.get('email', '')
    #    if User.objects.filter(email=email).exists():
    #        raise serializers.ValidationError(
    #            {'email': 'Email is already in use'})
    #    if email=="":
    #        raise serializers.ValidationError(
    #            {'email': 'Email is already in use'})
    #    return super().validate(attrs)
        

    
    

    #def create(self, validated_data):
    #    try:
    #        usr = User.objects.create_user(**validated_data)
    #        usr.is_active = False
    #        usr.save()
    #        return usr
    #    except Exception as e:
    #        error = {'message': e._message or 'Unknown error'}
    #        return Response(error,status=status.HTTP_400_BAD_REQUEST)
#

class LoginSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=65, min_length=8, write_only=True)
    username = serializers.CharField(max_length=255, min_length=2)

    class Meta:
        model = User
        fields = ['username', 'password']

class EmailTokenSerializer(serializers.Serializer):
    otp=serializers.CharField(max_length=10)
    email=serializers.CharField(max_length=10)




class ChangePasswordSerializer(serializers.Serializer):
    model = User
    
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(
        min_length=1, write_only=True)
    uidb64 = serializers.CharField(
        min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    #ef validate(self, attrs):
    #   
    #   password = attrs.get('password')
    #   token = attrs.get('token')
    #   uidb64 = attrs.get('uidb64')
    #   id = force_str(urlsafe_base64_decode(uidb64))
    #   user = User.objects.get(id=id)
    #   print(user)
    #   user.set_password(password)
    #   user.save()
    #   #if not PasswordResetTokenGenerator().check_token(user, token):
    #   #    print("invalied")
    #   #    raise AuthenticationFailed('The reset link is invalid', 401)
    #   
    #   return (user)
    #  
    #   #return super().validate(attrs)


    

class ResendOTP(serializers.Serializer):
        email = serializers.EmailField(min_length=2)
        class Meta:
            fields = ['email']
class Logoutserializer(serializers.Serializer):
        token = serializers.EmailField(min_length=2)
        class Meta:
            fields = ['token']
    

#from rest_framework_simplejwt.tokens import RefreshToken, TokenError
#class LogoutSerializer(serializers.Serializer):
#    refresh = serializers.CharField()
#
#    default_error_message = {
#        
#        'bad_token': ('Token is expired or invalid'),
#        
#    }
#
#    def validate(self, attrs):
#        
#        self.token = attrs['refresh']
#        return attrs
#
#    def save(self, **kwargs):
#
#        try:
#            RefreshToken(self.token).blacklist()
#
#        except exceptions :
#            self.fail('bad_token')





from rest_framework import serializers
from .models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email',
                  'first_name', 'last_name', 'is_active']