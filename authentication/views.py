
from django.db.models.base import Model
from django.shortcuts import render, redirect
from rest_framework import response

from rest_framework.generics import GenericAPIView
from .serializers import UserSerializer, LoginSerializer,EmailTokenSerializer, ResendOTP,Logoutserializer
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from django.contrib import auth
from .models import UserOTP
import random
import jwt
import time
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import HttpResponse
from rest_framework import generics, status, views, permissions
# for password reset
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.mail import BadHeaderError, send_mail
from django.core import mail
from datetime import datetime, timedelta
from django.utils import timezone 
from rest_framework.views import APIView


class RegisterView(GenericAPIView):
    
    serializer_class = UserSerializer

    def post(self, request):       
        data = request.data
        username=data.get('username','')
        email = data.get('email', '')
        first_name=data.get('first_name','')
        last_name=data.get('last_name','')
        password=data.get('password','')
        if email=="" and username=="" and last_name=="" and password=="" and first_name=="" :
            return Response({'status':False,'error':{'username':'this is required field','first_name':'this is required field','last_name':'this is required field','password':'this is required field',}}, status=status.HTTP_400_BAD_REQUEST)
        if username=="":
            return Response({'status':False,'error':{'username':'username is required'}}, status=status.HTTP_400_BAD_REQUEST)
        if password=="":
            return Response({'status':False,'error':{'password':'password is required'}}, status=status.HTTP_400_BAD_REQUEST)
        if first_name=="":
            return Response({'status':False,'error':{'first_name':'first_name is required'}}, status=status.HTTP_400_BAD_REQUEST)
        if last_name=="":
            return Response({'status':False,'error':{'last_name':'last_name is required'}}, status=status.HTTP_400_BAD_REQUEST)
        if email=="":
            return Response({'status':False,'error':{'username':'username is required'}}, status=status.HTTP_400_BAD_REQUEST)
        if username=="" or username=="" or last_name=="" or password=="" or first_name=="" :
            return Response({'status':False,'error':'all field are required'}, status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(email=email).exists():
            return Response({'status':False,'error':{'email':'this email is already used'},"registered":False}, status=status.HTTP_400_BAD_REQUEST)  
        ran =random.seed(time.time())
        print(ran)
        ran2=t = int( time.time() * 10000000.0 )
        random.seed( ((t & 0xff000000) >> 24) +
                     ((t & 0x00ff0000) >>  8) +
                     ((t & 0x0000ff00) <<  8) +
                     ((t & 0x000000ff) << 24)   )
        print(ran2)
        ran3=usr_otp = random.randint(100000, 999999)
        usr_otp=(ran2+ran3)%random.randint(100, 999)*random.randint(10, 20)
        
        print(usr_otp)
        if not UserOTP.objects.filter(otp = usr_otp).exists():
            usr=data.get('username', '')
            email=data.get('email','')
            usr = User.objects.create_user(username=username,first_name=first_name, last_name=last_name,email=email,password=password)
            usr.is_active = False
            usr.save()	
            mess = f"Hello \nYour OTP is {usr_otp}\nThanks!\nhttp://127.0.0.1:8000/admin/"
            try:

                send_mail(
		        "Welcome to - Verify Your Email", 
		        mess,
		        settings.EMAIL_HOST_USER,

		        [email],
		        fail_silently = False,
		        )
                
                UserOTP.objects.create(user = email, otp = usr_otp)
                data={"username":username,"first_name":first_name,"last_name":last_name,    "email":email}           
                return Response({"status":True,"data":data,"message":"we have send a OTP in your email  please verify our accoutn "}, status=status.HTTP_201_CREATED)

            except BadHeaderError:
                return Response('your eamil address is not valid', status=status.HTTP_400_BAD_REQUEST)       
        else:
            return Response({"status":False, "message":"click to resend otp"}, status=status.HTTP_400_BAD_REQUEST) 




class registerverify(GenericAPIView):
    serializer_class = EmailTokenSerializer
    def post(self, request):
       data = request.data
       get_otp = data.get('otp')
       try:    
           get = UserOTP.objects.get(otp=get_otp)
           get_time=get.time_st
           get_usr=get.user  #here we get email
           time_threshold =get_time  + timedelta(hours=0.4)
           usr = User.objects.filter(email=get_usr).first()
           
           if not usr:
               return Response({'status':False,'message': 'this email is not registered'}, status=status.HTTP_400_BAD_REQUEST)
           
           if int(get_otp) == UserOTP.objects.filter(user = get_usr).last().otp:
               if  not (timezone.now()>time_threshold):
                   usr.is_active = True
                   usr.save()
                   UserOTP.objects.get(otp = get_otp).delete()
                   
                  
                   return Response({'status':True,'message': 'We have registerd you'},   status=status.HTTP_200_OK)
               else:
                   UserOTP.objects.get(otp = get_otp).delete()
                   return Response({'status':False,'message': 'time out' ,"registered":False}, status=status.HTTP_400_BAD_REQUEST)
            
           else:
               return Response({'status':False,'message': 'you have entered wrong OTP',"registered":False}, status=status.HTTP_400_BAD_REQUEST)

       except UserOTP.DoesNotExist:
                messages.warning(request,f'you entered a wrong otp')
                

       return Response({"status":False,'message':'invalid token' ,"registered":False},status=status.HTTP_400_BAD_REQUEST)
    



from django.contrib.auth import login

class LoginView(views.APIView):
    serializer_class = LoginSerializer

    def post(self, request):    
        data = request.data
        username = data.get('username', '')
        password = data.get('password', '')
        if username=="":
            return Response({'status':False,'message': 'enter email  or username'},status=status.HTTP_400_BAD_REQUEST)
        try:
            if   User.objects.filter(username=username).exists() :
                user = User.objects.filter(username=username)
                if user:

                
                    usernamereg=User.objects.filter(username=username).first()
                    print(usernamereg)
                    if not usernamereg:
                        return Response({'status':False,'message': ' username is worng'}, status=status.            HTTP_401_UNAUTHORIZED)
                    if not usernamereg.is_active:
                        return Response({'status':False,'message': ' your account is not acitavted first verify     your        account'},  status=status.HTTP_401_UNAUTHORIZED)
                    user = auth.authenticate(username=username, password=password)
                    if user is not None:
                        if user.is_active:
                            login(request, user)
                            auth_token = jwt.encode(
                                {'username': user.username}, settings.JWT_SECRET_KEY, algorithm="HS256")

                            serializer = UserSerializer(user)            
                            userdetail= User.objects.filter(username=username).first()
                            data={'id':userdetail.id, 'username':userdetail.username,'firt_name':userdetail.    first_name,         'last_name':userdetail.last_name,'email':userdetail.email,  'join_date':userdetail.       date_joined.    strftime('%y-%m-%d %a %H:%M:%S'),   'last_login':userdetail.last_login.strftime    ('%y-%m-%d %a   %H:%M:%S'),'token':     auth_token}

                            return Response({'status':True,'data':data}, status=status.HTTP_200_OK)
                        return Response({'status':False,'message': ' your account is not acitavted firt verify  your account'},  status=status.HTTP_401_UNAUTHORIZED)
                    return Response({'status':False, 'message': ' password is worng'}, status=status.   HTTP_401_UNAUTHORIZED)
                
            if User.objects.filter(email=username).exists():
                usernamereg=User.objects.filter(email=username).first()
                usernames=usernamereg.username
                    #username=usernamereg.username
                if not usernamereg:
                    return Response({'status':False,'message': ' username is worng'}, status=status.        HTTP_401_UNAUTHORIZED)
                if not usernamereg.is_active:
                    return Response({'status':False,'message': ' your account is not acitavted first    verifyyour        account'},  status=status.HTTP_401_UNAUTHORIZED)

                user = auth.authenticate(username=usernames, password=password)
                if user is not None:
                    if user.is_active:
                        login(request, user)
                        auth_token = jwt.encode(
                            {'username': user.username}, settings.JWT_SECRET_KEY, algorithm="HS256")
                        serializer = UserSerializer(user)            
                        userdetail= User.objects.filter(email=username).first()
                        data={'id':userdetail.id, 'username':userdetail.username,'firt_name':userdetail.    first_name,         'last_name':userdetail.last_name,'email':userdetail.email,  'join_date':userdetail.       date_joined.    strftime('%y-%m-%d %a %H:%M:%S'),   'last_login':userdetail.last_login.strftime    ('%y-%m-%d %a   %H:%M:%S'), 'token':auth_token}
                        return Response({'status':True,'data':data}, status=status.HTTP_200_OK)
                    return Response({'status':False,'message': ' your account is not acitavted firt verify your     account'},  status=status.HTTP_401_UNAUTHORIZED)

                return Response({'status':False, 'message': ' password is worng'}, status=status.HTTP_401_UNAUTHORIZED)
            return Response({'status':False, 'message': ' username or email in not registered'}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception:
            return Response({'status':False, 'message': ' username or email in not registered'}, status=status.HTTP_401_UNAUTHORIZED)




class ResendOTP(GenericAPIView):
    serializer_class =ResendOTP
    def post(self, request):
        data = request.data
        email=data.get('email')
        is_user=User.objects.filter(email = email).first()       
        if  is_user :
            if not is_user.is_active:                
                ran =random.seed(time.time())
                print(ran)
                ran2=t = int( time.time() * 10000000.0 )
                random.seed( ((t & 0xff000000) >> 24) +
                             ((t & 0x00ff0000) >>  8) +
                             ((t & 0x0000ff00) <<  8) +
                             ((t & 0x000000ff) << 24)   )               
                ran3 = random.randint(100000, 999999)
                usr_otp=(ran2+ran3)%random.randint(100, 999)*random.randint(10, 20)
                if not UserOTP.objects.filter(otp = usr_otp).exists():               
                    UserOTP.objects.create(user = email, otp = usr_otp)
                    mess = f"Hello {email},\nYour OTP is {usr_otp}\nThanks!"
                    send_mail(
			        "Welcome to - Verify Your Email", 
			        mess,
			        settings.EMAIL_HOST_USER,                
			        [email],
			        fail_silently = False,
			        )    
                    data={"status":True,"message":"we have sent a otp to your email please verify your  account"}
                    return Response(data)
                return Response({'status':False,'message':'click to resend otp',"register":True},status=status.HTTP_400_BAD_REQUEST)
                
            return Response({'status':False,'message':'your email is already reistered ',"register":True},status=status.HTTP_400_BAD_REQUEST)
            
        return Response({'status':False,'message':'your email is not registered '},status=status.HTTP_400_BAD_REQUEST)





from rest_framework import generics
from .serializers import ChangePasswordSerializer, SetNewPasswordSerializer, ResetPasswordEmailRequestSerializer
from rest_framework.permissions import IsAdminUser, IsAuthenticated  
from rest_framework.settings import api_settings 
class ChangePasswordView(generics.UpdateAPIView):
    
    authentication_classes = api_settings.DEFAULT_AUTHENTICATION_CLASSES
    permission_classes = (IsAuthenticated,)
    
       
    serializer_class = ChangePasswordSerializer
    
    model = User
    def get_object(self, queryset=None):
        obj = self.request.user
        return obj
    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = request.data
        
        if serializer.get("old_password")=='' and serializer.get('new_password') =='':
            return Response({"status":False,"error":{"old_password": "required","new_password": "required"}},status=status.HTTP_400_BAD_REQUEST)
        if serializer.get("old_password")=='' :
            return Response({"status":False,"error":{"old_password": "required"}},status=status.HTTP_400_BAD_REQUEST)
        if  serializer.get('new_password') =='':
            return Response({"status":False,"error":{"new_password": "required"}},status=status.HTTP_400_BAD_REQUEST)

        
            # Check old password
        if not self.object.check_password(serializer.get("old_password")):
            return Response({"status":False,"error":{"old_password": "Wrong password."}},status=status.HTTP_400_BAD_REQUEST)
        # set_password also hashes the password that the user will get
        self.object.set_password(serializer.get("new_password"))
        self.object.save()
        response = {
            'status': '200',
            'code': status.HTTP_200_OK,
            'message': 'Password updated successfully',
            'data': []
        }
        return Response({'status':True,'message' :'you have change password successfully'},status=status.HTTP_200_OK)
        return Response({'status':False,"error":dict(serializer.errors)}, status=status.HTTP_400_BAD_REQUEST)







from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.urls import reverse
from .serializers import ResetPasswordEmailRequestSerializer
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import PasswordResetTokenGenerator
class RequestPasswordResetEmail(GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        model = User
        permission_classes = (IsAuthenticated,)
        email = request.data.get('email', '')
        if email=="":
            return Response({'status':False,'message': 'enter email address'},status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(email=email).exists() or User.objects.filter(username=email).exists() :
            user = User.objects.filter(email=email).first()
            if user:
                uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
                token = PasswordResetTokenGenerator().make_token(user)
                current_site = get_current_site(
                    request=request).domain
                relativeLink = reverse(
                    'password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
                redirect_url = request.data.get('redirect_url', '')
                absurl = 'http://'+current_site + relativeLink
                email_body = 'Hello, \n Use link below to reset your password  \n' + \
                    absurl+"?redirect_url="+redirect_url
                send_mail(
			        "Welcome to - password reset", 
			        email_body,
			        settings.EMAIL_HOST_USER,                
			        [email],
			        fail_silently = False,
			        )
                return Response({'status':True,'message': 'We have sent you a link to reset your    password'},    status=status.HTTP_200_OK)
            else:
                user = User.objects.get(username=email)
                usr_email=user.email
                uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
                token = PasswordResetTokenGenerator().make_token(user)
                current_site = get_current_site(
                    request=request).domain
                relativeLink = reverse(
                    'password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
                redirect_url = request.data.get('redirect_url', '')
                absurl = 'http://'+current_site + relativeLink
                email_body = 'Hello, \n Use link below to reset your password  \n' + \
                    absurl+"?redirect_url="+redirect_url
                send_mail(
			        "Welcome to - password reset", 
			        email_body,
			        settings.EMAIL_HOST_USER,                
			        [usr_email],
			        fail_silently = False,
			        )
                return Response({'status':True,'message': 'We have sent you a link to reset your    password'},    status=status.HTTP_200_OK)

        return Response({'status':False,'message': 'this email or username not registered'},    status=status.HTTP_400_BAD_REQUEST)




from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

class PasswordTokenCheckAPI(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):
        redirect_url = request.GET.get('redirect_url')
        
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            

            if not PasswordResetTokenGenerator().check_token(user,token):
                return Response({'status':False,'message':'token is not valid please request a new one'})
            return Response({'status':True, 'message':'success', 'uidd64':uidb64,'token':token}, status=status.HTTP_200_OK)
        except Exception:
             return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_400_BAD_REQUEST)
            #try:
            #    if not PasswordResetTokenGenerator().check_token(user):
            #        return Response({'error': 'Token is not valid, please request a new one'}, status=status.#HTTP_400_BAD_REQUEST)
            #        
            #except UnboundLocalError :
            #    return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_400_BAD_REQUEST)
            
    
                    
            

class SetNewPasswordAPIView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        attrs = request.data
        if attrs.get('uidb64')=="" and attrs.get('password') and attrs.get('token') :
            return Response({'status': False, 'error':{'uidb64': 'enter uidb64',"password":" new enter password", 'token':'enter token'}}, status=status.HTTP_400_BAD_REQUEST)
        if attrs.get('password')=="":
            return Response({'status': False, 'error': 'password field is not blank'}, status=status.HTTP_400_BAD_REQUEST)
        if attrs.get('token')=="":
            return Response({'status': False, 'error': 'enter token'}, status=status.HTTP_400_BAD_REQUEST)
        if attrs.get('uidb64')=="":
            return Response({'status': False, 'error': 'enter uidb64'}, status=status.HTTP_400_BAD_REQUEST)
        attrs = request.data
        
            
        if  (attrs.get('uidb64')=="" or attrs.get('password') or attrs.get('token')) :
            
            try:
        
                password = attrs.get('password')
                print(password)
                token = attrs.get('token')
                print(token)
                uidb64 = attrs.get('uidb64')
                id = force_str(urlsafe_base64_decode(uidb64))
                user = User.objects.get(id=id)
                print(user)
                print("from view")
                user.set_password(password)
                print(user.password)
                user.save()
                return Response({'status': True, 'message': 'Password reset success'}, status=status.       HTTP_200_OK)
            except Exception:
                return Response({'status': False, 'error':'uuid64 is wrong'}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'status': False, 'error':'all field are require'}, status=status.HTTP_400_BAD_REQUEST)



class GetALL_active_user(APIView):
    

    def get(self, request, format=None):
        userdetail=User.objects.all().filter(is_active=True)
        user_list={"status":True,"message":"all active user are fetched"}
        for userdetail in userdetail:
            if not userdetail.last_login:
                data={'id':userdetail.id, 'username':userdetail.username,'firt_name':userdetail.first_name,'last_name':userdetail.last_name,'email':userdetail.email,'join_date':userdetail.date_joined.strftime('%y-%m-%d %a %H:%M:%S'),'last_login':"0-0-0"}
                user_list[userdetail.id]=data
            if userdetail.last_login:
                data={'id':userdetail.id, 'username':userdetail.username,'firt_name':userdetail.first_name, 'last_name':userdetail.last_name,'email':userdetail.email,'join_date':userdetail.date_joined.    strftime('%y-%m-%d %a %H:%M:%S'),'last_login':userdetail.last_login.strftime    ('%y-%m-%d %a       %H:%M:%S')}
                user_list[userdetail.id]=data
    
        return Response(user_list,status=status.HTTP_200_OK)
            


from django.contrib.sessions.models import Session
from django.utils import timezone

class Get_all_logged_in_users(APIView):
    permission_classes = (IsAdminUser,)
    def get(self,request):
        sessions = Session.objects.filter(expire_date__gte=timezone.now())
        uid_list = []

        # Build a list of user ids from that query
        for session in sessions:
            data = session.get_decoded()
            uid_list.append(data.get('_auth_user_id', None))

        # Query all logged in users based on id list
        userdetail=User.objects.filter(id__in=uid_list)
        user_list={"status":True}
        c=1
        for userdetail in userdetail:

            data={'id':userdetail.id, 'username':userdetail.username,'firt_name':userdetail.first_name, 'last_name':userdetail.last_name,'email':userdetail.email,'join_date':userdetail.date_joined.strftime    ('%y-%m-%d %a %H:%M:%S')}
            user_list[c]=data
            c=c+1
        user_list["message"]="all logged in user are fetch "

        return Response(user_list)


from django.contrib.auth import authenticate, login, logout
from rest_framework.decorators import api_view
@api_view(['GET'])
def logout_request(request):
    if  request.user.is_authenticated:
        print(request.user)
        data={"status":True,"username":request.user,"message":"you are logged out"}
        logout(request)
        return HttpResponse('logged out ') 
    data={"status":False,"message":"no login user is there "}
    return HttpResponse(data) 


from rest_framework.decorators import api_view, permission_classes

class User_logout(views.APIView):
    authentication_classes = api_settings.DEFAULT_AUTHENTICATION_CLASSES
    permission_classes = (IsAuthenticated,)
    def post(self,request):
        


        data={"status":True,"username":request.user.username, "message":"you are logged out"}

        logout(request)

        return Response(data)






class Get_user_detail(APIView):
    permission_classes = (IsAuthenticated,)
    Model= User
    serializer_class = ResetPasswordEmailRequestSerializer
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        email = request.data.get('email', '')
        if email=="":
            return Response({'status':False,'message': 'enter email address'},status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(email=email).exists() or User.objects.filter(username=email).exists() :
            userdetail = User.objects.filter(email=email).first()
            if userdetail:
                data={"status":True,'data':{'id':userdetail.id, 'username':userdetail.username,'firt_name':userdetail.first_name,'last_name':userdetail.last_name,'email':userdetail.email,'join_date':userdetail.date_joined.strftime('%y-%m-%d %a %H:%M:%S')}}
                return Response(data,status=status.HTTP_200_OK)
            else:
                userdetails = User.objects.get(username=email)
                if not userdetails.last_login:
                    data={"status":True,'data':{'id':userdetails.id, 'username':userdetails.username,'firt_name':userdetails.first_name,'last_name':userdetails.last_name,'email':userdetails.email,'join_date':userdetails.date_joined.strftime('%y-%m-%d %a %H:%M:%S'),'last_login':'0-0-0'}}
                    return Response(data,status=status.HTTP_200_OK)
                data={"status":True,'data':{'id':userdetails.id, 'username':userdetails.username,'firt_name':userdetails.first_name,'last_name':userdetails.last_name,'email':userdetails.email,'join_date':userdetails.date_joined.strftime('%y-%m-%d %a %H:%M:%S'),'last_login':userdetails.last_login.strftime    ('%y-%m-%d %a   %H:%M:%S')}}
                return Response(data,status=status.HTTP_200_OK)

   
        return Response({'status':False,'message': 'this email or username not registered'},    status=status.HTTP_400_BAD_REQUEST)

        
    








from rest_framework.decorators import api_view
from rest_framework.response import Response
from .serializers import UserSerializer
@api_view(['GET'])
def profile(request):
    user = request.user
    serialized_user = UserSerializer(user).data
    return Response({'user': serialized_user })



from django.contrib.auth import get_user_model
from rest_framework.response import Response
from rest_framework import exceptions
from rest_framework.permissions import AllowAny
from rest_framework.decorators import api_view, permission_classes
from django.views.decorators.csrf import ensure_csrf_cookie
from .serializers import UserSerializer
from .utils import generate_access_token, generate_refresh_token


@api_view(['POST'])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def login_view(request):
    User = get_user_model()
    username = request.data.get('username')
    password = request.data.get('password')
    response = Response()
    if (username is None) or (password is None):
        raise exceptions.AuthenticationFailed(
            'username and password required')

    user = User.objects.filter(username=username).first()
    if(user is None):
        raise exceptions.AuthenticationFailed('user not found')
    if (not user.check_password(password)):
        raise exceptions.AuthenticationFailed('wrong password')

    serialized_user = UserSerializer(user).data

    access_token = generate_access_token(user)
    refresh_token = generate_refresh_token(user)

    response.set_cookie(key='refreshtoken', value=refresh_token, httponly=True)
    response.data = {
        'access_token': access_token,
       ' refresh_token':refresh_token,
        'user': serialized_user,
    }

    return response



import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from django.views.decorators.csrf import csrf_protect
from rest_framework import exceptions
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.decorators import api_view, permission_classes
from .utils import generate_access_token


@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_protect
def refresh_token_view(request):
    '''
    To obtain a new access_token this view expects 2 important things:
        1. a cookie that contains a valid refresh_token
        2. a header 'X-CSRFTOKEN' with a valid csrf token, client app can get it from cookies "csrftoken"
    '''
    User = get_user_model()
    refresh_token = request.COOKIES.get('refreshtoken')
    if refresh_token is None:
        raise exceptions.AuthenticationFailed(
            'Authentication credentials were not provided.')
    try:
        payload = jwt.decode(
            refresh_token, settings.REFRESH_TOKEN_SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        raise exceptions.AuthenticationFailed(
            'expired refresh token, please login again.')

    user = User.objects.filter(id=payload.get('user_id')).first()
    if user is None:
        raise exceptions.AuthenticationFailed('User not found')

    if not user.is_active:
        raise exceptions.AuthenticationFailed('user is inactive')


    access_token = generate_access_token(user)
    return Response({'access_token': access_token})
