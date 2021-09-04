
from authentication.serializers import ChangePasswordSerializer
from django.urls import path
from . import views
from rest_framework_simplejwt import views as jwt_views
from django.contrib.auth import views as auth_views


#creating router object


urlpatterns = [
   
     path('active/user',views.GetALL_active_user.as_view()),
     path('login/user',views.Get_all_logged_in_users.as_view()),
    
   
    path('register/',views.RegisterView.as_view()),
    path('log_in/',views.LoginView.as_view(),name='log_in'),
    #path('log_ins/',views.login_view,name='log_in'),
 

    path('logout/', views.User_logout.as_view(), name="logout"),
    path('get_detail/', views.Get_user_detail.as_view(), name="logout"),
    path('register/verify/',views.registerverify.as_view()),
    path('resend/otp/',views.ResendOTP.as_view()),
    path('changepassword/', views.ChangePasswordView.as_view()),
    path('api/token/', jwt_views.TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
     path('profile', views.profile, name='profile'),


    path('request-reset-email/', views.RequestPasswordResetEmail.as_view(),
         name="request-reset-email"),
    path('password-reset/<uidb64>/<token>/',
         views.PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password-reset-complete', views.SetNewPasswordAPIView.as_view(),
         name='password-reset-complete')

     
   
  
]

