
from django.db import models
from django.contrib.auth.models import User
from rest_framework import fields

class UserOTP(models.Model):
	user = models.CharField(max_length=39)
	time_st = models.DateTimeField(auto_now = True)
	otp = models.SmallIntegerField()

from django.contrib.auth.models import AbstractUser

#class User(AbstractUser):
#	pass
   
		
		
